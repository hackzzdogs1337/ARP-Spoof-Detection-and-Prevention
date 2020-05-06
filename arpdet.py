from scapy.all import *
from termcolor import colored
import os
def check(packet):
    global gatewaymac,rip
    smac=packet.hwsrc
    sip=packet.psrc
    op=packet.op
    if(op==2):
        if(smac==gatewaymac):
            if(sip==rip):
                pass
            else:
                print(colored('ARP spoofing is detected',"red"))
                print(colored(f'[+]Starting blocking arp packets coming from the source {sip}',"green"))
                os.system(f'arptables -A INPUT --source-ip {sip} -j DROP')
                break
rip=input("Enter the router's ip adddress")
askrou=ARP(pdst=rip,op=1)
result=sr1(askrou)
gatewaymac=result.hwsrc
a=sniff(filter='arp',prn=check,store=0)


