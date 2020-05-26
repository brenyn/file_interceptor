#!/usr/bin/env python

##########################################################################################################
#
# Author: Brenyn Kissoondath
# Course: Learn Python and Ethical Hacking From Scratch - StationX
# Instructor: Zaid Al Quraishi
# Purpose: Create a file interceptor
# Input(s): 
# Output(s): 
#
# Notes to self: http request if dport = http, http response if sport = http in TCP layer
#
##########################################################################################################
import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload()) #convert netfilterqueue packet into scapy packet so we can use scapy filters
	if scapy_packet.haslayer(scapy.Raw): #raw layer is where html is stored

		if scapy_packet[scapy.TCP].dport == 80: # default http port is 80

			if ".exe" in scapy_packet[scapy.Raw].load:
				print("[+] EXE request")
				ack_list.append(scapy_packet[scapy.TCP].ack)
				print(scapy_packet.show())

		elif scapy_packet[scapy.TCP].sport == 80: # default http port is 80
			if (scapy_packet[scapy.TCP].seq) in ack_list: # if the sequence matches an ack in ack_list it means a download request has been made and the TCP handshake is complete
				ack_list.remove(scapy_packet[scapy.TCP].seq)
				print("[+] Replacing file")
				print(scapy_packet.show())


	packet.accept()

queue = netfilterqueue.NetfilterQueue() #redirect traffic through netfilterqueue
queue.bind(0, process_packet) #direct packets to process_packet where they are turned into scapy packets, analysed and acted upon
queue.run()