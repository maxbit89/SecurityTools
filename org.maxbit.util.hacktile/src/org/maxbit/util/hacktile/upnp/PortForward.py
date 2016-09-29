#!/bin/python
'''
Created on 18.09.2016

@author: maxbit89
'''
import miniupnpc

UPNP_PROTOCOL_TCP = 'TCP'
UPNP_PROTOCOL_UDP = 'UDP'

class upnpPortMapping:
    def __init__(self):
        self.upnp = miniupnpc.UPnP()
        self.upnp.discoverdelay = 10
        self.upnp.discover()
        self.upnp.selectigd()
        
    def map(self, port, toIp, withPort, protocol):
        self.upnp.addportmapping(port, protocol, toIp, withPort, 'Microsoft Update Protforwarding', '')
        
    def getPublicIP(self):
        return self.upnp.externalipaddress()

portmapping = upnpPortMapping()
localip = portmapping.upnp.lanaddr;
print localip
externalPort = 80
portmapping.map(externalPort, localip, 8000, UPNP_PROTOCOL_TCP)
print "The new Service is available under:"+portmapping.getPublicIP()+":"+str(externalPort)