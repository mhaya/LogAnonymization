#!/usr/bin/env python
# -*- coding: utf-8 -*-

import Crypto.Cipher.AES
import socket
import struct
import array
import ipaddress
import numpy as np

#Orig IP: 192.168.0.1
#Ano IP: 2.149.253.242
  
class CryptoPAn:
    def __init__(self,key):
        self._init(key)

    def _init(self,key):
        self._cipher = Crypto.Cipher.AES.new(key[:16],Crypto.Cipher.AES.MODE_ECB)
        padding = array.array('B')
        padding.fromstring(self._cipher.encrypt(key[16:]))
        self._padding_int = self._to_int(padding)
        
    def changeKey(slef,key):
        self._init(key)
    
    def MSB(self,byte_array):
        n = byte_array[0] >> 7
        return n
    
    def LSB(self,byte_array):
        n = self._to_int(byte_array)
        return n & 1

    def anonymize(self,addr,version,priv):
        if version == 4:
            N = 32
            ext_addr = addr << 96
        elif version == 6:
            N = 128
            ext_addr = addr 
         
        flip_array = []
        
        for pos in range(N):
            prefix =  ext_addr >> (128-pos) << (128-pos) 
            padded_addr = prefix | (self._padding_int & (2**128-1 >> pos))
            self._input = self._to_byte_array(padded_addr,16)
            output = array.array('B')
            output.fromstring(self._cipher.encrypt(self._input))
            # 論文だとLSBだけど実装はMSB
            flip_array.append(self.MSB(output))
        result = reduce(lambda x, y: (x << 1) | y, flip_array)
        
        anonymizedIP = addr ^ (result & (2**N-1<<(N-priv)))
        return anonymizedIP
    
    def _to_int(self,byte_array):
        return reduce(lambda x,y: x << 8 | y,byte_array) 
    
    def _to_byte_array(self,n,byte_cnt):
        byte_array = array.array('B')
        for i in range(byte_cnt):
            byte_array.insert(0, (n >> (i * 8)) & 0xff)
        return byte_array
    
if __name__ == '__main__' :
    # 192.0.2.1 > 2.90.93.17
    # 2001:db8::1 > dd92:2c44:3fc0:ff1e:7ff9:c7f0:8180:7e00
    key = array.array('B',range(32))
    obj = CryptoPAn(key)
    orig_addr = '192.0.2.1'
    if not isinstance(orig_addr,unicode):
        orig_addr = unicode(orig_addr)

    ip=ipaddress.ip_address(orig_addr)
    print "Orig IP:",ip
    print "Orig IP(int):",int(ip)
    ret = obj.anonymize(int(ip),4,32)
    anonymizedIP = ipaddress.IPv4Address(ret)
    print "Ano IP:",anonymizedIP
    print "Ano IP(int):",ret

    orig_addr = '192.0.2.2'
    if not isinstance(orig_addr,unicode):
        orig_addr = unicode(orig_addr)

    ip=ipaddress.ip_address(orig_addr)
    ret = obj.anonymize(int(ip),4,32)
    
    anonymizedIP = ipaddress.IPv4Address(ret)
    print "Orig IP:",ip
    print "Orig IP(int):",int(ip)
    print "Ano IP:",anonymizedIP
    print "Ano IP(int):",ret
    orig_addr = '2001:db8::1'
    if not isinstance(orig_addr,unicode):
        orig_addr = unicode(orig_addr)

    ip=ipaddress.ip_address(orig_addr)
    ret = obj.anonymize(int(ip),6,128)
    anonymizedIP = ipaddress.IPv6Address(ret)
    print "Orig IP:",ip
    print "Orig IP(int):",int(ip)
    print "Ano IP:",anonymizedIP 
    print "Ano IP(int):",ret
    orig_addr = '2001:db8::2'
    if not isinstance(orig_addr,unicode):
        orig_addr = unicode(orig_addr)

    ip=ipaddress.ip_address(orig_addr)
    ret = obj.anonymize(int(ip),6,128)
    anonymizedIP = ipaddress.IPv6Address(ret)
    print "Orig IP:",ip
    print "Orig IP(int):",int(ip)
    print "Ano IP:",anonymizedIP   
    print "Ano IP(int):",ret
    print type(ret)
        

