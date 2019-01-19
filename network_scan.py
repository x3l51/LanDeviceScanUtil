#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
# network_scan.py

import datetime
import subprocess
from xml.dom import minidom

timeNow = str(datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S'))
subprocess.check_call("sudo nmap -sP -sn -oX network_scan.log 192.168.0.* > /dev/null 2>&1", shell=True)
doc = minidom.parse('network_scan.log')
data = doc.getElementsByTagName('host')

nmap = doc.getElementsByTagName('nmaprun')
nmap_time = int(nmap[0].attributes['start'].value)
date = datetime.datetime.fromtimestamp(nmap_time)
dataList = []

dataList.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
print('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')

def func():
    for i, v in enumerate(data):
        items = v.getElementsByTagName('address')
        itemsTwo = v.getElementsByTagName('hostname')
        itemsThree = v.getElementsByTagName('hostname')

        try:
            IP_get = items[0].attributes['addr'].value
        except:
            IP_get = ('n/a')
        dataList.append('IP: ' + IP_get)
        print('IP: ' + IP_get)

        try:
            MAC_get = items[1].attributes['addr'].value
        except:
            MAC_get = ('n/a')
        dataList.append('MAC: ' + MAC_get)
        print('MAC: ' + MAC_get)

        try:
            VENDOR_get = items[1].attributes['vendor'].value
        except:
            VENDOR_get = ('n/a')
        dataList.append('Vendor: ' + VENDOR_get)
        print('Vendor: ' + VENDOR_get)

        try:
            NAME_get = itemsTwo[0].attributes['name'].value
        except:
            NAME_get = ('n/a')
        dataList.append('Name: ' + NAME_get)
        print('Name: ' + NAME_get)

        dataList.append('\n')
        print('\n')

    with open('network_scan_all.txt', 'w') as readable:
        for item in dataList:
            readable.write("%s\n" % item)
func()
