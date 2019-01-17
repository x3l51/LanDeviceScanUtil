#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
# network_scan_email.py

import datetime
import subprocess
from xml.dom import minidom
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
 
fromaddr = "SENDER_ADDRESS_HERE"
toaddr = "RECEIVER_ADDRESS_HERE"
msg = MIMEMultipart()
msg['From'] = fromaddr
msg['To'] = toaddr
msg['Subject'] = "network_scan_" + timeNow + ".log"

timeNow = str(datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S'))
subprocess.check_call("sudo nohup nmap -sP -sn -oX network_scan_" + timeNow + ".log 192.168.0.*", shell=True)
doc = minidom.parse('network_scan_' + timeNow + '.log')
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

    body = '\n'.join(dataList)
    msg.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('SMTP_SERVER_HERE', 587)
    server.starttls()
    server.login(fromaddr, "PASSWORD_HERE")
    text = msg.as_string()
    server.sendmail(fromaddr, toaddr, text)
    server.quit()
    print('Email got sent.\n')

func()

