#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
# network_scan_email_compare.py

import datetime
import subprocess
import smtplib
import email
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
from xml.dom import minidom

timeNow = str(datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S'))
subprocess.check_call("sudo nmap -sP -sn -oX network_scan.log 192.168.0.* > /dev/null 2>&1", shell=True)
doc = minidom.parse('network_scan.log')
data = doc.getElementsByTagName('host')

nmap = doc.getElementsByTagName('nmaprun')
nmap_time = int(nmap[0].attributes['start'].value)
date = datetime.datetime.fromtimestamp(nmap_time)
public_ip = requests.get('http://ip.42.pl/raw').text
dataList = []

dataList.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
print('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')

dataList.append('Public IP: ' + public_ip + '\n')
print('Public IP: ' + public_ip + '\n')

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

        DEVICE = {'IP': IP_get,'MAC': MAC_get,'VENDOR': VENDOR_get,'NAME': NAME_get,'SEEN': timeNow, 'FIRST_SEEN': timeNow}

        with open('network_scan_all.json') as json_file:
            data_all = json.load(json_file)
        
        if MAC_get in data_all:
            print('Status: Known Device.')
            dataList.append('Status: Known device.')
            SEEN_val = {'SEEN': timeNow}
            data_all[MAC_get].update(SEEN_val)
            with open('network_scan_all.json', 'w') as outfile:
                json.dump(data_all, outfile)
        else:
            print('Status: Unknown device.')
            dataList.append('Status: Unknown device.')
            data_all[MAC_get] = DEVICE
            with open('network_scan_all.json', 'w') as outfile:
                json.dump(data_all, outfile)

        dataList.append('\n')
        print('\n')

    with open('network_scan_all.txt', 'w') as readable:
        for item in dataList:
            readable.write("%s\n" % item)

    if 'Unknown device.' in dataList:
        sendMail()
    else:
        return

def sendMail():
    fromaddr = "SENDER_ADDRESS_HERE"
    toaddr = "RECEIVER_ADDRESS_HERE"

    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = "Unknown device detected - network_scan_" + timeNow + ".log"
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

