#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-
# network_scan_email_compare.py

import datetime
import subprocess
import smtplib
import mimetypes
import email
import requests
import os
import sys
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
import json
from xml.dom import minidom

date = datetime.datetime.now()
timeNow = str(date.strftime('%Y-%m-%d_%H:%M:%S'))

dataList = []
dataListNew = []

dataList.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
dataListNew.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
print('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')

try:
    public_ip = requests.get('http://ip.42.pl/raw').text
    hostname = "ip.42.pl"
    response = os.system("ping -c 1 " + hostname + " > /dev/null 2>&1")
    if response == 0:
        subprocess.check_call("sudo nmap -sP -sn -oX network_scan_online.log 192.168.0.* > /dev/null 2>&1", shell=True)
        dataList.append('Public IP: ' + public_ip + '\n')
        dataListNew.append('Public IP: ' + public_ip + '\n')
        print('Public IP: ' + public_ip + '\n')
    else:
        dataList.append('Public IP: n/a (Bad domain? (' + hostname + ')?\n')
        dataListNew.append('Public IP: n/a (Bad domain? (' + hostname + ')?\n')
        print('Public IP: n/a (Bad domain? (' + hostname + ')?\n')
except:
    dataList.append('NO INTERNET CONNECTIVITY\n')
    dataListNew.append('NO INTERNET CONNECTIVITY\n')
    print('NO INTERNET CONNECTIVITY\n')

    with open('network_scan_online.txt', 'w') as readable:
        for item in dataList:
            readable.write("%s\n" % item)
        sys.exit()     

doc = minidom.parse('network_scan_online.log')
data = doc.getElementsByTagName('host')

def func():
    for i, v in enumerate(data):
        items = v.getElementsByTagName('address')
        itemsTwo = v.getElementsByTagName('hostname')

        try:
            NAME_get = itemsTwo[0].attributes['name'].value
        except:
            NAME_get = ('n/a')
        dataList.append('Name: ' + NAME_get)
        print('Name: ' + NAME_get)

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

        DEVICE = {'IP': IP_get,'MAC': MAC_get,'VENDOR': VENDOR_get,'NAME': NAME_get,'SEEN': timeNow, 'FIRST_SEEN': timeNow}

        with open('network_scan_all.json') as json_file:
            data_all = json.load(json_file)
        
        if MAC_get in data_all:
            print('Status: Known Device.')
            dataList.append('Status: Known device.')
            FIRST_SEEN_get = (data_all[MAC_get]["FIRST_SEEN"])
            dataList.append('First seen: ' + FIRST_SEEN_get)
            print('First seen: ' + FIRST_SEEN_get)
            dataList.append('\n')
            print('\n')
            SEEN_val = {'SEEN': timeNow}
            data_all[MAC_get].update(SEEN_val)
            with open('network_scan_all.json', 'w') as outfile:
                json.dump(data_all, outfile)
        else:
            print('Status: Unknown device.')
            dataListNew.append('Name: ' + NAME_get)
            dataListNew.append('IP: ' + IP_get)
            dataListNew.append('MAC: ' + MAC_get)
            dataListNew.append('Vendor: ' + VENDOR_get)
            dataList.append('Status: Unknown device.')
            dataListNew.append('Status: Unknown device.')
            FIRST_SEEN_get = timeNow
            dataListNew.append('First seen: ' + FIRST_SEEN_get)
            print('First seen: ' + FIRST_SEEN_get)
            dataListNew.append('\n')
            dataList.append('\n')
            print('\n')
            data_all[MAC_get] = DEVICE
            with open('network_scan_all.json', 'w') as outfile:
                json.dump(data_all, outfile)


    with open('network_scan_online.txt', 'w') as readable:
        for item in dataList:
            readable.write("%s\n" % item)

    generateListAll()

    if 'Status: Unknown device.' in dataList:
        sendMail()
    else:
        return

def generateListAll():
    dataListAll = []
    dataListAll.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
    dataListAll.append('Public IP: ' + public_ip + '\n')
    with open('network_scan_all.json') as json_file:
        data_all = json.load(json_file)
        for key in data_all.keys():
            key_NAME = (data_all[key]["NAME"])
            key_IP = (data_all[key]["IP"])
            key_MAC = (data_all[key]["MAC"])
            key_VENDOR = (data_all[key]["VENDOR"])
            key_FIRST_SEEN = (data_all[key]["FIRST_SEEN"])
            key_LAST_SEEN = (data_all[key]["SEEN"])
            dataListAll.append('Name: ' + key_NAME)
            dataListAll.append('IP: ' + key_IP)
            dataListAll.append('MAC: ' + key_MAC)
            dataListAll.append('Vendor: ' + key_VENDOR)
            dataListAll.append('First seen: ' + key_FIRST_SEEN)
            dataListAll.append('Last seen: ' + key_LAST_SEEN)
            dataListAll.append('\n')
            
    with open('network_scan_all.txt', 'w') as readableList:
        for item in dataListAll:
            readableList.write("%s\n" % item)

def sendMail():
    emailfrom = "SENDER_HERE"
    emailto = ["RECEIVER_HERE"]
    fileToSend = "network_scan_all.txt"

    msg = MIMEMultipart()
    msg["From"] = emailfrom
    msg["To"] = ",".join(emailto)
    msg["Subject"] = "Unknown device detected - network_scan_online_" + timeNow
    msg.preamble = "Unknown device detected - network_scan_online_" + timeNow

    ctype, encoding = mimetypes.guess_type(fileToSend)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream"

    maintype, subtype = ctype.split("/", 1)

    fp = open(fileToSend, "rb")
    attachment = MIMEBase(maintype, subtype)
    attachment.set_payload(fp.read())
    fp.close()
    encoders.encode_base64(attachment)
    attachment.add_header("Content-Disposition", "attachment", filename=fileToSend)
    body = '\n'.join(dataListNew)
    msg.attach(MIMEText(body, 'plain'))
    msg.attach(attachment)

    server = smtplib.SMTP('SERVER_HERE', 587)
    server.starttls()
    server.login(emailfrom, "PASSWORD_HERE")
    server.sendmail(emailfrom, emailto, msg.as_string())
    server.quit()
    print('Email got sent.\n')

func()

