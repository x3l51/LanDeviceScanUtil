# !/usr/bin/env python3.6
# -*- coding: utf-8 -*-
# network_scan_email_compare.py

import sys
import os
import platform
#import pdb ###
#pdb.set_trace()

CRED = '\033[91m'
CEND = '\033[0m'

opSys = platform.system()

if opSys == 'Linux':
    if os.geteuid() != 0:
        print(CRED + "\nRestart the script with root privileges: 'sudo python3.6 network_scan_email_compare.py'\n" + CEND)
        sys.exit(0)
elif opSys is 'Windows':
    print(CRED + "\nIs this script running on Windows? Try your luck! [ENTER]\n" + CEND)
elif opSys is 'Darwin':
    print(CRED + "\nIs this script running on an Apple device? Try your luck! [ENTER]\n" + CEND)
else:
    print(CRED + "\nCan\'t detect your operating system. Try your luck! [ENTER]\n" + CEND)

# check if py version = 3.6
if sys.version_info[0] < 3:
    print(CRED + "\nRestart the script using python3.6: 'sudo python3.6 network_scan_email_compare.py\n" + CEND)
    sys.exit(0)

import time
import datetime
import subprocess
import smtplib
import mimetypes
import email
import os.path, time
import json
import getpass
import base64
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from xml.dom import minidom

try:
    import requests
    import nmap
    import matplotlib.pyplot as plt
    import numpy as np
    from Crypto.Cipher import AES
except ImportError:
    # check if python3 is python3.6
    # if not install python3.6
    subprocess.call("sudo rm /var/lib/dpkg/lock && sudo dpkg --configure -a > {}".format(os.devnull), shell=True)
    subprocess.call("sudo apt-get update > {}".format(os.devnull), shell=True)
    subprocess.call("sudo apt-get install build-essential checkinstall libssl-dev libreadline-gplv2-dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3-pip -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H python3.6 -m pip install --upgrade pip > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3-nmap -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H python3.6 -m pip install nmap > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H python3.6 -m pip install requests > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H python3.6 -m pip install pyCrypto > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H python3.6 -m pip install matplotlib > {}".format(os.devnull), shell=True)
    subprocess.call("sudo apt-get install python3-tk -y > {}".format(os.devnull), shell=True)

if not os.path.exists('/usr/bin/nmblookup'):
    subprocess.call("sudo rm /var/lib/dpkg/lock && sudo dpkg --configure -a > {}".format(os.devnull), shell=True)
    subprocess.call("sudo apt-get update > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3-pip -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install samba-common-bin -y > {}".format(os.devnull), shell=True)

unixtime = time.time()
unixtimeStr = str(unixtime)
date = datetime.datetime.now()
timeNow = str(date.strftime('%Y-%m-%d_%H:%M:%S'))
timeNowHuman = str(date.strftime('%Y-%m-%d %H:%M:%S'))

dataList = []
dataListNew = []
dataListAll = []
dataListHTML = []

dataListHTML.append('<html><head><meta http-equiv="refresh" content="300" charset="utf-8" name="viewport" content="width=device-width, initial-scale=1"/><html lang="EN"><title>NET.SCAN</title><style> \
        * {font-family: calibri, awesome, arial;} \
        .dot_green {height: 10px;width: 10px;background-color: green;border-radius: 50%;display: inline-block;} \
        .dot_red {height: 10px;width: 10px;background-color: red;border-radius: 50%;display: inline-block;} \
        body {max-width: 100%;overflow-x: hidden;overflow-y: scroll;margin: 0;font-family: Arial, Helvetica, sans-serif;} \
        .header {padding: 2px 16px; background: #555;color: #f1f1f1;} \
        .content {padding: 16px;} \
        a:link {text-decoration: none;color: black;} \
        .sticky {z-index: 2;padding: 2px 33px; background: #555;color: #f1f1f1;position: fixed;top: 0;width: 100%;} \
        .sticky + .content {padding-top: 65px;} \
        table {max-width: 100%;border-collapse: collapse;} \
        td { min-width: 340; width: 50%; border: 1px solid #dddddd;text-align: left;padding: 8px;vertical-align: top;} \
        th { border: 1px solid #dddddd;text-align: left;padding: 8px;vertical-align: top;} \
        #hide{display: inline;} \
        #show{display: none;} \
         \
        .container {position: relative;} \
        .image {display: block;width: 100%;height: auto;} \
        .overlay {position: absolute;top: 0;bottom: 0;left: 0;right: 0;height: 100%;width: 100%;opacity: 0;transition: .5s ease;background-color: #008CBA;text-align: center;} \
        .container:hover .overlay {opacity: 1;} \
         \
        @media only screen and (max-width: 750px) { \
        table {width: 100%;border-collapse: collapse;} \
        td { width: 100%; border: 1px solid #dddddd;text-align: left;padding: 8px;vertical-align: top;} \
        th { border: 1px solid #dddddd;text-align: left;padding: 8px;vertical-align: top;} \
        #hide{display: none;} \
        #show{display: inline;}} \
        </style></head><body style="background-color:#dddddd;"><div class="sticky" id="topHeader"><br> \
        Time: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '<br><br>\n')

dataList.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
dataListNew.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
dataListAll.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
print('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n') 

### Send Mail
stdoutCap = str(subprocess.getoutput("df -P / | awk 'NR==2{print$5}'"))
stdoutCapStat = ""
if int(stdoutCap.replace("%", "")) > 85:
    stdoutCapStat = "CAPACITY WARNING"

stdoutTemp = subprocess.getstatusoutput("vcgencmd measure_temp")
if stdoutTemp[0] == 0:
    stdoutTemp = str(stdoutTemp[1].strip("temp=").replace("'C", "°C"))
else:
    stdoutTemp = str('n/a')
stdoutTempStat = ""
if stdoutTemp != 'n/a' and float(stdoutTemp.replace("°C", "")) > 65:
    stdoutTempStat = "TEMPERATURE WARNING"
###

public_ipv4 = requests.get('http://ip.42.pl/raw').text
hostname = "ip.42.pl"
response = os.system("ping -c 1 " + hostname + " > /dev/null 2>&1")

if response == 0:
    stdoutdataName = subprocess.getoutput("hostname")
    stdoutdataIP4loc = subprocess.getoutput("ifconfig | grep \"inet \" | grep -v 127.0.0.1 | awk '{print $2}'")

    if stdoutdataIP4loc is "":
        stdoutdataIP4loc = "n/a"
    stdoutdataIP6loc = subprocess.getoutput("ifconfig | grep \"inet6 \" | awk '{print $2}' | grep -i \"^[fe]\"")

    if stdoutdataIP6loc is "":
        stdoutdataIP6loc = "n/a"
    
    stdoutdataIP6pub_lo = subprocess.getoutput("ifconfig | grep \"inet6 \" | grep -v \"^[fe]\" | grep -v :: | awk 'NR==1{print$2}'")
    stdoutdataIP6pub_lt = subprocess.getoutput("ifconfig | grep \"inet6 \" | grep -v \"^[fe]\" | grep -v :: | awk 'NR==2{print$2}'")
    stdoutdataIP6pub_lt_cut = subprocess.getoutput("ifconfig | grep \"inet6 \" | grep -v \"^[fe]\" | grep -v :: | awk 'NR==2{print$2}' | cut -d: -f5,6,7,8")
    if stdoutdataIP6pub_lt is "":
        stdoutdataIP6pub = stdoutdataIP6pub_lo
        stdoutdataIP6pub_lt =  "n/a"
    else:
        stdoutdataIP6pub = (stdoutdataIP6pub_lo + " (:" + stdoutdataIP6pub_lt_cut + ")")

    if stdoutdataIP6pub is "":
        stdoutdataIP6pub_lo = "n/a"
        stdoutdataIP6pub = "n/a"
    stdoutdataIface = subprocess.getoutput("route | grep '^default' | grep -o '[^ ]*$'")

    if stdoutdataIface.startswith('e'):
        stdoutdataIface = ("Ethernet (" + stdoutdataIface + ")")
    elif stdoutdataIface.startswith('e'):
        stdoutdataIface = ("Wireless (" + stdoutdataIface + ")")

    stdoutdataMAC = subprocess.getoutput("cat /sys/class/net/*/address | awk 'NR==1{print $1}'")
    stdoutdataMAC_lt = subprocess.getoutput("cat /sys/class/net/*/address | awk 'NR==2{print $1}'")
    if stdoutdataMAC == '00:00:00:00:00:00' and stdoutdataMAC_lt != '':
        stdoutdataMAC = stdoutdataMAC_lt
    stdoutdataMACDiff = stdoutdataMAC[:8].replace(":","-")

    try:
        if os.path.exists('/var/lib/ieee-data/oui.txt'):
            if time.time() - os.path.getmtime('/var/lib/ieee-data/oui.txt') > (60 * 60 * 24):
                subprocess.check_call("sudo wget http://standards-oui.ieee.org/oui.txt --directory-prefix=/var/lib/ieee-data/ > /dev/null 2>&1", shell=True)
        else:
            subprocess.check_call("sudo wget http://standards-oui.ieee.org/oui.txt --directory-prefix=/var/lib/ieee-data/ > /dev/null 2>&1", shell=True)
        stdoutdataVendor = subprocess.getoutput("grep -i \"" + stdoutdataMACDiff + "\" /var/lib/ieee-data/oui.txt | awk '{$1=$2=\"\"; print substr($0,2)}'")
        if stdoutdataVendor == '':
            stdoutdataVendor = "n/a"
    except:
        stdoutdataVendor = "n/a"

    try:
        if sys.argv[1]:
            scanRange = sys.argv[1]
    except:
        scanRange = (subprocess.getoutput("ifconfig | grep inet | grep -v 127.0.0.1 | grep -v ::1 | awk 'NR==1{print $2}' | cut -d: -f2 | cut -d. -f -3") + ".*")

    subprocess.check_call("sudo nmap -sP -sn -oX network_scan_online.log " + scanRange + " > /dev/null 2>&1", shell=True)
    
    hostsOnlineStr = subprocess.getoutput("sudo nmap -sn " + scanRange + " | grep \"hosts up)\" | cut -d\( -f2 | awk '{print$1}'")
    hostsOnline = int(hostsOnlineStr)

    if os.path.exists('network_scan_info.log'):
        if time.time() - os.path.getmtime('network_scan_info.log') > (60 * 60):
            if stdoutdataIP6pub in (None, '', 'n/a'):
                subprocess.check_call("sudo nmap -F -A --host-timeout 20 -oN network_scan_info.log " + public_ipv4 + " > /dev/null 2>&1", shell=True)
            else:
                if public_ipv4 not in (None, '', 'n/a'):
                    subprocess.check_call("sudo nmap -F -A --host-timeout 20 -oN network_scan_info.log " + public_ipv4 + " > /dev/null 2>&1", shell=True)
                    subprocess.check_call("sudo nmap -6 -F -A --host-timeout 20 --append-output -oN network_scan_info.log " + stdoutdataIP6pub_lo + " > /dev/null 2>&1", shell=True)
                else:
                    subprocess.check_call("sudo nmap -6 -F -A --host-timeout 20 -oN network_scan_info.log " + stdoutdataIP6pub_lo + " > /dev/null 2>&1", shell=True)
                if stdoutdataIP6pub_lt not in (None, '', 'n/a'):
                    subprocess.check_call("sudo nmap -6 -F -A --host-timeout 20 --append-output -oN network_scan_info.log " + stdoutdataIP6pub_lt + " > /dev/null 2>&1", shell=True)
    else:
        if stdoutdataIP6pub in (None, '', 'n/a'):
            subprocess.check_call("sudo nmap -F -A --host-timeout 20 -oN network_scan_info.log " + public_ipv4 + " > /dev/null 2>&1", shell=True)
        else:
            if public_ipv4 not in (None, '', 'n/a'):
                subprocess.check_call("sudo nmap -F -A --host-timeout 20 -oN network_scan_info.log " + public_ipv4 + " > /dev/null 2>&1", shell=True)
                subprocess.check_call("sudo nmap -6 -F -A --host-timeout 20 --append-output -oN network_scan_info.log " + stdoutdataIP6pub_lo + " > /dev/null 2>&1", shell=True)
            else:
                subprocess.check_call("sudo nmap -6 -F -A --host-timeout 20 -oN network_scan_info.log " + stdoutdataIP6pub_lo + " > /dev/null 2>&1", shell=True)
            if stdoutdataIP6pub_lt not in (None, '', 'n/a'):
                subprocess.check_call("sudo nmap -6 -F -A --host-timeout 20 --append-output -oN network_scan_info.log " + stdoutdataIP6pub_lt + " > /dev/null 2>&1", shell=True)

    with open('network_scan_info.log') as infoFile:
        infoAll = infoFile.read()

    if os.path.exists('network_scan_open_ports.txt'):
        if time.time() - os.path.getmtime('network_scan_open_ports.txt') > (60 * 60):
            if stdoutdataIP6pub in (None, '', 'n/a'):
                subprocess.check_call("sudo nmap -F " + public_ipv4 + " | grep open > network_scan_open_ports.txt || true", shell=True)
            else:
                if public_ipv4 not in (None, '', 'n/a'):
                    subprocess.check_call("sudo nmap -F " + public_ipv4 + " | grep open > network_scan_open_ports.txt || true", shell=True)
                    subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub_lo + " | grep open >> network_scan_open_ports.txt || true", shell=True)
                else:
                    subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub_lo + " | grep open > network_scan_open_ports.txt || true", shell=True)
                if stdoutdataIP6pub_lt not in (None, '', 'n/a'):
                    subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub_lt + " | grep open >> network_scan_open_ports.txt || true", shell=True)
    else:
        if stdoutdataIP6pub in (None, '', 'n/a'):
            subprocess.check_call("sudo nmap -F " + public_ipv4 + " | grep open > network_scan_open_ports.txt || true", shell=True)
        else:
            if public_ipv4 not in (None, '', 'n/a'):
                subprocess.check_call("sudo nmap -F " + public_ipv4 + " | grep open > network_scan_open_ports.txt || true", shell=True)
                subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub_lo + " | grep open >> network_scan_open_ports.txt || true", shell=True)
            else:
                subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub_lo + " | grep open > network_scan_open_ports.txt || true", shell=True)
            if stdoutdataIP6pub_lt not in (None, '', 'n/a'):
                subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub_lt + " | grep open >> network_scan_open_ports.txt || true", shell=True)

    if not os.path.exists('network_scan_all.json'):
        dummyData = "{\"" + stdoutdataMAC + "\": {\"FIRST_SEEN\": \"" + timeNow + "\",\"IPv4loc\": \"" + stdoutdataIP4loc + "\",\"IPv4pub\": \"" + public_ipv4 + "\", \
        \"IPv6loc\": \"" + stdoutdataIP6loc + "\",\"IPv6pub\": \"" + stdoutdataIP6pub + "\",\"MAC\": \"" + stdoutdataMAC + "\", \
        \"NAME\": \"" + stdoutdataName + "\",\"SEEN\": \"" + timeNow + "\",\"VENDOR\": \"" + stdoutdataVendor + "\"}}"
        with open('network_scan_all.json', 'w') as outfile:
            outfile.write(dummyData)

    if not os.path.exists('./log/statistic.json'):
        subprocess.check_call("sudo mkdir ./log > /dev/null 2>&1", shell=True)
        dummyDataStat = "{\"" + stdoutdataMAC + "\": [" + unixtimeStr + "]}"
        with open('./log/statistic.json', 'w') as outfileStat:
            outfileStat.write(dummyDataStat)

    dataListHTML.append('</div><div class="content"><table><tr>')

    print('IP Table of ' + stdoutdataName + ':\n')
    print('IPv4 local: ' + stdoutdataIP4loc)
    print('IPv4 public: ' + public_ipv4)
    print('IPv6 local: ' + stdoutdataIP6loc)
    print('IPv6 public: ' + stdoutdataIP6pub_lo)
    print('IPv6 public: ' + stdoutdataIP6pub_lt + '\n')
    print('Interface: ' + stdoutdataIface + '\n')
    print('CPU temperature: ' + stdoutTemp + CRED + ' ' + stdoutTempStat + CEND + '\n')
    print('Disk space in use: ' + stdoutCap + CRED + ' ' + stdoutCapStat + CEND + '\n')

    dataList.append('IP Table of ' + stdoutdataName + ':\n')
    dataList.append('IPv4 local: ' + stdoutdataIP4loc)
    dataList.append('IPv4 public: ' + public_ipv4)
    dataList.append('IPv6 local: ' + stdoutdataIP6loc)
    dataList.append('IPv6 public: ' + stdoutdataIP6pub_lo)
    dataList.append('IPv6 public: ' + stdoutdataIP6pub_lt + '\n')
    dataList.append('Interface: ' + stdoutdataIface + '\n')
    dataList.append('CPU temperature: ' + stdoutTemp + ' ' + stdoutTempStat)
    dataList.append('Disk space in use: ' + stdoutCap + ' ' + stdoutCapStat + '\n')

    dataListNew.append('IP Table of ' + stdoutdataName + ':\n')
    dataListNew.append('IPv4 local: ' + stdoutdataIP4loc)
    dataListNew.append('IPv4 public: ' + public_ipv4)
    dataListNew.append('IPv6 local: ' + stdoutdataIP6loc)
    dataListNew.append('IPv6 public: ' + stdoutdataIP6pub_lo)
    dataListNew.append('IPv6 public: ' + stdoutdataIP6pub_lt + '\n')
    dataListNew.append('Interface: ' + stdoutdataIface + '\n')
    dataListNew.append('CPU temperature: ' + stdoutTemp + ' ' + stdoutTempStat)
    dataListNew.append('Disk space in use: ' + stdoutCap + ' ' + stdoutCapStat + '\n')

    dataListAll.append('IP Table of ' + stdoutdataName + ':\n')
    dataListAll.append('IPv4 local: ' + stdoutdataIP4loc)
    dataListAll.append('IPv4 public: ' + public_ipv4)
    dataListAll.append('IPv6 local: ' + stdoutdataIP6loc)
    dataListAll.append('IPv6 public: ' + stdoutdataIP6pub_lo)
    dataListAll.append('IPv6 public: ' + stdoutdataIP6pub_lt + '\n')
    dataListAll.append('Interface: ' + stdoutdataIface + '\n')
    dataListAll.append('CPU temperature: ' + stdoutTemp + ' ' + stdoutTempStat)
    dataListAll.append('Disk space in use: ' + stdoutCap + ' ' + stdoutCapStat + '\n')

    dataListHTML.append('<td><table><th>IP Table of ' + stdoutdataName + ':</th><tr><td>\n')
    dataListHTML.append('IPv4 local: ' + stdoutdataIP4loc + '<br>')
    dataListHTML.append('IPv4 public: ' + public_ipv4 + '<br><br>\n')
    dataListHTML.append('IPv6 local: ' + stdoutdataIP6loc + '<br>')
    dataListHTML.append('IPv6 public: ' + stdoutdataIP6pub_lo + '<br>')
    dataListHTML.append('IPv6 public: ' + stdoutdataIP6pub_lt + '<br><br>\n')
    dataListHTML.append('Interface: ' + stdoutdataIface + '<br><br>\n')
    dataListHTML.append('CPU temperature: ' + stdoutTemp + ' <font color="red">' + stdoutTempStat + '</font><br>')
    dataListHTML.append('Disk space in use: ' + stdoutCap + ' <font color="red">' + stdoutCapStat + '</font><br>\n')
    dataListHTML.append('</tr>')

    with open('network_scan_open_ports.txt') as portFileHTML:
        dataListHTML.append('<th><div id="show">Open ports:</div></th></tr><td><div id="show">')
        for line in portFileHTML:
            if not line:
                line = 'n/a'
            dataListHTML.append("%s<br>\n" % line)
        dataListHTML.append('</div></tr></table></td>')

    with open('network_scan_open_ports.txt') as portFileHTML:
        dataListHTML.append('<td><table><th><div id="hide">Open ports:</div></th><tr><td><div id="hide">')
        for line in portFileHTML:
            if not line:
                line = 'n/a'
            dataListHTML.append("%s<br>\n" % line)
        dataListHTML.append('</div></td></tr></table></td>')

    with open('network_scan_open_ports.txt') as portFile:
        portAll = portFile.read()
        if not portAll:
            portAll = 'n/a'
        dataList.append('Open ports:\n\n' + portAll + '\n')
        dataListNew.append('Open ports:\n\n' + portAll + '\n')
        dataListAll.append('Open ports:\n\n' + portAll + '\n')
        print('Open ports:\n\n' + portAll + '\n')

doc = minidom.parse('network_scan_online.log')
data = doc.getElementsByTagName('host')

def func():
    with open('network_scan_all.json') as json_file:
            data_all = json.load(json_file)

            if data_all[stdoutdataMAC]["IPv4pub"] != public_ipv4 and data_all[stdoutdataMAC]["IPv6pub"][:37] not in (stdoutdataIP6pub_lo, stdoutdataIP6pub_lt):
                subject = "Public IPs have changed"
                sendMail(subject)
            elif stdoutdataIP6pub ==  "n/a" and data_all[stdoutdataMAC]["IPv4pub"] != public_ipv4:
                subject = "Public IPv4 has changed"
                sendMail(subject)
            elif data_all[stdoutdataMAC]["IPv6pub"][:37] not in (stdoutdataIP6pub_lo, stdoutdataIP6pub_lt):
                subject = "Public IPv6 has changed"
                sendMail(subject)

    for i, v in enumerate(data):
        progbar(i, hostsOnline, 20)
        print(" #" + str(i) + " of #" + str(hostsOnline) + " - Scanning for devices. This might take a few minutes")
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")

        items = v.getElementsByTagName('address')
        itemsTwo = v.getElementsByTagName('hostname')

        try:
            if public_ipv4 == "n/a":
                IPv4pub_get = ('n/a')
            else:
                IPv4pub_get = public_ipv4
        except:
            IPv4pub_get = ('n/a')

        try:
            IPv4loc_get = items[0].attributes['addr'].value
        except:
            IPv4loc_get = ('n/a')

        if IPv4loc_get == stdoutdataIP4loc:
            MAC_get = (stdoutdataMAC)
        else:
            try:
                MAC_get = items[1].attributes['addr'].value
            except:
                if itemsTwo[0].attributes['name'].value == stdoutdataName:
                    MAC_get = (stdoutdataMAC)
                else:
                    MAC_get = ('n/a')

        try:
            try:
                NAME_get = itemsTwo[0].attributes['name'].value
                if MAC_get == stdoutdataMAC:
                    NAME_get = (stdoutdataName)
                if NAME_get is "n/a":
                    stdoutdataArpName = subprocess.getoutput("arp " + IPv4loc_get + " | grep -v Address | awk '{print$1}'")
                    NAME_get = stdoutdataArpName
            except:
                nmbName = subprocess.getoutput("nmblookup -A " + IPv4loc_get + " | grep -v \"<GROUP>\" | grep -v \"Looking\" | awk 'NR==1{print $1}'")
                stdoutdataArpName = subprocess.getoutput("arp " + IPv4loc_get + " | grep -v Address | awk '{print$1}'")
                if MAC_get == stdoutdataMAC:
                    NAME_get = (stdoutdataName)
                elif stdoutdataArpName == IPv4loc_get:
                    if nmbName not in ('No'):
                        NAME_get = nmbName
                    else:
                        NAME_get = ('n/a')
                else:
                    NAME_get = stdoutdataArpName
        except:
            NAME_get = ('n/a')

        try:
            VENDOR_get = items[1].attributes['vendor'].value
        except:
            if MAC_get == stdoutdataMAC:
                VENDOR_get = (stdoutdataVendor)
            else:
                VENDOR_get = ('n/a')

        dataList.append('Name: ' + NAME_get)
        print('Name: ' + NAME_get)
        dataList.append('IPv4 local: ' + IPv4loc_get)
        print('IPv4 local: ' + IPv4loc_get)
        dataList.append('MAC: ' + MAC_get)
        print('MAC: ' + MAC_get)

        DEVICE = {'IPv4loc': IPv4loc_get,'IPv4pub': IPv4pub_get,'MAC': MAC_get,'VENDOR': VENDOR_get,'NAME': NAME_get,'SEEN': timeNow, 'FIRST_SEEN': timeNow}

        with open('network_scan_all.json') as json_file:
            data_all = json.load(json_file)

        if MAC_get in data_all:
            if VENDOR_get == 'n/a':
                stdoutdataMACDiffSec = MAC_get[:8].replace(":","-")
                if os.path.exists('/var/lib/ieee-data/oui.txt'):
                    VENDOR_read = subprocess.getoutput("grep -i \"" + stdoutdataMACDiffSec + "\" /var/lib/ieee-data/oui.txt | awk '{$1=$2=\"\"; print substr($0,2)}'")
                    if VENDOR_read:
                        VENDOR_val = {'VENDOR': VENDOR_read}
                        data_all[MAC_get].update(VENDOR_val)
                    else:
                        VENDOR_get = ('n/a')
                else:
                    VENDOR_get = ('n/a')

            if MAC_get == stdoutdataMAC:
                IPv4loc_val = {'IPv4loc': stdoutdataIP4loc}
                data_all[MAC_get].update(IPv4loc_val)
                IPv4pub_val = {'IPv4pub': public_ipv4}
                data_all[MAC_get].update(IPv4pub_val)
                IPv6loc_val = {'IPv6loc': stdoutdataIP6loc}
                data_all[MAC_get].update(IPv6loc_val)
                IPv6pub_val = {'IPv6pub': stdoutdataIP6pub}
                data_all[MAC_get].update(IPv6pub_val)

            if data_all[MAC_get]["NAME"] == 'n/a':
                NAME_val = {'NAME': NAME_get}
                data_all[MAC_get].update(NAME_val)

            dataList.append('Vendor: ' + VENDOR_get)
            print('Vendor: ' + VENDOR_get)
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
                json.dump(data_all, outfile, sort_keys=False, indent=4)
        else:
            dataListNew.append('Name: ' + NAME_get)
            dataListNew.append('IPv4 local: ' + IPv4loc_get)
            dataListNew.append('MAC: ' + MAC_get)
            print('Vendor: ' + VENDOR_get)

            dataListNew.append('Vendor: ' + VENDOR_get)
            print('Status: Unknown device.')

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
                json.dump(data_all, outfile, sort_keys=False, indent=4)

    dataListNew.append('Detailed info on node:\n\n' + infoAll + '\n')
    dataList.append('Detailed info on node:\n\n' + infoAll + '\n')
    print('\nDetailed info on node:\n\n' + infoAll + '\n')

    with open('network_scan_online.txt', 'w') as readable:
        for item in dataList:
            readable.write("%s\n" % item)

    generateDiagram()
    generateListAll()
    generateListHTML()

    if 'Status: Unknown device.' in dataList:
        subject = "Unknown device detected"
        sendMail(subject)

def generateDiagram(): 
    with open('network_scan_all.json') as json_file:
        data_all = json.load(json_file)
        for item in data_all:
            key = item
            if data_all[key]["SEEN"] == timeNow:
                with open('./log/statistic.json') as json_file:
                    logData = json.load(json_file)
                    if key in logData:
                        logData[key].append(unixtime)
                    else:
                        logData[key] = []
                        logData[key].append(unixtime)
                with open('./log/statistic.json', 'w') as outfile:
                    json.dump(logData, outfile, sort_keys=False, indent=4)

        with open('./log/statistic.json') as json_file:
            logData = json.load(json_file)
            for item in logData:
                key = item
                X = []
                Y = []
                labelsx = []
                labelsxWD = []
                labelsy = ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00', '24:00']
                data = logData[key]
                dateNow = str(date.strftime('%Y-%m-%d'))

                for item in data:
                    tdelta = unixtime - item
                    fromNow = unixtime - tdelta

                    if time.strftime('%m', time.localtime(tdelta)) != '01' or time.strftime('%d', time.localtime(tdelta)) > '07':
                        X = ['-01']
                        Y = [-1]
                        plt.text(3, 12, 'NO DATA TO PLOT FOR THIS TIME PERIOD', horizontalalignment='center', verticalalignment='center')

                    else:
                        days = str(time.strftime('%d', time.localtime(tdelta)))
                        hours = 1 / 60 * int((time.strftime('%M', time.localtime(fromNow)))) + int(time.strftime('%H', time.localtime(fromNow)))
                        hoursRound = float("{0:.2f}".format(hours))

                        if int(time.strftime('%H', time.localtime(fromNow))) > int(time.strftime('%H', time.localtime(unixtime))):
                            days = str(int(time.strftime('%d', time.localtime(tdelta))) + 1)
                        
                        X.append(str("{:02d}".format(int(days))))
                        Y.append(hoursRound)

                for i in range(0, 31):
                    dateDelta = datetime.timedelta(days = i)
                    dateNow = date - dateDelta
                    labelsx.append(str(dateNow.strftime('%A'))[0:3] + ' ' + str(dateNow.strftime('%d. %b %y')))

                X.reverse()
                Y.reverse()

                for z in range(1, int(min(X))):
                    X.insert(0, str("{:02d}".format(int(min(X))-1)))
                    Y.insert(0, -1)

                for i in range(1, int(max(X))):
                    if (str("{:02d}".format(i))) not in X:
                        index = [ n for n,z in enumerate(X) if int(z)>int(i) ][0]
                        X.insert(index, str("{:02d}".format(i)))
                        Y.insert(index, -1)

                plt.scatter(X,Y,s=8, color='blue')
                plt.xlim(-0.3,6.3)
                plt.ylim(-0.5,24.5)
                plt.xticks(np.arange(7), labelsx, rotation=20)
                plt.yticks(np.arange(0, 25, 3),labelsy)
                plt.title('UPTIME OF ' + data_all[key]["NAME"] + ' (' + key + ')')
                plt.tight_layout()
                plt.savefig("./log/" + key + "_7_days.png", dpi=300)
                plt.close()

                plt.scatter(X,Y,s=8, color='blue')
                plt.xlim(-0.3,30.3)
                plt.ylim(-0.5,24.5)
                plt.xticks(np.arange(31), labelsx, rotation=90)
                plt.yticks(np.arange(0, 25, 3),labelsy)
                plt.title('UPTIME OF ' + data_all[key]["NAME"] + ' (' + key + ')')
                plt.tight_layout()
                plt.savefig("./log/" + key + "_1_month.png", dpi=300)
                plt.close()

def generateListAll():
    with open('network_scan_all.json') as json_file:
        data_all = json.load(json_file)

        data_all_sorted = sorted([*data_all.keys()], key=lambda x: (data_all[x]['SEEN'], data_all[x]['IPv4loc']), reverse=True)

        for i, item in enumerate(data_all_sorted):
            key = item
            global z
            z = i + 1
            key_NAME = (data_all[key]["NAME"])
            key_IPv4loc = (data_all[key]["IPv4loc"])
            key_MAC = (data_all[key]["MAC"])
            key_VENDOR = (data_all[key]["VENDOR"])
            key_FIRST_SEEN = (data_all[key]["FIRST_SEEN"])
            key_LAST_SEEN = (data_all[key]["SEEN"])

            dataListAll.append('Name: ' + key_NAME)
            dataListAll.append('IPv4 local: ' + key_IPv4loc)
            dataListAll.append('MAC: ' + key_MAC)
            dataListAll.append('Vendor: ' + key_VENDOR)
            dataListAll.append('First seen: ' + key_FIRST_SEEN)
            dataListAll.append('Last seen: ' + key_LAST_SEEN)

            if key_LAST_SEEN == timeNow:
                key_STATUS = "Online"
            else:
                key_STATUS = "Offline"

            dataListAll.append('Status: ' + key_STATUS)
            dataListAll.append('\n')

        dataListAll.append('Detailed info on node:\n\n' + infoAll + '\n')

    with open('network_scan_all.txt', 'w') as readableList:
        for item in dataListAll:
            readableList.write("%s\n" % item)

def progbar(curr, total, full_progbar):
    frac = curr/total
    filled_progbar = round(frac*full_progbar)
    print('\r', '#'*filled_progbar + '-'*(full_progbar-filled_progbar), '[{:>7.2%}]'.format(frac), end='')

def generateListHTML():
    with open('network_scan_all.json') as json_file:
        data_all = json.load(json_file)

        data_all_sorted = sorted([*data_all.keys()], key=lambda x: (data_all[x]['SEEN'], data_all[x]['IPv4loc']), reverse=True)

        for i, item in enumerate(data_all_sorted):
            key = item
            progbar(i, z, 20)

            key_NAME = (data_all[key]["NAME"])
            key_NAME_raw = (data_all[key]["NAME"])
            key_IPv4loc = (data_all[key]["IPv4loc"])
            key_MAC = (data_all[key]["MAC"])
            key_VENDOR = (data_all[key]["VENDOR"])
            key_FIRST_SEEN = (data_all[key]["FIRST_SEEN"])
            key_LAST_SEEN = (data_all[key]["SEEN"])
            
            print(" #" + str(i) + " of #" + str(z) + " - Scanning " + key_IPv4loc + " (" + key_NAME_raw + ") for services")
            sys.stdout.write("\033[F")
            sys.stdout.write("\033[K")

            stdoutdataURL = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -Ls -o /dev/null -w %{url_effective} " + key_IPv4loc + " | cut -d/ -f3")
            stdoutdataServices = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -s --head " + key_IPv4loc + " | grep \"text/html\" | awk '{print $2}' | cut -d\; -f1")
            if stdoutdataServices == 'text/html':
                key_IPv4loc_url = ('"http://' + key_IPv4loc + '/"')
                key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IPv4loc_url + '>' + key_NAME_raw + ' \
                    <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                    + key_NAME_raw + '" height="10" width="10"></a>')
            elif stdoutdataURL != key_IPv4loc:
                stdoutdataURL = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -Ls -o /dev/null -w %{url_effective} " + key_IPv4loc)
                key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + stdoutdataURL + '>' + key_NAME_raw + ' \
                    <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                    + key_NAME_raw + '" height="10" width="10"></a>')
            else:
                stdoutdataServicesPorts = subprocess.getoutput("sudo nmap --host-timeout 20 -Pn " + key_IPv4loc + " | grep open | cut -d/ -f1").splitlines()
                for item in stdoutdataServicesPorts:
                    stdoutdataForbidden = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -s --head " + key_IPv4loc + ":" + item + " | grep \"403 Forbidden\"")
                    stdoutdataUnavailable = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -s --head " + key_IPv4loc + ":" + item + " | grep \"503 Service Unavailable\"")
                    if stdoutdataForbidden == '' and stdoutdataUnavailable == '':
                        stdoutdataServices = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -s --head " + key_IPv4loc + ":" + item + " | grep \"text/html\" | awk '{print $2}' | cut -d\; -f1")
                        stdoutdataServicesSSL = subprocess.getoutput("curl --connect-timeout 3 --max-time 3 --insecure -s --head " + key_IPv4loc + ":" + item + " | grep \"text/html\" | awk '{print $2}' | cut -d\; -f1")
                        stdoutdataStatus = subprocess.getoutput("curl --connect-timeout 5 --max-time 5 --insecure -s --head https://" + key_IPv4loc + " | grep \"501 Not Implemented\"")
                        if stdoutdataServices == 'text/html':
                            key_IPv4loc_url = ('"http://' + key_IPv4loc + ':' + item + '/"')
                            key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IPv4loc_url + '>' + key_NAME_raw + ' \
                            <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                            + key_NAME_raw + '" height="10" width="10"></a>')
                            break
                        elif stdoutdataServicesSSL == 'text/html':
                            key_IPv4loc_url = ('"https://' + key_IPv4loc + ':' + item + '/"')
                            key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IPv4loc_url + '>' + key_NAME_raw + ' \
                            <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                            + key_NAME_raw + '" height="10" width="10"></a>')
                            break
                        elif stdoutdataStatus == 'HTTP/1.1 501 Not Implemented':
                            key_IPv4loc_url = ('"https://' + key_IPv4loc + '/"')
                            key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IPv4loc_url + '>' + key_NAME_raw + ' \
                            <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                            + key_NAME_raw + '" height="10" width="10"></a>')
                            break
                        else:
                            continue
                    continue

            if key_LAST_SEEN == timeNow:
                dataListHTML.append('<tr><td><table><tr><tr><th>Name: ' + key_NAME + '</th></tr></tr>')
                dataListHTML.append('<tr><td>IPv4 local: ' + key_IPv4loc + '<br>')
                dataListHTML.append('MAC: ' + key_MAC + '<br>')
                dataListHTML.append('Vendor: ' + key_VENDOR + '<br>')
                dataListHTML.append('First seen: ' + key_FIRST_SEEN + '<br>')
                dataListHTML.append('Last seen: ' + key_LAST_SEEN + '<br>')
                dataListHTML.append('<font color="green">Status: Online</font> <span class="dot_green"></span><br>')
                if os.path.exists('./log/' + key_MAC + '_7_days.png'):
                    dataListHTML.append('<br><div id="show"><a target="_blank" rel="noopener noreferrer" href="./log/' + key_MAC + '_7_days.png"> \
                        <div class="container"><img src="./log/' + key_MAC + '_7_days.png" class="image"><div class="overlay"><img src="./log/' + key_MAC + '_1_month.png" class="image"></div></div></a></div></td></tr></table></td>')
                    dataListHTML.append('<td><table><tr><td><div id="hide"><a target="_blank" rel="noopener noreferrer" href="./log/' + key_MAC + '_7_days.png"> \
                        <div class="container"><img src="./log/' + key_MAC + '_7_days.png" class="image"><div class="overlay"><img src="./log/' + key_MAC + '_1_month.png" class="image"></div></div></a></div></td></tr></table></td></tr>')
                else:
                    dataListHTML.append('</tr>')


            else:
                dataListHTML.append('<tr><td><table><tr><tr><th>Name: ' + key_NAME + '</th></tr></tr>')
                dataListHTML.append('<tr><td>IPv4 local: ' + key_IPv4loc + '<br>')
                dataListHTML.append('MAC: ' + key_MAC + '<br>')
                dataListHTML.append('Vendor: ' + key_VENDOR + '<br>')
                dataListHTML.append('First seen: ' + key_FIRST_SEEN + '<br>')
                dataListHTML.append('Last seen: ' + key_LAST_SEEN + '<br>')
                dataListHTML.append('<font color="red">Status: Offline</font> <span class="dot_red"></span><br>')
                if os.path.exists('./log/' + key_MAC + '_7_days.png'):
                    dataListHTML.append('<br><div id="show"><a target="_blank" rel="noopener noreferrer" href="./log/' + key_MAC + '_7_days.png"> \
                        <div class="container"><img src="./log/' + key_MAC + '_7_days.png" class="image"><div class="overlay"><img src="./log/' + key_MAC + '_1_month.png" class="image"></div></div></a></div></td></tr></table></td>')
                    dataListHTML.append('<td><table><tr><td><div id="hide"><a target="_blank" rel="noopener noreferrer" href="./log/' + key_MAC + '_7_days.png"> \
                        <div class="container"><img src="./log/' + key_MAC + '_7_days.png" class="image"><div class="overlay"><img src="./log/' + key_MAC + '_1_month.png" class="image"></div></div></a></div></td></tr></table></td></tr>')
                else:
                    dataListHTML.append('</tr>')

        dataListHTML.append('</tr></table><br>')

        dataListHTML.append('<table><tr><td><table><tr><tr><th>Detailed info on node:</th></tr></tr><tr><td>')

        with open('network_scan_info.log') as infoFileHTML:
            for line in infoFileHTML:
                dataListHTML.append("%s<br>\n" % line)

        dataListHTML.append('</td></tr></table></td></tr></table></div>\n')
        dataListHTML.append('<script>window.onscroll = function() {stickyHead()};\
        function stickyHead() {if (window.pageYOffset > sticky) {header.classList.add("sticky");} else {header.classList.remove("sticky");\}\}</script></body></html>')

    with open('network_scan_all.html', 'w') as readableList:
        for item in dataListHTML:
            readableList.write("%s\n" % item)

def sendMail(subject):
    secret_key = "{: <32}".format(stdoutdataMAC).encode("utf-8")
    cipher = AES.new(secret_key,AES.MODE_ECB)
    try:
        with open('credentials.json') as cred_file:
            cred_all = json.load(cred_file)
        mailEnable = cred_all["mailEnable"]
        if mailEnable is "0":
            os._exit(0)
        emailfrom = cred_all["sender"]
        emailto = cred_all["receiver"]
        mailServer = cred_all["mailServer"]
        password = cred_all["password"]

        decodedpassword = cipher.decrypt(base64.b64decode(password))
        password = decodedpassword.decode('utf8').strip()

        fileToSend = "network_scan_all.txt"

        msg = MIMEMultipart()
        msg["From"] = emailfrom
        msg["To"] = emailto
        msg["Subject"] = subject + ' - ' + stdoutdataName + ' ' + timeNowHuman
        msg.preamble = subject + ' - ' + stdoutdataName + ' ' + timeNowHuman

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

        server = smtplib.SMTP(mailServer, 587)
        server.starttls()
        server.login(emailfrom, password)
        server.sendmail(emailfrom, emailto, msg.as_string())
        server.quit()
        print('Email got sent. Subject: ' + subject + '\n')
    except:
        print(CRED + 'Check the mail credentials. Something is wrong here >> credentials.json\n' + CEND)
        inpOne = input("Do you wanna edit the credentials for sending mail? (y/n) ").lower()
        if inpOne in ('y', 'yes'):
            if not os.path.exists('credentials.json'):
                cred_all_dummy = {
                    "mailEnable": "1",
                    "sender": "",
                    "receiver": "",
                    "mailServer": "",
                    "password": ""
                }
                with open('credentials.json', 'w') as cred_file_dummy:
                    json.dump(cred_all_dummy, cred_file_dummy, indent=4)
                print("\nFile not there. Generating a new one.\n")

            with open('credentials.json', 'r') as cred_file:
                cred_all = json.load(cred_file)
            mailEnableBinary = cred_all["mailEnable"]
            emailfrom = cred_all["sender"]
            emailto = cred_all["receiver"]
            mailServer = cred_all["mailServer"]
            password = cred_all["password"]
            
            decodedpassword = cipher.decrypt(base64.b64decode(password))
            password = decodedpassword.decode('utf8').strip()

            if mailEnableBinary is "0":
                mailEnable = "no"
            else:
                mailEnable = "yes"
            if emailfrom is "":
                emailfrom = "n/a"
            if emailto is "":
                emailto = "n/a"
            if mailServer is "":
                mailServer = "n/a"
            if password is "":
                password = "n/a"
            maskedPassword = password[:3] + (len(password)-3)*"*"
            print('\nSaved credentials:')
            print('\nMailing enabled: ' + mailEnable)
            print('Sender mail address: ' + emailfrom)
            print('Receiver mail address: ' + emailto)
            print('Mail server: ' + mailServer)
            print('Password: ' + maskedPassword)
            print('\nEnter new credentials:\n')

            inpEna = input("Enable mail (yes/no): ").lower()

            with open('credentials.json') as cred_file:
                cred_all = json.load(cred_file)
            
            if inpEna in ('n', 'no'):
                mailEnable_val = {'mailEnable': "0"}
                cred_all.update(mailEnable_val)
                with open('credentials.json', 'w') as cred_file:
                    json.dump(cred_all, cred_file, indent=4)
                print(CRED + '\nMailing successfully disabled.\n' + CEND)
            elif inpEna in ('y', 'yes'):
                inpSen = input("Sender mail address: ").lower()
                inpRec = input("Receiver mail address: ").lower()
                inpMaSe = input("Mail server: ").lower()
                inpPw = getpass.getpass()
                inpPw = "{: <32}".format(inpPw)
                inpPw = base64.b64encode(cipher.encrypt(inpPw))
                inpPw = inpPw.decode('utf8')

                mailEnable_val = {'sender': "1"}
                sender_val = {'sender': inpSen}
                receiver_val = {'receiver': inpRec}
                mailServ_val = {'mailServer': inpMaSe}
                pw_val = {'password': inpPw}
                cred_all.update(sender_val)
                cred_all.update(receiver_val)
                cred_all.update(mailServ_val)
                cred_all.update(pw_val)
                with open('credentials.json', 'w') as cred_file:
                    json.dump(cred_all, cred_file, indent=4)
                print('\nNew credentials successfully set.\n')
            else:
                print(CRED + '\nInvalid input. Starting over.\n' + CEND)
                sendMail(subject)

            sendMail(subject)

        elif inpOne in ('n', 'no'):
            print(CRED + '\nF you then.\n' + CEND)
            sys.exit(0)
        else:
            print(CRED + '\nWrong input.\n' + CEND)
            sys.exit(0)

func()
