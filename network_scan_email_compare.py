# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# network_scan_email_compare.py

import datetime
import subprocess
import smtplib
import mimetypes
import email
import os
import os.path, time
import sys
import json
import getpass
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from xml.dom import minidom

CRED = '\033[91m'
CEND = '\033[0m'

if sys.version_info[0] < 3:
    print(CRED + "\nRestart the script using python3: 'sudo python3 network_scan_email_compare.py'\n" + CEND)
    sys.exit(0)

if os.geteuid() != 0:
    print(CRED + "\nRestart the script with root privileges: 'sudo python3 network_scan_email_compare.py'\n" + CEND)
    sys.exit(0)

try:
    import requests
    import nmap
except ImportError:
    subprocess.call("sudo -H apt-get install python3-pip -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3-nmap -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H python3 -m pip install requests > {}".format(os.devnull), shell=True)

if not os.path.exists('/usr/bin/nmblookup'):
    subprocess.call("sudo -H apt-get install samba-common-bin -y > {}".format(os.devnull), shell=True)

date = datetime.datetime.now()
timeNow = str(date.strftime('%Y-%m-%d_%H:%M:%S'))

dataList = []
dataListNew = []
dataListAll = []
dataListHTML = []
dataListHTML.append('<html><head><meta http-equiv="refresh" content="60" charset="utf-8" content="width=device-width, initial-scale=1"/><html lang="EN"><title>NET.SCAN</title><style> \
        * {font-family: calibri;} \
        .dot_green {height: 10px;width: 10px;background-color: green;border-radius: 50%;display: inline-block;} \
        .dot_red {height: 10px;width: 10px;background-color: red;border-radius: 50%;display: inline-block;} \
        body {margin: 0;font-family: Arial, Helvetica, sans-serif;} \
        .header {padding: 2px 16px; background: #555;color: #f1f1f1;} \
        .content {padding: 16px;} \
        a:link {text-decoration: none;color: black;} \
        .sticky {padding: 2px 33px; background: #555;color: #f1f1f1;position: fixed;top: 0;width: 100%;} \
        .sticky + .content {padding-top: 102px;} \
        table {width: 100%;border-collapse: collapse;} \
        td { width: 50%; border: 1px solid #dddddd;text-align: left;padding: 8px;vertical-align: top;} \
        th { border: 1px solid #dddddd;text-align: left;padding: 8px;vertical-align: top;} \
        </style></head><body style="background-color:#dddddd;"><div class="sticky" id="topHeader"><br>Time: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '<br><br>\n')

dataList.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
dataListNew.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
dataListAll.append('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n')
print('\nTime: ' + date.strftime('%Y-%m-%d %H:%M:%S') + '\n') 


public_ip = requests.get('http://ip.42.pl/raw').text
hostname = "ip.42.pl"
response = os.system("ping -c 1 " + hostname + " > /dev/null 2>&1")

if response == 0:
    stdoutdataName = subprocess.getoutput("hostname")
    stdoutdataIP4loc = subprocess.getoutput("ifconfig | grep \"inet \" | grep -v 127.0.0.1 | awk '{print $2}'")

    if stdoutdataIP4loc is "":
        stdoutdataIP4loc = "n/a"
    stdoutdataIP6loc = subprocess.getoutput("ifconfig | grep \"inet6 \" | grep fe | awk '{print $2}'")

    if stdoutdataIP6loc is "":
        stdoutdataIP6loc = "n/a"
    stdoutdataIP6pub = subprocess.getoutput("ifconfig | grep \"inet6 \" | grep -v fe | grep -v :: | awk '{print$2}'")

    if stdoutdataIP6pub is "":
        stdoutdataIP6pub = "n/a"
    stdoutdataIface = subprocess.getoutput("route | grep '^default' | grep -o '[^ ]*$'")

    if stdoutdataIface.startswith('e'):
        stdoutdataIface = ("Ethernet (" + stdoutdataIface + ")")
    elif stdoutdataIface.startswith('e'):
        stdoutdataIface = ("Wireless (" + stdoutdataIface + ")")

    stdoutdataMAC = subprocess.getoutput("cat /sys/class/net/*/address | awk 'NR==1{print $1}'")
    stdoutdataMACDiff = stdoutdataMAC[:8].replace(":","-")

    if os.path.exists('/var/lib/ieee-data/oui.txt'):
        stdoutdataVendor = subprocess.getoutput("grep -i \"" + stdoutdataMACDiff + "\" /var/lib/ieee-data/oui.txt | awk '{$1=$2=\"\"; print substr($0,2)}'")
    else:
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
                subprocess.check_call("sudo nmap -F -A -oN network_scan_info.log " + public_ip + " > /dev/null 2>&1", shell=True)
            else:
                subprocess.check_call("sudo nmap -6 -F -A -oN network_scan_info.log " + stdoutdataIP6pub + " > /dev/null 2>&1", shell=True)
    else:
        if stdoutdataIP6pub in (None, '', 'n/a'):
            subprocess.check_call("sudo nmap -F -A -oN network_scan_info.log " + public_ip + " > /dev/null 2>&1", shell=True)
        else:
            subprocess.check_call("sudo nmap -6 -F -A -oN network_scan_info.log " + stdoutdataIP6pub + " > /dev/null 2>&1", shell=True)

    with open('network_scan_info.log') as infoFile:
        infoAll = infoFile.read()

    if os.path.exists('network_scan_open_ports.txt'):
        if time.time() - os.path.getmtime('network_scan_open_ports.txt') > (60 * 60):
            if stdoutdataIP6pub in (None, '', 'n/a'):
                subprocess.check_call("sudo nmap -F " + public_ip + " | grep open > network_scan_open_ports.txt", shell=True)
            else:
                subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub + " | grep open > network_scan_open_ports.txt", shell=True)
    else:
        if stdoutdataIP6pub in (None, '', 'n/a'):
            subprocess.check_call("sudo nmap -F " + public_ip + " | grep open > network_scan_open_ports.txt", shell=True)
        else:
            subprocess.check_call("sudo nmap -6 -F " + stdoutdataIP6pub + " | grep open > network_scan_open_ports.txt", shell=True)

    if not os.path.exists('network_scan_all.json'):
        dummyData = "{\"" + stdoutdataMAC + "\": {\"FIRST_SEEN\": \"" + timeNow + "\",\"IP\": \"" + stdoutdataIP4loc + "\", \
        \"IPv6loc\": \"" + stdoutdataIP6loc + "\",\"IPv6pub\": \"" + stdoutdataIP6pub + "\",\"MAC\": \"" + stdoutdataMAC + "\", \
        \"NAME\": \"" + stdoutdataName + "\",\"SEEN\": \"" + timeNow + "\",\"VENDOR\": \"" + stdoutdataVendor + "\"}}"
        with open('network_scan_all.json', 'w') as outfile:
            outfile.write(dummyData)

    dataListHTML.append('</div><div class="content"><table><tr>')

    print('IP Table of ' + stdoutdataName + ':\n')
    print('IPv4 local: ' + stdoutdataIP4loc)
    print('IPv4 public: ' + public_ip)
    print('IPv6 local: ' + stdoutdataIP6loc)
    print('IPv6 public: ' + stdoutdataIP6pub + '\n')
    print('Interface: ' + stdoutdataIface + '\n')

    dataList.append('IP Table of ' + stdoutdataName + ':\n')
    dataList.append('IPv4 local: ' + stdoutdataIP4loc)
    dataList.append('IPv4 public: ' + public_ip)
    dataList.append('IPv6 local: ' + stdoutdataIP6loc)
    dataList.append('IPv6 public: ' + stdoutdataIP6pub + '\n')
    dataList.append('IPv6 public: ' + stdoutdataIP6pub + '\n')

    dataListNew.append('IP Table of ' + stdoutdataName + ':\n')
    dataListNew.append('IPv4 local: ' + stdoutdataIP4loc)
    dataListNew.append('IPv4 public: ' + public_ip)
    dataListNew.append('IPv6 local: ' + stdoutdataIP6loc)
    dataListNew.append('IPv6 public: ' + stdoutdataIP6pub + '\n')
    dataListNew.append('Interface: ' + stdoutdataIface + '\n')

    dataListAll.append('IP Table of ' + stdoutdataName + ':\n')
    dataListAll.append('IPv4 local: ' + stdoutdataIP4loc)
    dataListAll.append('IPv4 public: ' + public_ip)
    dataListAll.append('IPv6 local: ' + stdoutdataIP6loc)
    dataListAll.append('IPv6 public: ' + stdoutdataIP6pub + '\n')
    dataListAll.append('Interface: ' + stdoutdataIface + '\n')

    dataListHTML.append('<td><table><tr><tr><th>IP Table of ' + stdoutdataName + ':</th></tr></tr><tr><td>\n')
    dataListHTML.append('IPv4 local: ' + stdoutdataIP4loc + '<br>')
    dataListHTML.append('IPv4 public: ' + public_ip + '<br><br>\n')
    dataListHTML.append('IPv6 local: ' + stdoutdataIP6loc + '<br>')
    dataListHTML.append('IPv6 public: ' + stdoutdataIP6pub + '<br><br>\n')
    dataListHTML.append('Interface: ' + stdoutdataIface + '<br>\n')
    dataListHTML.append('</td></tr></table></td>')

    with open('network_scan_open_ports.txt') as portFileHTML:
        dataListHTML.append('<td><table><tr><tr><th>Open ports:</th></tr></tr><tr><td>')
        for line in portFileHTML:
            dataListHTML.append("%s<br>\n" % line)
        dataListHTML.append('</td></tr></table></td>')

    with open('network_scan_open_ports.txt') as portFile:
        portAll = portFile.read()
        dataList.append('Open ports:\n\n' + portAll + '\n')
        dataListNew.append('Open ports:\n\n' + portAll + '\n')
        dataListAll.append('Open ports:\n\n' + portAll + '\n')
        print('Open ports:\n\n' + portAll + '\n')

doc = minidom.parse('network_scan_online.log')
data = doc.getElementsByTagName('host')

def func():
    for i, v in enumerate(data):
        progbar(i, hostsOnline, 20)
        print(" #" + str(i+1) + " of #" + str(hostsOnline) + " - Scanning for devices. This might take a few minutes")
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")

        items = v.getElementsByTagName('address')
        itemsTwo = v.getElementsByTagName('hostname')

        try:
            IP_get = items[0].attributes['addr'].value
        except:
            IP_get = ('n/a')

        if IP_get == stdoutdataIP4loc:
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
                    stdoutdataArpName = subprocess.getoutput("arp " + IP_get + " | grep -v Address | awk '{print$1}'")
                    NAME_get = stdoutdataArpName
            except:
                if MAC_get == stdoutdataMAC:
                    NAME_get = (stdoutdataName)

                nmbName = subprocess.getoutput("nmblookup -A " + IP_get + " | grep -v \"<GROUP>\" | grep -v \"Looking\" | awk 'NR==1{print $1}'")
                stdoutdataArpName = subprocess.getoutput("arp " + IP_get + " | grep -v Address | awk '{print$1}'")
                if stdoutdataArpName == IP_get:
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
        dataList.append('IP: ' + IP_get)
        print('IP: ' + IP_get)
        dataList.append('MAC: ' + MAC_get)
        print('MAC: ' + MAC_get)

        DEVICE = {'IP': IP_get,'MAC': MAC_get,'VENDOR': VENDOR_get,'NAME': NAME_get,'SEEN': timeNow, 'FIRST_SEEN': timeNow}

        with open('network_scan_all.json') as json_file:
            data_all = json.load(json_file)

        if MAC_get in data_all:
            if VENDOR_get == 'n/a':
                stdoutdataMACDiffSec = MAC_get[:8].replace(":","-")
                if os.path.exists('/var/lib/ieee-data/oui.txt'):
                    VENDOR_read = subprocess.getoutput("grep -i \"" + stdoutdataMACDiffSec + "\" /var/lib/ieee-data/oui.txt | awk '{$1=$2=\"\"; print substr($0,2)}'")
                    if VENDOR_read:
                        VENDOR_get = VENDOR_read
                        VENDOR_val = {'VENDOR': VENDOR_get}
                        data_all[MAC_get].update(VENDOR_val)
                    else:
                        VENDOR_get = ('n/a')
                else:
                    VENDOR_get = ('n/a')

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
            dataListNew.append('IP: ' + IP_get)
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

    generateListAll()
    generateListHTML()

    if 'Status: Unknown device.' in dataList:
        sendMail()

def generateListAll():
    with open('network_scan_all.json') as json_file:
        data_all = json.load(json_file)
        for i, key in enumerate(data_all.keys()):
            global z
            z = i
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
        for i, key in enumerate(data_all.keys()):
            progbar(i, z, 20)

            if i % 2 == 0:
                dataListHTML.append('<tr>')
            key_NAME = (data_all[key]["NAME"])
            key_NAME_raw = (data_all[key]["NAME"])
            key_IP = (data_all[key]["IP"])
            key_MAC = (data_all[key]["MAC"])
            key_VENDOR = (data_all[key]["VENDOR"])
            key_FIRST_SEEN = (data_all[key]["FIRST_SEEN"])
            key_LAST_SEEN = (data_all[key]["SEEN"])

            print(" #" + str(i+1) + " of #" + str(z) + " - Scanning " + key_IP + " (" + key_NAME_raw + ") for services")
            sys.stdout.write("\033[F")
            sys.stdout.write("\033[K")

            stdoutdataURL = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -Ls -o /dev/null -w %{url_effective} " + key_IP + " | cut -d/ -f3")
            stdoutdataServices = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -s --head " + key_IP + " | grep \"text/html\" | awk '{print $2}' | cut -d\; -f1")
            print("stdoutdataURL " + stdoutdataURL)
            if stdoutdataServices == 'text/html':
                key_IP_url = ('"http://' + key_IP + '/"')
                key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IP_url + '>' + key_NAME_raw + ' \
                    <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                    + key_NAME_raw + '" height="10" width="10"></a>')
            elif stdoutdataURL != key_IP:
                stdoutdataURL = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -Ls -o /dev/null -w %{url_effective} " + key_IP)
                key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + stdoutdataURL + '>' + key_NAME_raw + ' \
                    <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                    + key_NAME_raw + '" height="10" width="10"></a>')
            else:
                stdoutdataServicesPorts = subprocess.getoutput("sudo nmap --host-timeout 30 -Pn " + key_IP + " | grep open | cut -d/ -f1").splitlines()
                for item in stdoutdataServicesPorts:
                    stdoutdataForbidden = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -s --head " + key_IP + ":" + item + " | grep \"403 Forbidden\"")
                    if stdoutdataForbidden == '':
                        stdoutdataServices = subprocess.getoutput("curl --connect-timeout 1 --max-time 2 -s --head " + key_IP + ":" + item + " | grep \"text/html\" | awk '{print $2}' | cut -d\; -f1")
                        stdoutdataServicesSSL = subprocess.getoutput("curl --connect-timeout 3 --max-time 3 --insecure -s --head " + key_IP + ":" + item + " | grep \"text/html\" | awk '{print $2}' | cut -d\; -f1")
                        stdoutdataStatus = subprocess.getoutput("curl --connect-timeout 5 --max-time 5 --insecure -s --head https://" + key_IP + " | grep \"501 Not Implemented\"")
                        if stdoutdataServices == 'text/html':
                            key_IP_url = ('"http://' + key_IP + ':' + item + '/"')
                            key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IP_url + '>' + key_NAME_raw + ' \
                            <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                            + key_NAME_raw + '" height="10" width="10"></a>')
                            break
                        elif stdoutdataServicesSSL == 'text/html':
                            key_IP_url = ('"https://' + key_IP + ':' + item + '/"')
                            key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IP_url + '>' + key_NAME_raw + ' \
                            <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                            + key_NAME_raw + '" height="10" width="10"></a>')
                            break
                        elif stdoutdataStatus == 'HTTP/1.1 501 Not Implemented':
                            key_IP_url = ('"https://' + key_IP + '/"')
                            key_NAME = ('<a target="_blank" rel="noopener noreferrer" href=' + key_IP_url + '>' + key_NAME_raw + ' \
                            <img src="https://wiki.selfhtml.org/images/7/7e/Link_icon_black.svg" alt="' \
                            + key_NAME_raw + '" height="10" width="10"></a>')
                            break
                        else:
                            continue
                    continue

            if key_LAST_SEEN == timeNow:
                dataListHTML.append('<td><table><tr><tr><th>Name: ' + key_NAME + '</th></tr></tr>')
                dataListHTML.append('<tr><td>IP: ' + key_IP + '<br>')
                dataListHTML.append('MAC: ' + key_MAC + '<br>')
                dataListHTML.append('Vendor: ' + key_VENDOR + '<br>')
                dataListHTML.append('First seen: ' + key_FIRST_SEEN + '<br>')
                dataListHTML.append('Last seen: ' + key_LAST_SEEN + '<br>')
                dataListHTML.append('<font color="green">Status: Online</font> <span class="dot_green"></span><br></td></tr></table></td>')
            else:
                dataListHTML.append('<td><table><tr><tr><th>Name: ' + key_NAME + '</th></tr></tr>')
                dataListHTML.append('<tr><td>IP: ' + key_IP + '<br>')
                dataListHTML.append('MAC: ' + key_MAC + '<br>')
                dataListHTML.append('Vendor: ' + key_VENDOR + '<br>')
                dataListHTML.append('First seen: ' + key_FIRST_SEEN + '<br>')
                dataListHTML.append('Last seen: ' + key_LAST_SEEN + '<br>')
                dataListHTML.append('<font color="red">Status: Offline</font> <span class="dot_red"></span><br></td></tr></table></td>')

            if i % 2 != 0:
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

def sendMail():
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

        fileToSend = "network_scan_all.txt"

        msg = MIMEMultipart()
        msg["From"] = emailfrom
        msg["To"] = emailto
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

        server = smtplib.SMTP(mailServer, 587)
        server.starttls()
        server.login(emailfrom, password)
        server.sendmail(emailfrom, emailto, msg.as_string())
        server.quit()
        print('Email got sent.\n')
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
                    json.dump(cred_all_dummy, cred_file_dummy)
                print("\nFile not there. Generating a new one.\n")

            with open('credentials.json', 'r') as cred_file:
                cred_all = json.load(cred_file)
            mailEnableBinary = cred_all["mailEnable"]
            emailfrom = cred_all["sender"]
            emailto = cred_all["receiver"]
            mailServer = cred_all["mailServer"]
            password = cred_all["password"]
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
                    json.dump(cred_all, cred_file)
                print(CRED + '\nMailing successfully disabled.\n' + CEND)
            elif inpEna in ('y', 'yes'):
                inpSen = input("Sender mail address: ").lower()
                inpRec = input("Receiver mail address: ").lower()
                inpMaSe = input("Mail server: ").lower()
                inpPw = getpass.getpass()
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
                    json.dump(cred_all, cred_file)
                print('\nNew credentials successfully set.\n')
            else:
                print(CRED + '\nInvalid input. Starting over.\n' + CEND)
                sendMail()

            sendMail()

        elif inpOne in ('n', 'no'):
            print(CRED + '\nF you then.\n' + CEND)
            sys.exit(0)
        else:
            print(CRED + '\nWrong input.\n' + CEND)
            sys.exit(0)

func()
