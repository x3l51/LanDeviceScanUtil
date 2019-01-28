# !/usr/bin/env python3.6
# -*- coding: utf-8 -*-
# network_scan_email_compare.py

try:
    import datetime
    import subprocess
    import smtplib
    import mimetypes
    import email
    import requests
    import os
    import os.path, time
    import sys
    import json
    from email import encoders
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from xml.dom import minidom
except ImportError:
    subprocess.call("sudo -H apt-get install python3-pip -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3-nmap -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 datetime -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 subprocress -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 smtplib -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 mimetypes -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 email -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 requests -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 json -y > {}".format(os.devnull), shell=True)
    subprocess.call("sudo -H apt-get install python3 xml.dom -y > {}".format(os.devnull), shell=True)

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
    stdoutdataIP6pub = subprocess.getoutput("ifconfig | grep \"inet6 \" | grep -v fe | grep -v ::")
    if stdoutdataIP6pub is "":
        stdoutdataIP6pub = "n/a"
    stdoutdataIface = subprocess.getoutput("route | grep '^default' | grep -o '[^ ]*$'")
    if stdoutdataIface.startswith('e'):
        stdoutdataIface = ("Ethernet (" + stdoutdataIface + ")")
    elif stdoutdataIface.startswith('e'):
        stdoutdataIface = ("Wireless (" + stdoutdataIface + ")")
    stdoutdataMAC = subprocess.getoutput("cat /sys/class/net/*/address | awk 'NR==1{print $1}'")
    stdoutdataMACDiff = stdoutdataMAC[:8].replace(":","-")
    try:
        stdoutdataVendor = subprocess.getoutput("grep -i \"" + stdoutdataMACDiff + "\" /var/lib/ieee-data/oui.txt | awk '{$1=$2=\"\"; print substr($0,2)}'")
    except:
        stdoutdataVendor = "n/a"
    subprocess.check_call("sudo nmap -sP -sn -oX network_scan_online.log 192.168.0.* > /dev/null 2>&1", shell=True)
    
    if os.path.exists('network_scan_info.log'):
        if time.time() - os.path.getmtime('network_scan_info.log') > (60 * 60):
            subprocess.check_call("sudo nmap -F -A -oN network_scan_info.log " + public_ip + " > /dev/null 2>&1", shell=True)
    else:
        subprocess.check_call("sudo nmap -F -A -oN network_scan_info.log " + public_ip + " > /dev/null 2>&1", shell=True)
    with open('network_scan_info.log') as infoFile:
        infoAll = infoFile.read()

    if os.path.exists('network_scan_open_ports.txt'):
        if time.time() - os.path.getmtime('network_scan_open_ports.txt') > (60 * 60):
            subprocess.check_call("sudo nmap -F " + public_ip + " | grep open > network_scan_open_ports.txt", shell=True)
    else:
        subprocess.check_call("sudo nmap -F " + public_ip + " | grep open > network_scan_open_ports.txt", shell=True)

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
        
        items = v.getElementsByTagName('address')
        itemsTwo = v.getElementsByTagName('hostname')

        # IP
        try:
            IP_get = items[0].attributes['addr'].value
        except:
            IP_get = ('n/a')

        # MAC
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

        # NAME
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

                stdoutdataArpName = subprocess.getoutput("arp " + IP_get + " | grep -v Address | awk '{print$1}'")
                if stdoutdataArpName == IP_get:
                    NAME_get = ('n/a')
                else:
                    NAME_get = stdoutdataArpName
        except:
           NAME_get = ('n/a')

        # VENDOR
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
                VENDOR_read = subprocess.getoutput("grep -i \"" + stdoutdataMACDiffSec + "\" /var/lib/ieee-data/oui.txt | awk '{$1=$2=\"\"; print substr($0,2)}'")
                if VENDOR_read:
                    VENDOR_get = VENDOR_read
                    VENDOR_val = {'VENDOR': VENDOR_get}
                    data_all[MAC_get].update(VENDOR_val)
                else:
                    VENDOR_get = ('n/a')
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
                json.dump(data_all, outfile, sort_keys=True, indent=4)
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
                json.dump(data_all, outfile, sort_keys=True, indent=4)
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
    else:
        return

def generateListAll():
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

def generateListHTML():
    with open('network_scan_all.json') as json_file:
        data_all = json.load(json_file)
        for i, key in enumerate(data_all.keys()):
            if i % 2 == 0:
                dataListHTML.append('<tr>')
            key_NAME = (data_all[key]["NAME"])
            key_IP = (data_all[key]["IP"])
            key_MAC = (data_all[key]["MAC"])
            key_VENDOR = (data_all[key]["VENDOR"])
            key_FIRST_SEEN = (data_all[key]["FIRST_SEEN"])
            key_LAST_SEEN = (data_all[key]["SEEN"])
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
    emailfrom = "MAIL_SENDER_HERE"
    emailto = ["MAIL_RECEIVER_HERE"]
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

    server = smtplib.SMTP('MAIL_SERVER_HERE', 587)
    server.starttls()
    server.login(emailfrom, "MAIL_PASSWORD_HERE")
    server.sendmail(emailfrom, emailto, msg.as_string())
    server.quit()
    print('Email got sent.\n')

func()
