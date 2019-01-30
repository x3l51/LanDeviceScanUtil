# LanDeviceScanUtil
Scans the local network for devices in the same IP range as you are.

You'll find a human readable output file named `network_scan_all.txt` and a html fine named `network_scan_all.html`, which you could `cp` via cron into your apache server. It's really beautiful tho!

The script `network_scan_email_compare.py` creates and updates a list with all devices it has ever seen (`network_scan_all.json`). If an unknown device is detected, an email is sent.



This will automatically use the full IP range, which your device is in:
```
sudo python3 network_scan_email_compare.py
```



This let's you enter a custom range or specific device:
```
sudo python3 network_scan_email_compare.py 192.168.0.*
```
```
sudo python3 network_scan_email_compare.py 192.168.0.1/24
```
```
sudo python3 network_scan_email_compare.py 192.168.0.91
```


Output:
```
--@server:/testing $ sudo python3 network_scan_email_compare.py

Time: 2019-01-19 05:41:57

IP Table of server.gateway:

IPv4 local: 192.168.0.74
IPv4 public: 89.215.12.71
IPv6 local: fb00::a00:11ff:abc1:de0f
IPv6 public: n/a

Interface: Ethernet (eth1)

Open ports:

22/tcp  open  ssh
443/tcp  open  https

Name: gateway
IP: 192.168.0.1
MAC: 5C:49:79:8B:XX:XX
Vendor: VendorName
Status: Known Device.
First seen: 2019-01-16_13:41:32


Name: something.gateway
IP: 192.168.0.20
MAC: 90:A7:83:87:XX:XX
Vendor: VendorName
Status: Unknown Device.
First seen: 2019-01-19_05:41:57


Name: server.gateway
IP: 192.168.0.74
MAC: n/a
Vendor: n/a
Status: Unknown device.
First seen: 2019-01-19_05:41:57


Email got sent.

Detailed info on node:

# NMAP output of """nmap -F -A -oN""" here
```


If you want to have an email sent everytime an unknown device is being discovered in the network, do the following:

Run the script as a cronjob every minute or so. To do so, download the script with:

    sudo wget https://raw.githubusercontent.com/x3l51/LanDeviceScanUtil/master/network_scan_email_compare.py
    
Then type:

    sudo chmod +x network_scan_email_compare.py
    
Then type:

    sudo crontab -e
    
Append this at the end of the file to have it run every minute:

    * * * * * cd /filePath/to/yourScript && python3 network_scan_email_compare.py
    


You could also have all this automated with this commands:

    sudo wget https://raw.githubusercontent.com/x3l51/LanDeviceScanUtil/master/network_scan_setup.sh && sudo bash network_scan_setup.sh
