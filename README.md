# LanDeviceScanUtil
Scans the local network for devices in IP range 192.168.0.*

You'll find a human readable output file named `network_scan_all.txt`

For the scripts with email you have to enter your credentials.

The script `network_scan_email_compare.py` has a list with all devices it has ever seen (`network_scan_all.json`, this one is human readable: `network_scan_all.txt`). If an unknown device is detected, an email is sent.

```
--@server:/testing $ sudo python3 network_scan_email_compare.py

Time: 2019-01-19 05:41:57

Public IP: 89.215.12.81

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
```


If you want to have an email sent everytime an unknown device is being discovered in the network, do the following:

Run the script as a cronjob every minute. To do so, download the script with:

    `sudo wget https://raw.githubusercontent.com/x3l51/LanDeviceScanUtil/master/network_scan_email_compare.py`

And modify the script to contain your credentials for sending emails.
    
Then type:

    `sudo chmod +x network_scan_email_compare.py
    
Then type:

    `sudo crontab -e`
    
Append this at the end of the file:

    `* * * * * cd /filePath/to/yourScript && python3 network_scan_email_compare.py`
    


You could also have all this automated with this commands:

    `sudo wget https://raw.githubusercontent.com/x3l51/LanDeviceScanUtil/master/network_scan_setup.sh && sudo bash network_scan_setup.sh`
