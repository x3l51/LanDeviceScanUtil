# LanDeviceScanUtil
Scans the local network for devices in IP range 192.168.0.*

You'll find a human readable output file named `network_scan_all.txt`

For the scripts with email you have to enter your credentials.

The script `network_scan_email_compare.py` has a list with all devices it has ever seen. If an unknown device is detected, the email is sent.

```
--@server:/testing $ sudo python3 network_scan_email_compare.py

Time: 2019-01-19 05:41:57

IP: 192.168.0.1
MAC: 5C:49:79:8B:XX:XX
Vendor: VendorName
Name: gateway
Status: Known Device.


IP: 192.168.0.20
MAC: 90:A7:83:87:XX:XX
Vendor: VendorName
Name: something.gateway
Status: Unknown Device.


IP: 192.168.0.74
MAC: n/a
Vendor: n/a
Name: server.gateway
Status: Unknown device.


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
