# LanDeviceScanUtil
Scans the local network for devices in IP range 192.168.0.*

If you want to scan another IP range, modify the script on line 9


```
--@server:/testing $ sudo python3 network_scan.py

Time: 2019-01-17 13:34:17

IP: 192.168.0.1
MAC: 5C:49:79:8B:XX:XX
Vendor: VendorName
Name: gateway


IP: 192.168.0.20
MAC: 90:A7:83:87:XX:XX
Vendor: VendorName
Name: something.gateway


IP: 192.168.0.74
MAC: n/a
Vendor: n/a
Name: server.gateway
```

For the scripts with email you have to enter your credentials.

The script `network_scan_email_compare.py` has list with all devices it has ever seen and does compare every new scan with if it has already seen the devices. If an unknown device is detected, the email is sent.

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
