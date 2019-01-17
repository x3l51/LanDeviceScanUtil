# LanDeviceScanUtil
Scans the local network for devices in IP range 192.168.0.*

If you want to scan another IP range, modify the script on line 9


```
--@server:/testing $ sudo python3 network_scan.py
nohup: ignoring input and appending output to 'nohup.out'

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
