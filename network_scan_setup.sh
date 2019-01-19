sudo wget https://raw.githubusercontent.com/x3l51/LanDeviceScanUtil/master/network_scan.py
sudo wget https://raw.githubusercontent.com/x3l51/LanDeviceScanUtil/master/network_scan_email.py
sudo wget https://raw.githubusercontent.com/x3l51/LanDeviceScanUtil/master/network_scan_email_compare.py
sudo chmod +x network_scan_email_compare.py
sudo crontab -e
* * * * * cd /filePath/to/yourScript && python3 network_scan_email_compare.py
