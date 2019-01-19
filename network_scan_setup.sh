sudo wget https://github.com/x3l51/LanDeviceScanUtil/archive/master.zip
sudo unzip master.zip
cd LanDeviceScanUtil-master/
sudo chmod +x network_scan.py
sudo chmod +x network_scan_email.py
sudo chmod +x network_scan_email_compare.py
sudo crontab -l | { cat; echo "* * * * * cd /filePath/to/yourScript && python3 network_scan_email_compare.py"; } | crontab -
