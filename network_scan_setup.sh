#!/bin/sh

echo "What is your usename?"
read curUSER
cd /home/$curUSER
sudo wget https://github.com/x3l51/LanDeviceScanUtil/archive/master.zip
sudo unzip master.zip
sudo rm master.zip
cd /home/$curUSER/LanDeviceScanUtil-master
sudo chmod +x network_scan_email_compare.py
crontab -l > mycron
echo "*/30 * * * * cd /home/$curUSER/LanDeviceScanUtil-master && sudo python3 network_scan_email_compare.py" >> mycron
crontab mycron
rm mycron
sudo python3 network_scan_email_compare.py
