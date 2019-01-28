cd ~/
sudo mkdir ~/Network_Scan
cd ~/Network_Scan
sudo wget https://github.com/x3l51/LanDeviceScanUtil/archive/master.zip
sudo unzip master.zip
cd LanDeviceScanUtil-master/
sudo chmod +x network_scan_email_compare.py
crontab -l > mycron
echo "* * * * * cd /filePath/to/yourScript && python3 network_scan_email_compare.py" >> mycron
crontab mycron
rm mycron
sudo python3 network_scan_email_compare.py
