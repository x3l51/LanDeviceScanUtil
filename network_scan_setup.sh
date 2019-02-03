sudo mkdir /home/$USER/Network_Scan
cd /home/$USER/Network_Scan
sudo wget https://github.com/x3l51/LanDeviceScanUtil/archive/master.zip
sudo unzip master.zip
sudo rm master.zip
cd /home/$USER/Network_Scan/LanDeviceScanUtil-master
sudo chmod +x network_scan_email_compare.py
crontab -l > mycron
echo "*/30 * * * * cd /home/$USER/Network_Scan/LanDeviceScanUtil-master && sudo python3 network_scan_email_compare.py" >> mycron
crontab mycron
rm mycron
sudo python3 network_scan_email_compare.py
