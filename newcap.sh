#!/bin/bash
DIRCAP=$(echo "cap");
cd $DIRCAP;
N=$(ls -s | wc -l);
PCAPNAME=$(echo "cap"$N".pcap");
DIRNAME=$(echo $DIRCAP"_"$N);
sudo mkdir $DIRNAME;
cd $DIRNAME;
sudo tshark -i wlan0 -f "tcp and (src host archlinux.mirrors.ovh.net)" -w $PCAPNAME &
sleep 5;
wget http://archlinux.mirrors.ovh.net/archlinux/iso/2013.10.01/archlinux-2013.10.01-dual.iso;
sudo killall tshark;
sudo chown $USER $PCAPNAME;
