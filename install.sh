#!/bin/bash

######## INSTALLATION ###########################################################

utilisateur=$(grep 1000 /etc/passwd | awk -F ":" '{print $1}')
echo -e "${jaune}Utiliser 'sudo' ou root :\nSi [OK] appuyer sur [ENTRER]\nSinon appuyer sur [Ctrl + c]${neutre}"
read test1

mkdir /home/$utilisateur/Documents/Linux-Post_Install/
cp -r * /home/$utilisateur/Documents/Linux-Post_Install/
cd /home/$utilisateur/Documents/Linux-Post_Install/
chmod -R 750 /home/$utilisateur/Documents/
chown -R $utilisateur: /home/$utilisateur/Documents/
./Post_install-FSICS_PRO.sh
