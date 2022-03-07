#!/bin/bash

######## INSTALLATION ###########################################################

utilisateur=$(grep 1000 /etc/passwd | awk -F ":" '{print $1}')
uidutilisateur=$(echo $UID)
if [ "$uidutilisateur" = "0" ] ; then
    if [ ! -d "/home/$utilisateur/Documents/Linux-Post_Install/" ] ; then
        mkdir /home/$utilisateur/Documents/Linux-Post_Install/
        cp -r * /home/$utilisateur/Documents/Linux-Post_Install/
        cd /home/$utilisateur/Documents/Linux-Post_Install/
        chmod -R 750 /home/$utilisateur/Documents/
        chown -R $utilisateur: /home/$utilisateur/Documents/
        ./Post_install-FSICS_PRO.sh
    else
        cd /home/$utilisateur/Documents/Linux-Post_Install/
        chmod -R 750 /home/$utilisateur/Documents/
        chown -R $utilisateur: /home/$utilisateur/Documents/
        ./Post_install-FSICS_PRO.sh
    fi
else
    echo -e "${jaune}Veuillez utiliser 'sudo' ou root !!${neutre}"
    read test1
    exit
fi
