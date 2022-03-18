#!/bin/bash

######## INSTALLATION ###########################################################

rouge='\e[1;31m'
neutre='\e[0;m'

utilisateur=$(grep 1000 /etc/passwd | awk -F ":" '{print $1}')
uidutilisateur=$(echo $UID)
cheminInstall="/home/$utilisateur/Documents/Linux-Post_Install/"

if [ "$uidutilisateur" = "0" ] ; then
    if [ ! -d "$cheminInstall" ] ; then
        mkdir "$cheminInstall"
        cp -r ./* "$cheminInstall"
        cd "$cheminInstall"
        chmod -R 750 /home/"$utilisateur"/Documents/
        chown -R "$utilisateur": /home/"$utilisateur"/Documents/
        ./Post_install-FSICS_PRO.sh
    else
        cd "$cheminInstall"
        chmod -R 750 /home/"$utilisateur"/Documents/
        chown -R "$utilisateur": /home/"$utilisateur"/Documents/
        ./Post_install-FSICS_PRO.sh
    fi
else
    echo -e "${rouge}Veuillez utiliser 'sudo' ou root !!${neutre}"
    read -p "Appuyer sur une touche pour continuer"
    exit
fi
