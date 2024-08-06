#!/bin/bash

# https://github.com/yakisyst3m 

# 2022 01 22    v1.0
# 2022 02 03    v1.1
# 2022 02 17    v1.2
# 2022 03 06    v2.0 
# 2022 03 06    v2.1         Mise en place du menu + fonctions
# 2022 03 07    v2.1-1       Modif ShimCacheParser.py
# 2022 03 07    v2.1-2       Modif nommage volatility : vol2.py pour volatility 2.6 / vol3.py pour volatility 3
# 2022 03 09    v2.1-3       Correctif chemins + python3 + fcontion validchg
# 2022 03 10    v2.1-4       Modif install wireshark + extpackVbox + formatage du mode verbeux
# 2022 03 16    v2.1-5       Correction volatility 3 table des symbols windows + fonction décompte + modif fct IPv6
# 2022 03 18    v2.1-6       Suite sleuthkit
# 2022 03 18    v2.1-7       Python ImageMounter
# 2022 03 22    v2.1-8       Correction vol2.py + vol3.py + ShimCacheParser.py
# 2022 03 25    v2.1-8.1     Ajout outils log + amélioration code
# 2022 03 26    v2.1-8.2     Ajout de mft_dump
# 2022 03 28    v2.1-8.3     AJout csv2xlsx.py + ramParserVolatility3
# 2022 03 31    v2.1-8.4     Multiples corrections - ramParserVolatility3 + ajout backup dconf rep 'res' + modif lancement fonctions menu
# 2022 04 01    v2.1-8.5     Yara + Multiples corrections - ramParserVolatility3 de la version beta
# 2022 04 02    v2.2         Multiples corrections - ramParserVolatility3 v1.0 + modification de csv2xlsx
# 2022 04 05    v2.2-1.0     CyberChef
# 2022 04 06    v2.2-1.1     wine32 + wine64 + guestmount
# 2022 06 06    v2.2-1.3     wine64-tools + dos2unix + radare2
# 2022 10 08    v2.2-1.4     MAJ virtualbox + logiciel base
# 2022 10 08    v2.2-1.5     UPGRADE to virtualbox 7.0
# 2022 10 23    v2.2-1.6     Correction install.sh
# 2022 11 20    v2.2-1.7     Modif install CyberChef pour installation auto de la dernière version
# 2022 12 03    v2.2-1.8     Powershell add + UPX
# 2022 12 05    v2.2-1.9     Correctifs cheminInstall + fonctions
# 2022 12 06    v2.2-1.10    Menu correction
# 2022 12 06    v2.2-1.11    Yara moodif install
# 2024 06 18    v2.2-1.12    remplacement python3.9 par python3 / Ajout : adb fastboot docker dockerCompose
# 2024 06 19    v2.2-1.13    ajout jq  + config thunderbird et download add-on import export tool NG
# 2024 07 06    v2.3-0.0     Refonte type installateur, correctif VBOX + thunderbird
# 2024 07 05    v2.3-0.1     Interdiction lancement debian 12 pour le moment ; il manque beaucoup de librairies

versionIFT="v2.3-0.1 du 6 aout 2024"

##################################      INSTALLATION DES OUTILS FORENSICS POUR DEBIAN OU UBUNTU      ######################################"

# VARIABLES : CHEMINS / COULEURS
      
    utilisateur=$(grep 1000 /etc/passwd | awk -F ":" '{print $1}') # toto
    uidutilisateur=$(echo $UID) # 1000
    VERSION_OS=$(grep -E '^ID=' /etc/os-release | cut -d "=" -f2) # debian ...
    VERSION_DISTRI_DEBIAN=$(grep "VERSION_CODENAME" /etc/os-release | awk -F "=" '{print $2}') # bullseye / bookworm ...
    VERSION_KERNEL=$(uname -r)
    VERSION_INITRD=$(basename /boot/initrd.img-$(uname -r) | cut -d "-" -f2-4)
    ENVBUREAU="/etc/mate/"
    GESTCONNECTION="/etc/lightdm/"
    cheminInstall="/home/$utilisateur/Documents/IFT-install_forensics_tools/"
    cheminRelatifActuel=$(pwd)

    ETHNAME=$(ip a | grep "2: en" | tr " " ":" | awk -F ":" '{print $3}')
    ETHCHEMIN="/etc/sysconfig/network-scripts/ifcfg-$ETHNAME" # pour le futur : RedHat
    ETHUUID=$(nmcli con show | grep eth | awk -F " " '{print $2}')
    
    SYSCTL="/etc/sysctl.conf"
    rouge='\e[1;31m'
    vert='\e[1;32m'
    jaune='\e[1;33m'
    bleu='\e[1;34m' 
    violet='\e[1;35m'
    neutre='\e[0;m'
    bleufondjaune='\e[7;44m\e[1;33m'
    souligne="\e[4m"
    neutrePolice='\e[0m'


######## TEST COMPTE ROOT
testRootCpt() {
    # Vérifie si l'utilisateur actuel a l'UID 0 (root)
    if [ "$(id -u)" -ne 0 ]; then
        # Si l'utilisateur n'est pas root, afficher un message d'erreur et demander à utiliser 'sudo' ou root
        echo -e "${rouge}Veuillez utiliser 'sudo' ou root !!${neutre}"
        read -p "Appuyez sur une touche pour continuer"
        exit 1
    fi
    # Si l'utilisateur est root, la fonction continue son exécution (aucune action nécessaire ici)
}


######## ANNULATION LANCEMENT SI DEBIAN 12
testDebian12Annul() {
    if [ "$VERSION_OS" = 'debian' ] && [ "$VERSION_DISTRI_DEBIAN" = 'bookworm' ] ; then
        echo -e "\n${rouge}Le système d'exploitation ${VERSION_OS} ${VERSION_DISTRI_DEBIAN} n'est pas compatible, arrêt de l'installation ...${neutre}\n"
        read -p "Appuyez sur une touche pour continuer ..."
        exit 1                   
    else
        echo -e "\n${vert}Le système d'exploitation ${VERSION_OS} ${VERSION_DISTRI_DEBIAN} est compatible, poursuite de l'installation ...${neutre}\n"
        read -p "Appuyez sur une touche pour continuer ..."    
    fi
}


######## DECOMPTE 

decompte() {
    i=$1
    echo " "
    while [[ $i -ge 0 ]] ; do
            echo -e "${rouge}\r "$i secondes" \c ${neutre}"
            sleep 1
            i=$(("$i"-1))
    done
    echo -e "\n${vert} Fin du décompte ${neutre}"
}

######## MODIFICATION DES SOURCE.LIST 

function sourcelist() {
    # DEBIAN 11
    if [ "$VERSION_OS" = 'debian' ] && [ "$VERSION_DISTRI_DEBIAN" = 'bullseye' ] ; then
        echo -e "\n${bleu}[ ---- Mise à jour de source.list - DEBIAN 11 BULLSEYE DETECTED---- ]${neutre}\n"
        echo "deb http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN main non-freecontrib" > /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN main non-free contrib" >> /etc/apt/sources.list
        echo "deb http://security.debian.org/debian-security $VERSION_DISTRI_DEBIAN-security main contrib non-free" >> /etc/apt/sources.list
        echo "deb-src http://security.debian.org/debian-security $VERSION_DISTRI_DEBIAN-security main contrib non-free" >> /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN-updates main contrib non-free" >> /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN-updates main contrib non-free" >> /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian $VERSION_DISTRI_DEBIAN-backports main contrib non-free" >> /etc/apt/sources.list
        echo -e "${vert} [ OK ] Sources.list $VERSION_OS à jour ${neutre}"
        apt update && apt install -y apt-transport-https
        sed -i 's/http/https/g' /etc/apt/sources.list
        apt update && apt upgrade -y && echo -e "${vert} [ OK ] Système $VERSION_OS à jour ${neutre}"
        sleep 2
        decompte 3

    # DEBIAN 12
    elif [ "$VERSION_OS" = 'debian' ] && [ "$VERSION_DISTRI_DEBIAN" = 'bookworm' ] ; then
        echo -e "\n${bleu}[ ---- Mise à jour de source.list - DEBIAN 12 BOOKWORM DETECTED ---- ]${neutre}\n"
        echo "deb http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN main non-free-firmware contrib" > /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN main non-free-firmware contrib" >> /etc/apt/sources.list
        echo "deb http://security.debian.org/debian-security $VERSION_DISTRI_DEBIAN-security main contrib non-free-firmware" >> /etc/apt/sources.list
        echo "deb-src http://security.debian.org/debian-security $VERSION_DISTRI_DEBIAN-security main contrib non-free-firmware" >> /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN-updates main contrib non-free-firmware" >> /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian/ $VERSION_DISTRI_DEBIAN-updates main contrib non-free-firmware" >> /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian $VERSION_DISTRI_DEBIAN-backports main contrib non-free-firmware" >> /etc/apt/sources.list
        echo -e "${vert} [ OK ] Sources.list $VERSION_OS à jour ${neutre}"
        apt update && apt install -y apt-transport-https
        sed -i 's/http/https/g' /etc/apt/sources.list
        apt update && apt upgrade -y && echo -e "${vert} [ OK ] Système $VERSION_OS à jour ${neutre}"
        sleep 2
        decompte 3
                      
    # UBUNTU 
    elif [ "$VERSION_OS" = 'ubuntu' ] ; then
        echo -e "\n${bleu}[ ---- Mise à jour de source.list - UBUNTU DETECTED ---- ]${neutre}\n"
        echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"  > /etc/apt/sources.list
        echo "deb http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb-src http://fr.archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb-src http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse"  >> /etc/apt/soyakisyst3m/post_install_linux_install_forensics_toolsurces.list
        echo "deb-src http://fr.archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse"  >> /etc/apt/sources.list
        echo -e "${vert} [ OK ] Sources.list $VERSION_OS à jour ${neutre}"
        apt update && apt upgrade -y && echo -e "${vert} [ OK ] Système $VERSION_OS à jour ${neutre}"
        decompte 3
    else
        echo -e "${rouge}Le système d'exploitation n'est ni une distribution DEBIAN, ni une distribution UBUNTU : [ Fin de l'installation ]${neutre}"
        exit
    fi
}

######## MISE A JOUR DU SYSTEME D'EXPLOITATION

function mjour() {
    echo -e "\n${bleu}[ ---- Mise à jour du système d'exploitation---- ]${neutre}\n"
    apt update && apt upgrade -y && echo -e "${vert} [ OK ] Système $VERSION_OS à jour ${neutre}"
    decompte 3
}

######## INSTALL DES LOGICIELS DE BASE 

function installbase() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Installation des logiciels de base ---- ]${neutre}\n"
    logicielsDeBase="vim htop bmon gcc build-essential linux-headers-$(uname -r) make dkms nmap net-tools hping3 arping foremost libimage-exiftool-perl sonic-visualiser wxhexeditor hexedit gparted rsync tcpdump geany wget curl bash-completion tree numlockx minicom git whois nethogs testdisk tmux openssh-server openssl sqlite3 python3 python2.7 python3-pip python3-venv tshark openssl keepassx gufw rename parted p7zip wireshark dos2unix xattr git ssdeep jq"
    echo -e "${vert}$logicielsDeBase${neutre}\n"
    decompte 4
    apt update && apt install -y $logicielsDeBase && echo -e "${vert} [ OK ] Logiciels de Base installés ${neutre}"

    ## Corrections kernel Debian 11
    if [ "$VERSION_OS" = 'debian' ] && [ "$VERSION_DISTRI_DEBIAN" = 'bullseye' ] ; then
        echo -e "\n##############################################\n"
        echo -e "${bleu}[ Correction des erreurs au boot et à l'arrêt ]${neutre}"
        
        # Correction "A job is running UID 1000 (34s / 2mi 3s)"
        if [ "grep -q 'DefaultTimeoutStartSec=20s' /etc/systemd/system.conf" ] ; then
            echo -e "${vert} [ OK ] Correction des erreurs déjà effectué ${neutre}"
        else
            sed -i '/\[Manager]/a DefaultTimeoutStartSec=20s' /etc/systemd/system.conf 
            sed -i '/\[Manager]/a DefaultTimeoutStopSec=20s' /etc/systemd/system.conf && echo -e "${vert} [ OK ] Correction des erreurs au boot et à l'arrêt effectué ${neutre}"
        fi
        
        apt install -y libblockdev-mdraid2 libblockdev* apt-file 
        apt install -y firmware-linux firmware-linux-free firmware-linux-nonfree && echo -e "${vert} [ OK ] Le firmware-linux pour Debian est Installé ${neutre}"
        if [ "$VERSION_KERNEL" != "$VERSION_INITRD" ] ; then
            update-initramfs -u -k all && echo -e "${vert} [ OK ] Mise à jour de l'initrd effectué ${neutre}"
        else
            echo -e "${vert} [ OK ] Pas de mise à jour car --> L'initrd version : $VERSION_INITRD = kernel version : $VERSION_KERNEL ${neutre}"
            echo "Pas de correction car la distribution est différente de Debian 11"
        fi
        decompte 3
    fi

    cp res/gufw.service /etc/systemd/system/ && echo -e "${vert} [ OK ] Firewall Gufw service en place à l'emplacement : /etc/systemd/system/${neutre}"
    decompte 3

    if [ -d "$ENVBUREAU" ] ; then
        apt install -y caja-open-terminal mate-desktop-environment-extras && echo -e "${vert} [ OK ] Outils d'environnement de Bureau Mate installés${neutre}"
        decompte 3
    fi
}

######## CONFIGURATION DES APPLICATIONS

function config() {
    # Wireshark
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Configuration de wireshark ---- ]${neutre}\n"
    dpkg -l | awk -F " " '{print $2}' | grep -qEi "wireshark$"
    if [ "$?" = "0" ] ; then    
        usermod -aG wireshark "$utilisateur"
        chgrp wireshark /usr/bin/dumpcap
        chmod 750 /usr/bin/dumpcap
        setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap && echo -e "${vert} [ OK ] Wireshark configuré ${neutre}" || echo -e "${rouge} [ NOK ] Résoudre le problème ${neutre}"
        decompte 3
    fi

    # Désactivation IPv6
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Désactivation de l'IPv6 ---- ]${neutre}\n"

    #sed -ri  "s/^IPV6/#IPV6/g" "$ETHCHEMIN" && echo -e "${vert} [ OK ] Ligne IPV6 désactivées dans le fichier $ETHCHEMIN ${neutre}"

    grep -q 'net.ipv6.conf.all.disable_ipv6' "$SYSCTL"
    if [ "$?" = "0" ] ; then # si la ligne existe / -q pour mode silencieux, ne note rien à l'écran
        sed -ri 's/^(|#)net\.ipv6\.conf\.all\.disable_ipv6=(0|1|)/net\.ipv6\.conf\.all\.disable_ipv6=1/g' "$SYSCTL"  && echo -e "${vert} [ OK ] net.ipv6.conf.all.disable_ipv6=1 : paramétré ${neutre}"
    else 
        echo "net.ipv6.conf.all.disable_ipv6=1" >> "$SYSCTL" && echo -e "${vert} [ OK ] net.ipv6.conf.all.disable_ipv6=1 : paramétré ${neutre}"
    fi

    grep -q 'net.ipv6.conf.all.autoconf' "$SYSCTL"
    if [ "$?" = "0" ] ; then 
        sed -ri 's/^(|#)net\.ipv6\.conf\.all\.autoconf=(0|1|)/net\.ipv6\.conf\.all\.autoconf=0/g' "$SYSCTL"  && echo -e "${vert} [ OK ] net.ipv6.conf.all.autoconf=0 : paramétré ${neutre}"
    else
        echo "net.ipv6.conf.all.autoconf=0" >> "$SYSCTL"  && echo -e "${vert} [ OK ] net.ipv6.conf.all.autoconf=0 : paramétré ${neutre}"
    fi

    grep -q 'net.ipv6.conf.default.disable_ipv6' "$SYSCTL"
    if [ "$?" = "0" ] ; then
        sed -ri 's/^(|#)net\.ipv6\.conf\.default\.disable_ipv6=(0|1|)/net\.ipv6\.conf\.default\.disable_ipv6=1/g' "$SYSCTL"  && echo -e "${vert} [ OK ] net.ipv6.conf.default.disable_ipv6=1 : paramétré ${neutre}"
    else
        echo "net.ipv6.conf.default.disable_ipv6=1" >> "$SYSCTL"  && echo -e "${vert} [ OK ] net.ipv6.conf.default.disable_ipv6=1 : paramétré ${neutre}"
    fi

    grep -q 'net.ipv6.conf.default.autoconf' "$SYSCTL"
    if [ "$?" = "0" ] ; then
        sed -ri 's/^(|#)net\.ipv6\.conf\.default\.autoconf=(0|1|)/net\.ipv6\.conf\.default\.autoconf=0/g' "$SYSCTL"  && echo -e "${vert} [ OK ] net.ipv6.conf.default.autoconf=0 : paramétré ${neutre}"
    else
        echo "net.ipv6.conf.default.autoconf=0" >> "$SYSCTL"  && echo -e "${vert} [ OK ] net.ipv6.conf.default.autoconf=0 : paramétré ${neutre}"
    fi

    sysctl -p && echo -e "\n${bleufondjaune}IPv6 a été désactivé dans le fichier $SYSCTL ${neutre}\n"
    decompte 3

    # Pavé numérique
    if [ -d $GESTCONNECTION ] ; then # Debian Mate avec lightdm
        echo -e "\n##############################################\n"
        echo -e "\n${bleu}[ ---- Configuration du pavé numérique ---- ]${neutre}\n"
        sed -i '/\[Seat:\*\]/a greeter-setup-script=/usr/bin/numlockx on' /etc/lightdm/lightdm.conf
        echo "NUMLOCK=on" > /etc/default/numlockx
        grep -q "NUMLOCK=on" /etc/default/numlockx && echo -e "${vert} [ OK ] - Le pavé numérique a été activé en auto pour lightdm ${neutre}"
        decompte 3
    fi

    if [ "$VERSION_OS" = 'ubuntu' ] ; then # Ubuntu avec GDM3
        echo -e "\n##############################################\n"
        echo -e "\n${bleu}[ ---- Configuration du pavé numérique ---- ]${neutre}\n"
        sed -i '/exit 0/i \if [ -x /usr/bin/numlockx ]; then\nexec /usr/bin/numlockx on\nfi' /etc/gdm3/Init/Default && echo -e "${vert} [ OK ] - Le pavé numérique a été activé en auto pour gdm3 Ubuntu ${neutre}"
        decompte 3
    fi

    # Modif des droits TMUX
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Configuration de TMUX ---- ]${neutre}\n"
    if [[ -f "/home/$utilisateur/.tmux.conf" ]] && [[ -f "/root/.tmux.conf" ]] ; then
        cp ./res/tmux.conf /home/"$utilisateur"/.tmux.conf
        cp ./res/tmux.conf /root/.tmux.conf
        chown "$utilisateur": /home/"$utilisateur"/.tmux.conf && echo -e "${vert} [ OK ] TMUX a été Configuré ${neutre}"
        decompte 3
    fi

    # Conf vim
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Configuration de VIM ---- ]${neutre}\n"
    grep -qi "syntax on" /etc/vim/vimrc
    if [ "$?" != "0" ] ; then
        echo -e "syntax on\nset number\nset autoindent\nset tabstop=6\nset showmode\nset mouse=a" >> /etc/vim/vimrc && echo -e "${vert} [ OK ] VIM a été Configuré ${neutre}"
        decompte 3
    fi

    # Ajout Date + heure bash_history
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Configuration de bash_history en lui ajoutant la date et l'heure ---- ]${neutre}\n"
    
    grep -q 'HISTTIMEFORMAT' ~/.bashrc
    if [ "$?" != "0" ] ; then 
        echo 'export HISTTIMEFORMAT="[ %d/%m/%y-%T ] - "' >> ~/.bashrc && echo -e "${vert} [ OK ] Ajout de l'horodatage dans l'historique de commande de root ${neutre}"
        source ~/.bashrc    
    fi
    
    grep -q 'HISTTIMEFORMAT' /home/"$utilisateur"/.bashrc
    if [ "$?" != "0" ] ; then
        echo 'export HISTTIMEFORMAT="[ %d/%m/%y-%T ] - "' >> /home/"$utilisateur"/.bashrc && echo -e "${vert} [ OK ] Ajout de l'horodatage dans l'historique de commande de $utilisateur ${neutre}"
        source /home/"$utilisateur"/.bashrc
    fi
}

######## ARCHITECTURE DOSSIER   TRAVAIL FORENSIC

function creerrepertoires() {
    #    Cas d'anlyse Windows
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Création des dossiers qui contiendront les points de montages des disques, RAM, Artefacts Windows et Linux ---- ]${neutre}\n"
    if [[ ! -d "/cases" ]] ; then
        mkdir -p /cases/artefacts/{win_Artefacts_01,win_Artefacts_02,win_Artefacts_03,win_Artefacts_04}/{firefoxHistory,pst/PJ_outlook,prefetch,malware,mft,dump,evtx,timeline,hivelist,network,filecarving/{photorec,foremost}} && echo -e "${vert} [ OK ] accueil windows : /cases/artefacts/win_XXX Configuré ${neutre}"

        #    Cas d'analyse linux
        mkdir -p /cases/artefacts/{linux_Artefacts_01,linux_Artefacts_02,linux_Artefacts_03,linux_Artefacts_04}/{firefoxHistory,info_OS/{release,grub},cron,history/{cmd,viminfo},mail/{PJ_mail,},malware,dump,log,timeline,login_MDP,network/{ssh,},filecarving/{photorec,foremost}} && echo -e "${vert} [ OK ] accueil linux : /cases/artefacts/linux_XXX Configuré ${neutre}"

        #    Pour accueil des montages HDD ...
        mkdir -p /cases/montages/{usb1,usb2,usb3,usb4,win1,win2,linux1,linux2,encase1-E01,encase2-E01,encase3-E01,encase4-E01,ram1,ram2,raw1,raw2,raw3,raw4} && echo -e "${vert} [ OK ] accueil des point de montage des images : /cases/montages Configuré ${neutre}"    
        decompte 3
    fi
}

########  INSTALLER CLAMAV

function claminst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de clamav ---- ]${neutre}\n"
    dpkg -l | awk -F " " '{print $2}' | grep -qEi "clamav$"
    if [ "$?" != "0" ] ; then
        apt update && apt install -y clamav && echo -e "${vert} [ OK ] Clamav installé ${neutre}"
        systemctl stop clamav-freshclam.service && echo -e "${vert} [ OK ] Arrêt du service Clamav ${neutre}"
        freshclam && echo -e "${vert} [ OK ] Mise à jour du service Clamav ${neutre}"
        systemctl start clamav-freshclam.service && echo -e "${vert} [ OK ] Démarrage du service Clamav ${neutre}"
        sleep 3
    else
        echo "${vert} [ OK ] Clamav est déjà installé poursuite avec la mise à jour ${neutre}"
        sleep 2
        systemctl stop clamav-freshclam.service && echo -e "${vert} [ OK ] Arrêt du service Clamav ${neutre}"
        freshclam && echo -e "${vert} [ OK ] Mise à jour du service Clamav ${neutre}"
        systemctl start clamav-freshclam.service && echo -e "${vert} [ OK ] Démarrage du service Clamav ${neutre}"
    fi
}

########  COPIE DE VSENCODE DANS DOCUMENTS

function vsencodeinstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Copie du programme Windows vsencode dans Documents - désencoder fichier APEX ---- ]${neutre}\n"

}

######## INSTALL GDB-PEDA

function gdbinst() {
    # GDB-PEDA pour user
    echo -e "\n${bleu}[ ---- Début d'installation de gdb-peda ---- ]${neutre}\n"
    apt update && apt install -y gdb
    git clone https://github.com/longld/peda.git /home/"$utilisateur"/peda
    echo "source /home/$utilisateur/peda/peda.py" >> /home/"$utilisateur"/.gdbinit  && echo -e "${vert} [ OK ] gdp-peda paramétré pour $utilisateur ${neutre}"

    # Pour root
    cp -r /home/"$utilisateur"/peda /root/peda
    echo "source /root/peda/peda.py" >> /root/.gdbinit  && echo -e "${vert} [ OK ] gdp-peda paramétré pour root ${neutre}"
    decompte 3
}

######## INSTALL RADARE2

function radare2inst() {
    echo -e "\n${bleu}[ ---- Début d'installation de radare2 ---- ]${neutre}\n"
    if [[ ! -f "/usr/local/bin/radare2" ]] ; then
    git clone https://github.com/radareorg/radare2
    cd radare2/sys
    ./install.sh && echo -e "${vert} [ OK ] radare2 a été installé ${neutre}"
    cd ..
    decompte 3
    cd "$cheminRelatifActuel"
    else
        echo -e "${vert} [ OK ] radare2 est déjà installé ${neutre}"
    fi    
}


######################## INSTALLATION DE VOLATILITY 2.6 OU 3 #####################################"

########    INSTALLER VOLATILITY 2.6

function volat2() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de Volatility 2.6 ---- ]${neutre}\n"
    if [[ ! -f "/usr/local/bin/vol.py" ]] || [[ ! -f "/usr/local/bin/vol2.py" ]] ; then
        # Préparation avant installation
        cd /home/"$utilisateur"/Documents/
        echo "Début de l'installation et des mises à jour de Volatility 2.6 :"
        echo "Installation des librairies"
        apt update && apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata  && echo -e "${vert} [ OK ] Installation des librairies pour Volatility 2.6 installés ${neutre}"
        decompte 1
        
        # Installation de python 2
        echo "Installation des outils python 2"
        apt install -y python2 python2.7-dev libpython2-dev
        curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
        python2 get-pip.py
        python2 -m pip install -U setuptools wheel  && echo -e "${vert} [ OK ] Outils python2.7 pour Volatility 2.6 installés ${neutre}"
        decompte 1
        
        # Installation des modules volatility
        echo "Installation des dépendences"
        python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
        ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so  && echo -e "${vert} [ OK ] Modules de Volatility 2.6 installés ${neutre}"
        decompte 1
        
        # Téléchargement et Installation de volatility 2.6
        python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git  && echo -e "${vert} [ OK ] Téléchargement et Installation Volatility 2.6 effectué ${neutre}"
        decompte 1
        
        # Renommage de fichier
        mv /usr/local/bin/vol.py /usr/local/bin/vol2.py
        
        # Test
        vol2.py -h
        decompte 3
        cd "$cheminRelatifActuel"
    else
        echo -e "${vert} [ OK ] Volatility 2 est déjà installé ${neutre}"
        decompte 3    
    fi
}
        
########    INSTALLER VOLATILITY 3

function volat3() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de Volatility 3 ---- ]${neutre}\n"
    if [[ ! -f "/usr/local/bin/vol3.py" ]] ; then
    
        # Préparation avant installation
        cd /home/"$utilisateur"/
        echo "Début de l'installation et des mises à jour de Volatility 3:"
        echo "Installation des librairies"
        apt update && apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata  && echo -e "${vert} [ OK ] Modules afférent à Volatility 3 installés ${neutre}"
        decompte 1

        # Installation de python 3
        echo "Installation des outils python 3"
        apt install -y python3 python3-dev libpython3-dev python3-pip python3-setuptools python3-wheel git && echo -e "${vert} [ OK ] Outils python pour Volatility 3 installés ${neutre}"

        # Téléchargement de volatility 3
        git clone https://github.com/volatilityfoundation/volatility3.git
        mv volatility3 /home/"$utilisateur"/.volatility3
        
        # Téléchargement de la table des symbols windows
        cd /home/"$utilisateur"/.volatility3/volatility3/symbols/
        wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
        unzip windows.zip
        
        # Renommage 
        cd /home/"$utilisateur"/.volatility3
        mv vol.py vol3.py
        chmod -R 750 ../.volatility3/
        chown -R "$utilisateur": ../.volatility3/
        
        # Installation des modules volatility
        pip3 install -r requirements.txt
        
        # Lien pour lancer l'application
        ln -s /home/"$utilisateur"/.volatility3/vol3.py /usr/local/bin/vol3.py && echo -e "${vert} [ OK ] Volatility 3 a été installé ${neutre}"
        
        # TestMAJ
        vol3.py -h
        decompte 3
        cd "$cheminRelatifActuel"
    else
        echo -e "${vert} [ OK ] Volatility 3 est déjà installé ${neutre}"
    fi
}

########    OUTILS DE CONVERSIONS       https://gitlab.com/DerLinkshaender/csv2xlsx

convertinstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de csv2xlsx ---- ]${neutre}\n"
    if [[ ! -f "/usr/local/bin/csv2xlsx" ]] ; then
        cd "$cheminInstall"
        cp res/csv2xlsx_linux_amd64 /opt/csv2xlsx
        chmod +x /opt/csv2xlsx
        chown $utilisateur: /opt/csv2xlsx
        ln -s /opt/csv2xlsx /usr/local/bin && echo -e "${vert} [ OK ] csv2xlsx a été installé ${neutre}"
        csv2xlsx --help
        decompte 3
        cd "$cheminRelatifActuel"
    else
        echo -e "${vert} [ OK ] csv2xlsx est déjà installé ${neutre}"
        decompte 3
    fi
}

########    INSTALLER RAM PARSER de Yakisyst3m

ramParserinstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de ramParser ---- ]${neutre}\n"
    if [[ -f "/usr/local/bin/vol3.py" ]] && [[ -f "/usr/local/bin/csv2xlsx" ]] ; then
        if [[ ! -f "/usr/local/bin/ramParserVolatility3" ]] ; then
            cd "$cheminInstall"
            cp res/ramParserVolatility3.sh /opt
            chmod +x /opt/ramParserVolatility3.sh
            chown $utilisateur: /opt/ramParserVolatility3.sh
            ln -s /opt/ramParserVolatility3.sh /usr/local/bin/ramParserVolatility3 && echo -e "${vert} [ OK ] ramParserVolatility3 s'est correctement installé ${neutre}"
            decompte 3
            cd "$cheminRelatifActuel"
        else 
            echo -e "${vert} [ OK ] ramParserVolatility3 est déjà installé ${neutre}"
            decompte 3
        fi
    else
        echo -e "${rouge} [ NOK ] Volatility3 ou csv2xlsx : au moins une des 2 applications n'est pas installée ${neutre}"
        decompte 3
    fi    
}

########    INSTALLER DES OUTILS REGRIPPER V3

function reginst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de Regripper V3.0 ---- ]${neutre}\n"
    cd "$cheminInstall"
    if [[ ! -f "/usr/local/bin/rip.pl" ]] ; then
        apt update && apt install -y git libparse-win32registry-perl -y
        
        # Téléchargement de RegRipper3.0 et déplacement des fichiers dans /usr/local/src/regripper
        cd /usr/local/src/
        rm -r /usr/local/src/regripper/ 2>/dev/nul
        rm -r /usr/share/regripper/plugins 2>/dev/nul
        git clone https://github.com/keydet89/RegRipper3.0.git 
        mv RegRipper3.0 regripper
        mkdir /usr/share/regripper
        ln -s  /usr/local/src/regripper/plugins /usr/share/regripper/plugins 2>/dev/nul
        chmod 755 regripper/* || exit
        
        # Copier les modules perl spécifiques à RegRipper 
        cp regripper/File.pm /usr/share/perl5/Parse/Win32Registry/WinNT/File.pm
        cp regripper/Key.pm /usr/share/perl5/Parse/Win32Registry/WinNT/Key.pm
        cp regripper/Base.pm /usr/share/perl5/Parse/Win32Registry/Base.pm

        # Modifier le fichierrip.pl.linux depuis le fichier original original rip.pl
        cp regripper/rip.pl regripper/rip.pl.linux || exit
        sed -i '77i my \$plugindir \= \"\/usr\/share\/regripper\/plugins\/\"\;' /usr/local/src/regripper/rip.pl.linux 
        sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' /usr/local/src/regripper/rip.pl.linux
        sed -i "1i #!$(which perl)" /usr/local/src/regripper/rip.pl.linux
        sed -i '2i use lib qw(/usr/lib/perl5/);' /usr/local/src/regripper/rip.pl.linux
        md5sum /usr/local/src/regripper/rip.pl.linux && echo -e "${vert} rip.pl a été créé"

        # Copier rip.pl.linux dans /usr/local/bin/rip.pl
        cp regripper/rip.pl.linux /usr/local/bin/rip.pl && echo -e "${vert}Succès /usr/local/src/regripper/rip.pl.linux copié dans /usr/local/bin/rip.pl${neutre}"
        /usr/local/bin/rip.pl  && echo -e "${vert}\nrip.pl a été mis dans : /usr/local/bin/rip.pl !\n\nLe fichier d'origine se trouve dans : /usr/local/src/regripper/rip.pl\n\n${neutre}"
        decompte 3
        cd "$cheminRelatifActuel"
    else
        echo -e "${vert} [ OK ] Regripper est déjà installé ${neutre}"
        decompte 3
    fi
}

########    LES OUTILS DE BUREAUTIQUE

#### CONFIG THUNDERBIRD + DOWNLOAD import export Tool NG
# Fonction pour récupérer l'URL de téléchargement du dernier release depuis l'API GitHub
get_latest_release_url() {
    release_xpi_url=$(curl -s https://api.github.com/repos/thunderbird/import-export-tools-ng/releases/latest | grep browser_download_url | sed 's/"//g' | awk '{print $2}')
    
    if [ -z "$release_xpi_url" ]; then
        echo "Erreur : Impossible de trouver l'URL de téléchargement dans les données JSON."
        exit 1
    fi

    echo "$release_xpi_url"
}

# Fonction pour configurer Thunderbird et créer un profil nommé "Analyste" s'il n'existe pas
configure_thunderbird() {
    profile_name="Analyste"
    profile_path="/home/$utilisateur/.thunderbird"
    
    if [ ! -d "$profile_path" ]; then
        mkdir -p "$profile_path"
        chmod -R 700 "$profile_path"
        chown -R "$utilisateur": "$profile_path"
    else
        chmod -R 700 "$profile_path"
        chown -R "$utilisateur": "$profile_path"    
    fi

    profile_ini="$profile_path/profiles.ini"
    profile_dir="$profile_path/$(xvfb-run thunderbird -CreateProfile "$profile_name" | grep Path | awk '{print $2}')"

    if [ ! -d "$profile_dir" ]; then
        echo "Création du profil Thunderbird '$profile_name'..."
        xvfb-run thunderbird -CreateProfile "$profile_name $profile_dir"
        
        if [ $? -ne 0 ]; then
            echo "Erreur : Impossible de créer le profil Thunderbird."
            exit 1
        fi
    else
        echo "Le profil Thunderbird '$profile_name' existe déjà."
    fi

    # Configuration initiale pour éviter l'ouverture de l'onglet "Account Setup"
    prefs_js="$profile_dir/prefs.js"
    {
        echo 'user_pref("mail.account.account1.server", "server1");'
        echo 'user_pref("mail.accountmanager.accounts", "account1");'
        echo 'user_pref("mail.accountmanager.defaultaccount", "account1");'
        echo 'user_pref("mail.accountmanager.localfoldersserver", "server1");'
        echo 'user_pref("mail.identity.id1.fullName", "Analyste");'
        echo 'user_pref("mail.identity.id1.useremail", "analyste@localhost");'
        echo 'user_pref("mail.identity.id1.composeHtml", false);'
        echo 'user_pref("mail.server.server1.directory-rel", "[ProfD]Mail/Local Folders");'
        echo 'user_pref("mail.server.server1.hostname", "Local Folders");'
        echo 'user_pref("mail.server.server1.name", "Local Folders");'
        echo 'user_pref("mail.server.server1.type", "none");'
        echo 'user_pref("mail.server.server1.userName", "nobody");'
        echo 'user_pref("mail.smtp.defaultserver", "smtp1");'
        echo 'user_pref("mail.smtpserver.smtp1.hostname", "localhost");'
        echo 'user_pref("mail.smtpserver.smtp1.username", "nobody");'
        echo 'user_pref("mail.smtpserver.smtp1.description", "Default");'
        echo 'user_pref("mail.smtpservers", "smtp1");'
        echo 'user_pref("mail.startup.enabledMailCheckOnce", true);'
        echo 'user_pref("mail.ui-rdf.version", 17);'
        echo 'user_pref("mailnews.start_page_override.mstone", "ignore");'
    } >> "$prefs_js"
}

# Fonction pour télécharger l'add-on dans le dossier de téléchargements
download_addon() {
    release_xpi_url=$(get_latest_release_url)
    download_dir="/home/$utilisateur/Téléchargements"
    tmp_file="$download_dir/$(basename "$release_xpi_url")"

    echo "Téléchargement de l'add-on Thunderbird ImportExportTools NG depuis GitHub..."
    wget -q --show-progress "$release_xpi_url" -O "$tmp_file"

    if [ $? -ne 0 ]; then
        echo "Erreur : Téléchargement de l'add-on a échoué. Vérifiez l'URL ou votre connexion internet."
        rm "$tmp_file"
        exit 1
    fi

    echo "L'add-on Thunderbird ImportExportTools NG a été téléchargé avec succès dans $download_dir."
}

function burinst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation des outils de bureautique ---- ]${neutre}\n"
    apt update && apt install -y libemail-outlook-message-perl pst-utils thunderbird xvfb && echo -e "${vert} [ OK ] Outils Bureautique installés ${neutre}"

    # Appel des fonctions thunderbird
    configure_thunderbird
    download_addon

    decompte 3
}


########    LES OUTILS DE DISQUES

function diskinst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation des outils de disque ---- ]${neutre}\n"
    apt update && apt install -y guymager qemu-utils libewf-dev ewf-tools hdparm sdparm && echo -e "${vert} [ OK ] Outils de disques installés ${neutre}"
    decompte 3
}

########    QUELQUES LOGICIELS FORENSIC 

function mftinst() {
    echo -e "\n##############################################\n"
    
    # oletools et analyzeMFT
    echo -e "\n${bleu}[ ---- Début d'installation de oletools analyzeMFT ---- ]${neutre}\n"
    if ! pip show oletools &>/dev/null || ! pip show analyzeMFT &>/dev/null; then
        pip install oletools analyzeMFT && echo -e "${vert} [ OK ] oletools analyzeMFT installés ${neutre}"
    else
        echo -e "${vert} [ OK ] oletools analyzeMFT déjà installés ${neutre}"
    fi
    decompte 1

    # pff-tools, ewf-tools, libewf-dev, libewf2, attr
    echo -e "\n${bleu}[ ---- Début d'installation de pff-tools ewf-tools libewf-dev libewf2 attr ---- ]${neutre}\n"
    if ! dpkg -l | grep -qE "pff-tools|ewf-tools|libewf-dev|libewf2|attr"; then
        apt update && apt install -y pff-tools ewf-tools libewf-dev libewf2 attr && echo -e "${vert} [ OK ] pff-tools ewf-tools libewf-dev libewf2 attr installés ${neutre}"
    else
        echo -e "${vert} [ OK ] pff-tools ewf-tools libewf-dev libewf2 attr déjà installés ${neutre}"
    fi
    decompte 1

    # Suite plaso
    echo -e "\n${bleu}[ ---- Début d'installation de la suite plaso ---- ]${neutre}\n"
    if ! dpkg -l | grep -q plaso; then
        apt install -y plaso && echo -e "${vert} [ OK ] Suite plaso installée ${neutre}"
    else
        echo -e "${vert} [ OK ] Suite plaso déjà installée ${neutre}"
    fi
    decompte 1

    # windowsprefetch
    echo -e "\n${bleu}[ ---- Début d'installation de windowsprefetch ---- ]${neutre}\n"
    if ! pip3 show windowsprefetch &>/dev/null; then
        pip3 install windowsprefetch && echo -e "${vert} [ OK ] windowsprefetch installés ${neutre}"
    else
        echo -e "${vert} [ OK ] windowsprefetch déjà installés ${neutre}"
    fi
    decompte 1

    # ShimCacheParser.py
    echo -e "\n${bleu}[ ---- Début d'installation de ShimCacheParser.py ---- ]${neutre}\n"
    if [ ! -d "/home/$utilisateur/.shimcacheparser/" ]; then
        cd "$cheminInstall"
        apt install -y python2*
        unzip ./res/ShimCacheParser-master.zip 
        mv ShimCacheParser-master /home/"$utilisateur"/.shimcacheparser/
        chmod -R 750 /home/"$utilisateur"/.shimcacheparser/ && echo -e "${vert} [ OK ] ShimCacheParser copié dans : /home/$utilisateur/.shimcacheparser/  ${neutre}"
        chown -R "$utilisateur": /home/"$utilisateur"/.shimcacheparser/
        ln -s /home/"$utilisateur"/.shimcacheparser/ShimCacheParser.py /usr/local/bin/ShimCacheParser.py
        decompte 3
        cd "$cheminRelatifActuel"
    else
        echo -e "${vert} [ OK ] ShimCacheParser déjà installé ${neutre}"
    fi
}


########    INSTALLER LA SUITE SLEUTHKIT
    # fls / mmls / icat / mactime  
function sleuthkitInstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de la suite sleuthkit ---- ]${neutre}\n"

    tools=("fls" "mmls" "icat" "mactime")
    missing_tools=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" ; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -eq 0 ]; then
        echo -e "${vert} [ OK ] Suite Sleuthkit déjà installée ${neutre}"
        decompte 3
    else
        echo -e "${bleu}Installation de la suite Sleuthkit en cours...${neutre}"
        cd res/ || { echo "Erreur: Impossible de changer de répertoire vers $cheminInstall"; exit 1; }
        unzip sleuthkit-debian-master.zip || { echo "Erreur: Impossible de décompresser sleuthkit-debian-master.zip"; exit 1; }
        cd sleuthkit-debian-master/ || { echo "Erreur: Impossible de changer de répertoire vers sleuthkit-debian-master"; exit 1; }
        ./configure || { echo "Erreur: Échec de la configuration"; exit 1; }
        make || { echo "Erreur: Échec de la compilation"; exit 1; }
        make install && echo -e "${vert} [ OK ] Suite Sleuthkit installée ${neutre}" || { echo "Erreur: Échec de l'installation"; exit 1; }
        decompte 3
        cd "$cheminRelatifActuel" || { echo "Erreur: Impossible de changer de répertoire vers $cheminRelatifActuel"; exit 1; }
    fi
}


########    INSTALLER MFT DUMP      https://github.com/omerbenamram/mft

function mftdumpinst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de mft_dump ---- ]${neutre}\n"
    if [[ ! -f "/usr/local/bin/mft_dump" ]] ; then
        wget --progress=bar https://github.com/omerbenamram/mft/releases/download/v0.6.0/mft_dump-v0.6.0-x86_64-unknown-linux-gnu -O $cheminInstall/res/mft_dump
        cp res/mft_dump /opt
        chmod +x /opt/mft_dump
        ln -s /opt/mft_dump /usr/local/bin/mft_dump
        mft_dump -h && echo -e "${vert} [ OK ] mft_dump installé ${neutre}"
        decompte 3
        cd "$cheminRelatifActuel"
    else
        echo -e "${vert} [ OK ] MFT Dump est déjà installé ${neutre}"
        decompte 3    
    fi
}

########    INSTALLER LES OUTILS DE LOGS

function loginstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation des outils de log ---- ]${neutre}\n"

    # Vérifier et installer auditd
    if ! command -v auditd &>/dev/null; then
        mjour
        apt install -y auditd
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de l'installation de auditd."
            exit 1
        fi
    else
        echo -e "${vert} [ OK ] auditd est déjà installé ${neutre}"
    fi

    # Vérifier et installer evtx2log
    if ! command -v evtx2log.sh &>/dev/null; then
        apt install -y rename libevtx-utils
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de l'installation des dépendances pour evtx2log."
            exit 1
        fi

        # Cloner evtx2log depuis GitHub
        git clone https://github.com/yakisyst3m/evtx2log.git
        mv evtx2log/ res/
        cp res/evtx2log/evtx2log.sh /opt/
        chmod 755 /opt/evtx2log.sh
        ln -s /opt/evtx2log.sh /usr/local/bin/
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de la configuration de evtx2log."
            exit 1
        fi

        # Tester l'exécution de evtx2log.sh
        evtx2log.sh
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de l'exécution de evtx2log.sh."
            exit 1
        fi

        echo -e "${vert} [ OK ] evtx2log installé ${neutre}"
    else
        echo -e "${vert} [ OK ] evtx2log est déjà installé ${neutre}"
    fi

    decompte 3
    cd "$cheminRelatifActuel"
}



########    INSTALLER L'APPLICATION PYTHON IMAGEMOUNTER - MOTAGE AUTO E01

function imagemounterE01() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de l'application Python ImageMounter pour Image E01 Encase ---- ]${neutre}\n"

    # Vérification et installation des dépendances obligatoires
    echo -e "\n${bleu}[ ---- Installation des dépendances obligatoires ---- ]${neutre}\n"
    apt update
    apt install -y python3-pip python-setuptools xmount ewf-tools afflib-tools disktype qemu-utils avfs xfsprogs lvm2 vmfs-tools mtd-tools squashfs-tools mdadm cryptsetup libbde-utils libvshadow-utils

    # Vérifier si FLS (de sleuthkit) est déjà installé
    if ! command -v fls &>/dev/null; then
        echo -e "\n${bleu}[ ---- Installation de FLS de sleuthkit ---- ]${neutre}\n"
        apt install -y sleuthkit
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de l'installation de sleuthkit."
            exit 1
        fi
    else
        echo -e "${vert} [ OK ] FLS de sleuthkit est déjà installé ${neutre}"
    fi

    # Installation d'ImageMounter
    echo -e "\n${bleu}[ ---- Installation de ImageMounter ---- ]${neutre}\n"
    pip3 install pytsk3 python-magic imagemounter
    if [[ $? -ne 0 ]]; then
        echo "Erreur: Échec de l'installation de ImageMounter."
        exit 1
    fi

    # Vérification des dépendances
    echo -e "\n${bleu}[ ---- Vérification des dépendances ---- ]${neutre}\n"
    imount --check
    echo -e "\n\t${rouge}Vérifier que les dépendances obligatoires sont installées + Appuyer sur une touche pour continuer ...${neutre}"
    echo -e "\n\t${bleu}Pour info : XFS, JFFS et SQUASHFS sont quand même installés mais n'apparaissent pas dans les commandes mount ...${neutre}"

    decompte 3
    cd "$cheminRelatifActuel"
}


########    INSTALLER L'APPLICATION GUESTMOUNT - MONTAGE VMDK VDI

function mountvmdkinstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de guestmount ---- ]${neutre}\n"
        if [ ! -f "/usr/bin/guestmount" ] ; then
            apt-get update && sudo apt install libguestfs-tools -y && echo -e "${vert} [ OK ] guestmount a été installé ${neutre}"
            decompte 3 
        else
            echo -e "${vert} [ OK ] guestmount est déjà installé ${neutre}"
            decompte 3            
        fi
}

########    FORENSICS-ALL

function forall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de FORENSICS-ALL ---- ]${neutre}\n"
    
    # Vérifier si forensics-all est déjà installé
    if ! dpkg -s forensics-all &>/dev/null; then
        echo -e "\n${bleu}[ ---- Installation de forensics-all ---- ]${neutre}\n"
        apt update
        apt install -y forensics-all
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de l'installation de forensics-all."
            exit 1
        fi
    else
        echo -e "${vert} [ OK ] forensics-all est déjà installé ${neutre}"
    fi

    decompte 3
}


########    FORENSICS-EXTRA

function forextra() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de FORENSICS-EXTRA ---- ]${neutre}\n"
    
    # Vérifier si forensics-extra est déjà installé
    if ! dpkg -s forensics-extra &>/dev/null; then
        echo -e "\n${bleu}[ ---- Installation de forensics-extra ---- ]${neutre}\n"
        apt update
        apt install -y forensics-extra
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de l'installation de forensics-extra."
            exit 1
        fi
    else
        echo -e "${vert} [ OK ] forensics-extra est déjà installé ${neutre}"
    fi

    decompte 3
}


########    FORENSICS-EXTRA-GUI

function forextragui() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de FORENSICS-EXTRA-GUI ---- ]${neutre}\n"
    
    # Vérifier si forensics-extra-gui est déjà installé
    if ! dpkg -s forensics-extra-gui &>/dev/null; then
        echo -e "\n${bleu}[ ---- Installation de forensics-extra-gui ---- ]${neutre}\n"
        apt update
        apt install -y forensics-extra-gui
        if [[ $? -ne 0 ]]; then
            echo "Erreur: Échec de l'installation de forensics-extra-gui."
            exit 1
        fi
    else
        echo -e "${vert} [ OK ] forensics-extra-gui est déjà installé ${neutre}"
    fi

    decompte 3
}


########    INSTALLATION DE VIRTUALBOX 7.0

function vbox() {
    echo -e "\n##############################################\n"

    # Vérification que l'on est sur une machine physique
    os=$(dmidecode | grep -Ei '(version.*virt)' | awk -F " " '{print $2}')

    if [ "$os" != "VirtualBox" ]; then
        # Vérification de la version installée de VirtualBox 7
        vbox7Installed=$(dpkg -l | grep -i virtualbox-7. | wc -l)

        if [ "$vbox7Installed" -gt 0 ]; then
            echo -e "${vert} [ OK ] VirtualBox 7 est déjà installé ${neutre}"
            decompte 3
            return
        fi

        # Vérification de la version installée de VirtualBox 6
        vbox6Installed=$(dpkg -l | grep -i virtualbox-6. | wc -l)

        if [ "$vbox6Installed" -gt 0 ]; then
            echo -e "${jaune}[ Désinstallation de VirtualBox 6 ]${neutre}"
            apt remove --purge -y virtualbox-6.*
            apt autoremove -y
        fi

        # Modification de la source.list et mise à jour
        echo -e "${jaune}[ Modification des sources.list ]${neutre}"
        if [ "$VERSION_OS" = 'ubuntu' ]; then
            add-apt-repository "deb [arch=amd64 signed-by=/usr/share/keyrings/oracle-virtualbox-2016.gpg] https://download.virtualbox.org/virtualbox/debian jammy contrib"
        elif [ "$VERSION_OS" = 'debian' ]; then
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/oracle-virtualbox-2016.gpg] https://download.virtualbox.org/virtualbox/debian $VERSION_DISTRI_DEBIAN contrib" >> /etc/apt/sources.list
        fi

        # Téléchargement des clés publiques
        echo -e "\n${bleu}[ ---- Début d'installation et de configuration Virtualbox ---- ]${neutre}\n"
        echo -e "${jaune}[ Téléchargement et ajout des clés publiques de VirtualBox ]${neutre}"
        wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo gpg --dearmor --yes --output /usr/share/keyrings/oracle-virtualbox-2016.gpg

        # Mise à jour des paquets après modification des sources.list
        mjour

        # Installation de VirtualBox 7
        echo -e "${jaune}[ Installation de VirtualBox 7 ]${neutre}"
        apt install -y virtualbox-7.0 && echo -e "${vert} [ OK ] VirtualBox 7 installé ${neutre}"
        
        # Détection de la version installée de VirtualBox 7
        vboxVersion=$(dpkg -l | grep -i virtualbox-7 | awk -F " " '{print $3}' | grep -oE '([0-9]{1}\.){2}[0-9]{1,3}' | sort | tail -1)

        # Désinstallation de l'extension Pack existant
        echo -e "${jaune}[ Désinstallation de l'ancien Extension Pack ]${neutre}"
        VBoxManage extpack uninstall "Oracle VM VirtualBox Extension Pack"

        # Téléchargement de l'Extension Pack
        echo -e "${jaune}[ Installation de l'extension Pack ]${neutre}"
        wget https://download.virtualbox.org/virtualbox/"$vboxVersion"/Oracle_VM_VirtualBox_Extension_Pack-"$vboxVersion".vbox-extpack

        # Installation de l'Extension Pack avec acceptation de la licence automatique
        echo ${ACCEPT_ORACLE_EXTPACK_LICENSE:='y'} | VBoxManage extpack install "Oracle_VM_VirtualBox_Extension_Pack-$vboxVersion.vbox-extpack" && echo -e "${vert} [ OK ] Extension Pack de VirtualBox $vboxVersion installée ${neutre}"

        # Configuration pour permettre l'utilisation des clés USB
        echo -e "${jaune}[ Configuration de VirtualBox pour utiliser les clés USB ]${neutre}"
        usermod -aG vboxusers "$utilisateur" && echo -e "${vert} [ OK ] Utilisation de l'USB configurée ${neutre}"

        # Configuration pour permettre le démarrage sur clé USB
        usermod -aG disk "$utilisateur" && echo -e "${vert} [ OK ] Configuration pour démarrage sur clé USB configurée ${neutre}"

        echo -e "${vert}[ ---- Fin d'installation et de configuration VirtualBox ---- ]${neutre}"
        decompte 3
    else
        echo -e "${rouge}Vous êtes sur une machine virtuelle, pas d'installation${neutre}"
        decompte 3
    fi
}




########    WINE 32 + 64

function wineinstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de CyberChef ---- ]${neutre}\n"
        if [ ! -f "/usr/bin/wine64" ] ; then
            dpkg --add-architecture i386
            apt-get update && sudo apt install wine32 wine64 wine64-tools -y && echo -e "${vert} [ OK ] Wine a été installé ${neutre}"
            wine --version
            decompte 3 
        else
            echo -e "${vert} [ OK ] Wine est déjà installé ${neutre}"
            decompte 3            
        fi
}


########    CYBERCHEF

function cyberchefinstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de CyberChef ---- ]${neutre}\n"
    if [ ! -d "/opt/cyberchef/" ] ; then
        cd res/
        LOCATION=$(curl -s  https://api.github.com/repos/gchq/CyberChef/releases/latest | grep "browser_download_url" | awk '{ print $2 }' | sed 's/,$//' | sed 's/"//g') ; wget "$LOCATION"
        unzip CyberChef*.zip -d cyberchef
        cp -r cyberchef/ /opt/
        chmod -R 750 /opt/cyberchef
        chown -R $utilisateur: /opt/cyberchef
        ln -s /opt/cyberchef/CyberChef*.html /home/"$utilisateur"/Bureau/
        mv /home/"$utilisateur"/Bureau/CyberChef*.html /home/"$utilisateur"/Bureau/CyberChef && echo -e "${vert} [ OK ] CyberChef a été installé ${neutre}"
        decompte 3
        cd "$cheminRelatifActuel"
    elif [ -d "/opt/cyberchef/" ] ; then
        echo -e "${vert} [ OK ] CyberChef est déjà installé, suppression de l'ancienne version avant réinstallation ${neutre}"
        rm -rf /opt/cyberchef
        LOCATION=$(curl -s  https://api.github.com/repos/gchq/CyberChef/releases/latest | grep "browser_download_url" | awk '{ print $2 }' | sed 's/,$//' | sed 's/"//g') ; wget "$LOCATION"
        unzip CyberChef*.zip -d cyberchef
        cp -r cyberchef/ /opt/
        chmod -R 750 /opt/cyberchef
        chown -R $utilisateur: /opt/cyberchef
        ln -s /opt/cyberchef/CyberChef*.html /home/"$utilisateur"/Bureau/
        mv /home/"$utilisateur"/Bureau/CyberChef*.html /home/"$utilisateur"/Bureau/CyberChef && echo -e "${vert} [ OK ] CyberChef a été mis à jour avec la dernière version ${neutre}"        
        decompte 3
        cd "$cheminRelatifActuel"
    fi
}

########    YARA

function yarainstall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de YARA ---- ]${neutre}\n"
    dpkgyara=$(dpkg -l | awk -F " " '{print $2}' | grep -E "^yara$")
    dpkgyaraDoc=$(dpkg -l | awk -F " " '{print $2}' | grep -E "^yara-doc$")
    dpkgyaraLib=$(dpkg -l | awk -F " " '{print $2}' | grep -oE "^libyara-dev")
    dpkgyaraLib4=$(dpkg -l | awk -F " " '{print $2}' | grep -oE "^libyara4")
    dpkgyaraLib9=$( dpkg -l | awk -F " " '{print $2}' | grep -oE "^libyara9")
    
    if [ "$dpkgyara" != "yara" ] ; then
        apt update && apt install -y libyara-dev libyara8 yara yara-doc
        yara -h && echo -e "${vert} [ OK ] yara pour la recherche de pattern est installé ${neutre}"
    else
        echo -e "${vert} [ OK ] yara est déjà installé : version yara $versionYara ${neutre}"
        decompte 2
    fi
    if [ "$dpkgyaraDoc" != "yara-doc" ] ; then
        apt update && apt install -y yara-doc
    else
        echo -e "${vert} [ OK ] yara-doc est déjà installé${neutre}"
        decompte 2    
    fi
    if [ "$dpkgyaraLib" != "libyara-dev" ] ; then
        apt update && apt install -y libyara-dev
    else
        echo -e "${vert} [ OK ] libyara-dev est déjà installé${neutre}"
        decompte 2    
    fi
    if [ "$dpkgyaraLib4" != "libyara4" ] ; then
        apt update && apt install -y libyara4
    else
        echo -e "${vert} [ OK ] libyara4 est déjà installé${neutre}"
        decompte 2    
    fi
    if [ "$dpkgyaraLib9" != "libyara9" ] ; then
        apt update && apt install -y libyara9
    else
        echo -e "${vert} [ OK ] libyara8 est déjà installé${neutre}"
        decompte 2    
    fi

    yarac -h && echo -e "${vert} [ OK ] yarac pour la compilation est installé ${neutre}"
    versionYara=$(yara -v) && echo -e "${vert} [ OK ] Version de yara installée : yara $versionYara ${neutre}"
    decompte 3
}

########    SCRIPTING

function powershellinstall() {
      echo -e "\n##############################################\n"
      echo -e "\n${bleu}[ ---- Début d'installation de powershell ---- ]${neutre}\n"
      if [ ! -f "/usr/bin/pwsh" ] ; then
            apt update  && apt install -y curl gnupg apt-transport-https
            curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
            sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list'
            apt update && apt install -y powershell && echo -e "${vert} [ OK ] Powershell a été installé${neutre}"
            decompte 3 
      else
            echo -e "${vert} [ OK ] Powershell est déjà installé${neutre}"
            decompte 3      
      fi
}

function upxinstall() {
      echo -e "\n##############################################\n"
      echo -e "\n${bleu}[ ---- Début d'installation du Packer/Depacker UPX ---- ]${neutre}\n"
      if [ ! -f "/usr/bin/upx" ] ; then
            apt update  && apt install -y upx-ucl && echo -e "${vert} [ OK ] UPX a été installé${neutre}"
            decompte 3 
      else
            echo -e "${vert} [ OK ] UPX est déjà installé${neutre}"
            decompte 3      
      fi
}


########    INSTALLER les outils ANDROID

function androidForensics() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de adb + fastboot ---- ]${neutre}\n"
        if [ ! -f "/usr/bin/adb" ] ; then
            apt-get update && sudo apt install adb -y && echo -e "${vert} [ OK ] adb  a été installé ${neutre}"
            decompte 3 
        else
            echo -e "${vert} [ OK ] adb est déjà installé${neutre}"
            decompte 3            
        fi
        
        if [ ! -f "/usr/bin/fastboot" ] ; then
            apt-get update && sudo apt install fastboot -y && echo -e "${vert} [ OK ] fastboot a été installé ${neutre}"
            decompte 3 
        else
            echo -e "${vert} [ OK ] fastboot est déjà installé${neutre}"
            decompte 3            
        fi

}

########    INSTALLER les outils DOCKER

function dockerTools() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de Docker + Docker Compose ---- ]${neutre}\n"

    # Vérification de Docker
    if which docker &>/dev/null && which docker-compose &>/dev/null; then
        echo -e "${vert} [ OK ] Docker et Docker Compose sont déjà installés ${neutre}"
        decompte 3
        return
    fi

    # DEBIAN
    if [ "$VERSION_OS" = 'debian' ] ; then
        echo -e "\n${bleu}[ ---- Début d'installation de DOCKER ---- ]${neutre}\n"
        apt remove docker docker-engine docker.io containerd runc       # Désinstalle les anciennes dépendances
        apt update && apt install -y ca-certificates curl gnupg lsb-release p7zip-full unzip              # Ajout des dépendances à Docker
        curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg  # Installation des clés
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt update && apt install -y docker-ce docker-ce-cli containerd.io            # Installation de Docker

        sleep 2
        decompte 3
                      
    # UBUNTU 
    elif [ "$VERSION_OS" = 'ubuntu' ] ; then
        apt remove docker docker-engine docker.io containerd runc       # Désinstalle les anciennes dépendances
        apt install -y ca-certificates curl gnupg lsb-release p7zip-full unzip               # Ajout des dépendances à Docker
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg  # Installation des clés
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt update && apt install -y docker-ce docker-ce-cli containerd.io

        sleep 2
        decompte 3

    else
        echo -e "${rouge}Le système d'exploitation n'est ni une distribution Debian, ni une distribution Ubuntu : [ Fin de l'installation ]${neutre}"
        exit 1
    fi

    # Installation de Docker Compose
    echo -e "\n${bleu}[ ---- Début d'installation de DOCKER COMPOSE---- ]${neutre}\n"
    curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose

    # Vérification après installation
    if which docker &>/dev/null && which docker-compose &>/dev/null; then
        echo -e "${vert} [ OK ] Docker et Docker Compose installés avec succès ${neutre}"
    else
        echo -e "${rouge} [ ERREUR ] Docker ou Docker Compose n'a pas été installé correctement ${neutre}"
    fi

    decompte 3
}


######## VALIDATION DES CHANGEMENTS ###########################################################

function validChang() {
    echo -e "\n${rouge}Voulez-vous redemérrer maintenant pour valider tous les changements ? ( y / n )${neutre}"
    read REBOOT

    if [ "$REBOOT" = "y" ] ; then
        reboot
    else
        echo -e "${violet}Il faudra redémarrer avant d'utiliser les applications${neutre}"
        echo -e "${violet}Retour au menu dans 4 secondes...${neutre}"
        decompte 4
    fi
}

######## MENU ###########################################################

# Test compte root
testRootCpt
# Test version OS
testDebian12Annul


# Menu
while true ; do 
echo -e "${bleu}           ________     ${neutre} ______     ${rouge}_________ ${neutre}"
echo -e "${bleu}          /_______/\    ${neutre}/_____/\   ${rouge}/________/\ ${neutre}"
echo -e "${bleu}          \__.::._\/    ${neutre}\::::_\/_  ${rouge}\__.::.__\/ ${neutre}"
echo -e "${bleu}             \::\ \      ${neutre}\:\/___/\    ${rouge}\::\ \   ${neutre}"
echo -e "${bleu}             _\::\ \__    ${neutre}\:::._\/     ${rouge}\::\ \  ${neutre}"
echo -e "${bleu}            /__\::\__/\    ${neutre}\:\ \        ${rouge}\::\ \ ${neutre}"
echo -e "${bleu}            \________\/     ${neutre}\_\/         ${rouge}\__\/  ${neutre}"               
echo " "
echo -e "\e[2C${bleu}---${neutre}----${rouge}----   [ ${bleu}INSTALL ${neutre}FORENSICS ${rouge}TOOLS${bleu} ]    ---${neutre}----${rouge}----${neutre}\t$versionIFT"
echo " "
    #echo -e "${bleu}Faites votre choix d'installation :${neutre}"
    #echo -e "${vert}-----------------------------------${neutre}"
    echo -e "\e[3C${bleu}[ --    ${souligne}INSTALLATION DE BASE${neutrePolice}${bleu}     -- ]${neutre}"    
    echo -e "\t[   ${vert}0${neutre} ] - Modification du fichier source.list HTTP vers HTTPS + Mise à jour des paquets"    
    echo -e "\t[   ${vert}1${neutre} ] - Mise à jour des paquets"
    echo -e "\t[   ${vert}2${neutre} ] - Installation des logiciels de base + configuration des applications : Wireshark / déscativation IPv6 / Activation du pavé numérique / Tmux / Vim / Date-Heure bash_history ${rouge}(Obligatoire)${neutre}"
    echo -e "\t[   ${vert}3${neutre} ] - Création de l'architecture des dossiers : pour montage des disques windows et linux à analyser"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}ANTI-VIRUS${neutrePolice}${bleu}     -- ]${neutre}"    
    echo -e "\t[  ${vert}10${neutre} ] - Installation de clamav + Mise à jour des signatures AV"
    #echo -e "\t[  ${vert}11${neutre} ] - Copie de vsencode dans Documents/ : désencoder fichiers APEX"    
    
    echo -e "\e[3C${bleu}[ --    ${souligne}REVERSE ENGINEERING${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[  ${vert}20${neutre} ] - Installation des outils de Reverse : gdb-peda"
    echo -e "\t[  ${vert}21${neutre} ] - Installation des outils de Reverse : radare2"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}ANALYSE RAM${neutrePolice}${bleu}     -- ]${neutre}"    
    echo -e "\t[  ${vert}30${neutre} ] - Installation de volatility 2.6    ${rouge}(https://github.com/volatilityfoundation/volatility.git)${neutre}"
    echo -e "\t[  ${vert}31${neutre} ] - Installation de volatility 3    ${rouge}(https://github.com/volatilityfoundation/volatility3.git)${neutre}"
    echo -e "\t[  ${vert}32${neutre} ] - Installation de ramParserVolatility3 : parsing .raw avec Vol3.py + export en CSV / XLSX    ${rouge}(https://github.com/yakisyst3m/IFT-install_forensics_tools/res/ramParserVolatility3.sh)${neutre}"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}ANALYSE REGISTRE${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[  ${vert}40${neutre} ] - Installation de Regripper : analyse registre Windows"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}OUTILS BUREAUTIQUE${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[  ${vert}50${neutre} ] - Installation des outils de bureautique : thunderbird / readpst / msgconvert"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}ANALYSE DISQUE  + MFT + TIMELINE${neutrePolice}${bleu}   -- ]${neutre}"
    echo -e "\t[  ${vert}60${neutre} ] - Installation des outils de disques : guymager / qemu / suite ewf / hdparm / sdparm "
    echo -e "\t[  ${vert}61${neutre} ] - Installation de l'outil de disque E01 : Pyhton ImageMounter pour montage auto d'une image E01 encase"
    echo -e "\t[  ${vert}62${neutre} ] - Installation des Outils de Timeline et Artefacts Windows : La suite plaso / ewf / olevba3 / prefetch / ShimCacheParser"
    echo -e "\t[  ${vert}63${neutre} ] - Installation de la suite sleuthkit : mmls / fls / icat / mactime"
    echo -e "\t[  ${vert}64${neutre} ] - Installation de mft_dump : parser le fichier \$MFT      ${rouge}(https://github.com/omerbenamram/mft)${neutre}"
    echo -e "\t[  ${vert}65${neutre} ] - Installation de l'outil : guestmount - montage disque VMDK + VDI${neutre}"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}LOG - CONVERSION - PARSING - COLLECTE${neutrePolice}${bleu}   -- ]${neutre}"
    echo -e "\t[  ${vert}70${neutre} ] - Installation des outils d'analyse de log : auditd / evtx2log    ${rouge}(https://github.com/yakisyst3m/evtx2log)${neutre}"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}OUTILS FORENSICS SUPPLEMENTAIRES${neutrePolice}${bleu}     -- ]${neutre}"    
    echo -e "\t[  ${vert}80${neutre} ] - Installation du paquet : forensics-all"
    echo -e "\t[  ${vert}81${neutre} ] - Installation du paquet : forensics-extra"
    echo -e "\t[  ${vert}82${neutre} ] - Installation du paquet : forensics-extra-gui"
    
    echo -e "\e[3C${bleu}[ --    ${souligne}VIRTUALISATION - Emulateur${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[  ${vert}90${neutre} ] - Installation et configuration de Virtualbox 7.0 + son Extension Pack"
    echo -e "\t[  ${vert}91${neutre} ] - Installation et configuration de wine32 et wine64"

    echo -e "\e[3C${bleu}[ --    ${souligne}CONVERTISSEURS${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[ ${vert}100${neutre} ] - Installation de l'outil : csv2xlsx pour convertir les CSV en XLSX - choix : délimiteur / nb colonnes-lignes / encoding..      ${rouge}(https://gitlab.com/DerLinkshaender/csv2xlsx)${neutre}"
    echo -e "\t[ ${vert}101${neutre} ] - Installation de l'outil : CyberChef      ${rouge}(https://github.com/gchq/CyberChef/releases)${neutre}"

    echo -e "\e[3C${bleu}[ --    ${souligne}YARA${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[ ${vert}110${neutre} ] - Installation des outils Yara et yarac: recherche de Pattern pour la détection de Malware"

    echo -e "\e[3C${bleu}[ --    ${souligne}SCRIPTING${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[ ${vert}120${neutre} ] - Installation de powershell sous Linux"
    echo -e "\t[ ${vert}121${neutre} ] - Installation du Packer/Depacker UPX"

    echo -e "\e[3C${bleu}[ --    ${souligne}ANDROID TOOLS${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[ ${vert}130${neutre} ] - Installation de ADB et FASTBOOT"

    echo -e "\e[3C${bleu}[ --    ${souligne}DOCKER TOOLS${neutrePolice}${bleu}     -- ]${neutre}"
    echo -e "\t[ ${vert}140${neutre} ] - Installation de Docker + Docker Compose"

#    echo -e "\n\e[3C${bleu}[ --    ${souligne}SIGMA${neutrePolice}${bleu}     -- ]${neutre}"
#    echo -e "\t[ ${vert}120${neutre} ] - Installation de SIGMA : règles de détection et de partage pour les SIEM"

    echo -e "\n\t[ ${vert}200${neutre} ] - ${vert}Tout installer${neutre}"
    echo -e "\t[  ${rouge}F${neutre}  ] - Taper F pour finaliser l'installation..."
    echo -e "\t\t---> Dans tous les cas, une fois vos installations choisies, terminer par l'option [ F ]\n"
    echo -e "\e[20C[  ${rouge}Q${neutre}  ] - Taper ${rouge}Q${neutre} pour ${rouge}quitter${neutre}...\n"
    echo -e "\e[3CEntrer votre choix : \c"
    read INSTALL
    echo
    case $INSTALL in
    "0")
        sourcelist ;;
    "1")
        mjour ;;
    "2")
        installbase ; config;;
    "3")
        creerrepertoires ;;
    "10")
        claminst ;;
   # "11")
    #    vsencodeinstall ;;        
    "20")
        gdbinst ;;
    "21")
        radare2inst ;;        
    "30")
        volat2 ; validChang ;;
    "31")
        volat3 ; validChang ;;
    "32")
        volat3 ; convertinstall ; ramParserinstall ;;
    "40")
        reginst ;;
    "50")
        burinst ;;
    "60")
        diskinst ;;
    "61")
        imagemounterE01 ;;
    "62")
        mftinst ;;
    "63")
        sleuthkitInstall ;;
    "64")
        mftdumpinst ;;
    "65")
        mountvmdkinstall ;;               
    "70")
        loginstall ;;        
    "80")        
        forall ;;
    "81")
        forextra ;;
    "82")
        forextragui ;;
    "90")
        vbox ;;
    "91")
        wineinstall ;;        
   "100")
        convertinstall ;;
   "101")
        cyberchefinstall ;;
   "110")
        yarainstall ;;
   "120")
        powershellinstall ;;
   "121")
        upxinstall ;;   
   "130")
        androidForensics ;;
   "140")        
        dockerTools ;;
   "200")
        sourcelist ; mjour ; installbase ; config ; creerrepertoires ; claminst ; gdbinst ; radare2inst ; volat2 ; volat3 ; convertinstall ; ramParserinstall ;\
        reginst ; burinst ; diskinst ; imagemounterE01 ; mftinst ; sleuthkitInstall ; mftdumpinst ; mountvmdkinstall ;\
        loginstall ; forall ; forextra ; forextragui ; vbox ; wineinstall ; convertinstall ; cyberchefinstall ; yarainstall ;\
        powershellinstall ; upxinstall ; androidForensics ; dockerTools ;;
    f|F) break ;;
    q|Q) exit ;;
    *) continue ;;
    esac     
done


########    FINALISATION    ###########################################################

chmod -R 750 /home/"$utilisateur"/
chown -R "$utilisateur": /home/"$utilisateur"/


echo -e "\n##############################################\n"
echo -e "${vert}---------- FIN D'INSTALLATION -----------${neutre}"
echo "Voulez-vous redemérrer maintenant pour valider tous les changements ? ( y / n )"
read REBOOT

if [ "$REBOOT" = "y" ] ; then
    reboot
else
    echo -e "${violet}Il faudra redémarrer avant d'utiliser les applications${neutre}"
fi


















