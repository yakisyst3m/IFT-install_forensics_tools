#!/bin/bash

# https://github.com/yakisyst3m 

# 2022 01 22    v1.0
# 2022 02 03    v1.1
# 2022 02 17    v1.2
# 2022 03 06    v2.0 
# 2022 03 06    v2.1 mise en place du menu + fonctions
# 2022 03 07    v2.1-1 Modif ShimCacheParser.py
# 2022 03 07    v2.1-2 Modif nommage volatility : vol2.py pour volatility 2.6 / vol3.py pour volatility 3
# 2022 03 09    v2.1-3 Correctif chemins + python3 + fcontion validchg
# 2022 03 10    v2.1-4 Modif install wireshark + extpackVbox + formatage du mode verbeux
# 2022 03 16    v2.1-5 Correction volatility 3 table des symbols windows + fonction décompte + modif fct IPv6
# 2022 03 18    v2.1-6 suite sleuthkit
# 2022 03 18    v2.1-7 Python ImageMounter


##################################      INSTALLATION DES OUTILS FORENSICS POUR DEBIAN OU UBUNTU      ######################################"

# VARIABLES : LES VERSIONS / CHEMINS / COULEURS
    utilisateur=$(grep 1000 /etc/passwd | awk -F ":" '{print $1}')
    VERSION_OS=$(grep -E '^ID=' /etc/os-release | cut -d "=" -f2)
    ENVBUREAU="/etc/mate/"
    GESTCONNECTION="/etc/lightdm/"
    cheminInstall="/home/$utilisateur/Documents/Linux-Post_Install/"

    ETHNAME=$(ip a | grep "2: en" | tr " " ":" | awk -F ":" '{print $3}')
    ETHCHEMIN="/etc/sysconfig/network-scripts/ifcfg-$ETHNAME"
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



######## DECOMPTE ###########################################################

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

######## MODIFICATION DES SOURCE.LIST ####################################################

    ######## version os DEBIAN ####################################################
function mjour() {
    if [ "$VERSION_OS" = 'debian' ] ; then
        echo -e "\n${bleu}[ ---- Mise à jour de source.list de Debian ---- ]${neutre}\n"
        echo "deb http://deb.debian.org/debian/ bullseye main non-free contrib" > /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian/ bullseye main non-free contrib" >> /etc/apt/sources.list
        echo "deb http://security.debian.org/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list
        echo "deb-src http://security.debian.org/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list
        echo "deb-src http://deb.debian.org/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list
        echo "deb http://deb.debian.org/debian bullseye-backports main contrib non-free" >> /etc/apt/sources.list

        apt update && apt install -y apt-transport-https
        sed -i 's/http/https/g' /etc/apt/sources.list
        apt update && apt upgrade -y && echo -e "${vert} [ OK ] Système à jour ${neutre}"
        sleep 2
        
        # Correction "A job is runnin UID 1000 (34s / 2mi 3s)"
        if [ "grep -q 'DefaultTimeoutStartSec=20s' /etc/systemd/system.conf" ] ; then
            echo -e "${vert} [ OK ] Correction des erreurs déjà effectué ${neutre}"
        else
            sed -i '/\[Manager]/a DefaultTimeoutStartSec=20s' /etc/systemd/system.conf 
            sed -i '/\[Manager]/a DefaultTimeoutStopSec=20s' /etc/systemd/system.conf && echo -e "${vert} [ OK ] Correction des erreurs au boot et à l'arrêt effectué ${neutre}"
        fi
        decompte 2
                      
    ######## version os UBUNTU ############################################################"
    elif [ "$VERSION_OS" = 'ubuntu' ] ; then
        echo -e "\n${bleu}[ ---- Mise à jour de source.list de Ubuntu ---- ]${neutre}\n"
        echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"  > /etc/apt/sources.list
        echo "deb http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb-src http://fr.archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb-src http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse"  >> /etc/apt/soyakisyst3m/post_install_linux_install_forensics_toolsurces.list
        echo "deb-src http://fr.archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse"  >> /etc/apt/sources.list
        echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse"  >> /etc/apt/sources.list

        apt update && apt upgrade -y && echo -e "${vert} [ OK ] Système à jour ${neutre}"
        decompte 2
    else
        echo -e "${rouge}Le système d'exploitation n'est ni une distribution Debian, ni une distribution unbuntu : [ Fin de l'installation ]${neutre}"
        exit
    fi
}


######## INSTALL DES LOGICIELS DE BASE #################################################################################

function installbase() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Installation des logiciels de base ---- ]${neutre}\n"
    apt install -y vim htop glances bmon gcc build-essential linux-headers-$(uname -r) make dkms nmap net-tools hping3 arping foremost libimage-exiftool-perl sonic-visualiser wxhexeditor hexedit gparted rsync tcpdump geany wget curl bash-completion tree numlockx minicom git whois nethogs testdisk tmux openssh-server openssl sqlite3 python3.9 python2.7 python3-pip python3-venv tshark openssl keepassx gufw rename parted p7zip 
    
    # Installation de Wireshark de façon non-intéractive
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark && echo -e "${vert} [ OK ] Logiciels de Bases Installés ${neutre}"

    decompte 2

    if [ "$VERSION_OS" = 'debian' ] ; then
        ## Corrections kernel Debian 11
        echo -e "\n##############################################\n"
        echo -e "${bleu}[ Correction des erreurs au boot et à l'arrêt ]${neutre}"
        apt install -y libblockdev-mdraid2 libblockdev* apt-file 
        apt install -y firmware-linux firmware-linux-free firmware-linux-nonfree && echo -e "${vert} [ OK ] Le firmware-linux pour Debian Installé ${neutre}"
        update-initramfs -u -k all && echo -e "${vert} [ OK ] Correction des erreurs au boot et à l'arrêt effectué ${neutre}"
        decompte 2
    fi

    cp res/gufw.service /etc/systemd/system/ && echo -e "${vert} [ OK ] Firewall Gufw service en place à l'emplacement : /etc/systemd/system/${neutre}"
    decompte 2

    if [ -d "$ENVBUREAU" ] ; then
        apt install -y caja-open-terminal mate-desktop-environment-extras  && echo -e "${vert} [ OK ] Outils d'environnement de Bureau Mate installés${neutre}"
        decompte 2
    fi
}

######## CONFIGURATION DES APPLICATIONS

function config() {
    # Wireshark
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Configuration de wireshark ---- ]${neutre}\n"
    usermod -aG wireshark "$utilisateur"
    chgrp wireshark /usr/bin/dumpcap
    chmod 750 /usr/bin/dumpcap
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap && echo -e "${vert} [ OK ] Wireshark configuré ${neutre}" || echo -e "${rouge} [ NOK ] Résoudre le problème ${neutre}"
    sleep 2

    # Désactivation IPv6
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Désactivation de l'IPv6 ---- ]${neutre}\n"

    sed -ri  "s/^IPV6/#IPV6/g" "$ETHCHEMIN" && echo -e "${vert} [ OK ] Ligne IPV6 désactivées dans le fichier $ETHCHEMIN ${neutre}"

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
    echo -e "\n${bleufondjaune}Validation de la configuration${neutre}\n"

    sysctl -p
    sleep 2

    # Pavé numérique
    if [ -d $GESTCONNECTION ] ; then # Debian Mate avec lightdm
        echo -e "\n##############################################\n"
        echo -e "\n${bleu}[ ---- Configuration du pavé numérique ---- ]${neutre}\n"
        sed -i '/\[Seat:\*\]/a greeter-setup-script=/usr/bin/numlockx on' /etc/lightdm/lightdm.conf
        echo "NUMLOCK=on" > /etc/default/numlockx
        grep -q "NUMLOCK=on" /etc/default/numlockx && echo -e "${vert} [ OK ] installé et paramétré pour lightdm ${neutre}"
        sleep 2
    fi

    if [ "$VERSION_OS" = 'ubuntu' ] ; then # Ubuntu avec GDM3
        echo -e "\n##############################################\n"
        echo -e "\n${bleu}[ ---- Configuration du pavé numérique ---- ]${neutre}\n"
        sed -i '/exit 0/i \if [ -x /usr/bin/numlockx ]; then\nexec /usr/bin/numlockx on\nfi' /etc/gdm3/Init/Default && echo -e "${vert} [ OK ] installé et paramétré pour gdm3 Ubuntu ${neutre}"
        sleep 2
    fi

    # Modif des droits TMUX
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Configuration de TMUX ---- ]${neutre}\n"
    cp ./res/.tmux.conf /home/"$utilisateur"/
    cp ./res/.tmux.conf /root/

    chown "$utilisateur": /home/"$utilisateur"/.tmux.conf && echo -e "${vert} [ OK ] TMUX Configuré ${neutre}"
    sleep 2

    # Conf vim
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Configuration de VIM ---- ]${neutre}\n"
    echo -e "syntax on\nset number\nset autoindent\nset tabstop=6\nset showmode\nset mouse=a" >> /etc/vim/vimrc && echo -e "${vert} [ OK ] VIM Configuré ${neutre}"
    decompte 2
}

######## ARCHITECTURE DOSSIER   TRAVAIL FORENSIC

function creerrepertoires() {
    #    Cas d'anlyse Windows
    #   ----------------------
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Création des dossiers qui contiendront les points de montages des disques, RAM, Artefacts Windows et Linux ---- ]${neutre}\n"
    mkdir -p /cases/{w_01,w_02,w_03,w_04}/{firefoxHistory,pst/PJ_outlook,prefetch,malware,mft,dump,evtx,timeline,hivelist,network,filecarving/{photorec,foremost}} && echo -e "${vert} [ OK ] accueil windows : /cases Configuré ${neutre}"
    mkdir -p /mnt/{usb1,usb2,win1,win2,linux1,linux2,encase1-E01,encase2-E01,ram1,ram2} && echo -e "${vert} [ OK ] accueil windows : /mnt Configuré ${neutre}"

    #    Cas d'analyse linux
    #   ----------------------
    mkdir -p /cases/{lx_01,lx_02,lx_03,lx_04}/{firefoxHistory,info_OS/{release,grub},cron,history/{cmd,viminfo},mail/{PJ_mail,},malware,dump,log,timeline,login_MDP,network/{ssh,},filecarving/{photorec,foremost}} && echo -e "${vert} [ OK ] accueil linux : /cases Configuré ${neutre}"
    sleep 3
}

########  INSTALLER CLAMAV

function claminst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de clamav ---- ]${neutre}\n"
    apt install -y clamav && echo -e "${vert} [ OK ] Clamav installé ${neutre}"
    systemctl stop clamav-freshclam.service && echo -e "${vert} [ OK ] Arrêt du service Clamav ${neutre}"
    freshclam && echo -e "${vert} [ OK ] Mise à jour du service Clamav ${neutre}"
    systemctl start clamav-freshclam.service && echo -e "${vert} [ OK ] Démarrage du service Clamav ${neutre}"
    sleep 3
}

######## INSTALL GDB-PEDA

function gdbinst() {
    # GDB-PEDA pour user
    echo -e "\n${bleu}[ ---- Début d'installation de gdb-peda ---- ]${neutre}\n"
    apt install -y gdb
    git clone https://github.com/longld/peda.git /home/"$utilisateur"/peda
    echo "source /home/$utilisateur/peda/peda.py" >> /home/"$utilisateur"/.gdbinit  && echo -e "${vert} [ OK ] gdp-peda paramétré pour $utilisateur ${neutre}"

    # Pour root
    cp -r /home/"$utilisateur"/peda /root/peda
    echo "source /root/peda/peda.py" >> /root/.gdbinit  && echo -e "${vert} [ OK ] gdp-peda paramétré pour root ${neutre}"
    sleep 3
}

######################## INSTALLATION DE VOLATILITY 2.6 OU 3 #####################################"

########    INSTALLER VOLATILITY 2.6

function volat2() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de Volatility 2.6 ---- ]${neutre}\n"
    decompte 2
    # Préparation avant installation
    cd /home/"$utilisateur"/Documents/
    echo "Début de l'installation et des mises à jour de Volatility 2.6 :"
    echo "Installation des librairies"
    apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata  && echo -e "${vert} [ OK ] Modules afférent à Volatility 2.6 installés ${neutre}"
    decompte 1
    
    # Installation de python 2
    echo "Installation des outils python 2"
    apt install -y python2 python2.7-dev libpython2-dev
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
    python2 get-pip.py
    python2 -m pip install -U setuptools wheel  && echo -e "${vert} [ OK ] Outils python pour Volatility 2.6 installés ${neutre}"
    decompte 1
    
    # Installation des modules volatility
    echo "Install des dépendences"
    python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
    ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so  && echo -e "${vert} [ OK ] Dépendences de Volatility 2.6 installés ${neutre}"
    decompte 1
    
    # Téléchargement et Installation de volatility 2.6
    python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git  && echo -e "${vert} [ OK ] Volatility 2.6 installé ${neutre}"
    decompte 1
    
    # Renommage de fichier
    mv /usr/local/bin/vol.py /usr/local/bin/vol2.py
    
    # Configuration du PATH de env pour volatility
    echo "export PATH=/home/$utilisateur/.local/bin:"'$PATH' >> ~/.bashrc
    . ~/.bashrc && echo -e "${vert} [ OK ] PATH $utilisateur mis à jour ${neutre}"
    
    # Test
    vol2.py -h
    sleep 3
}
        
########    INSTALLER VOLATILITY 3

function volat3() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de Volatility 3 ---- ]${neutre}\n"
    decompte 2
    
    # Préparation avant installation
    cd /home/"$utilisateur"/
    echo "Début de l'installation et des mises à jour de Volatility 3:"
    echo "Installation des librairies"
    apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata  && echo -e "${vert} [ OK ] Modules afférent à Volatility 3 installés ${neutre}"
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
    chown -R "$utilisateur": ../.volatility3/ && echo -e "${vert} [ OK ] Volatility 3 téléchargé ${neutre}"
    
    # Installation des modules volatility
    pip3 install -r requirements.txt
    
    # Configuration du PATH de env pour volatility 3
    echo "export PATH=/home/$utilisateur/.volatility3:"'$PATH' >> /home/"$utilisateur"/.bashrc
    echo "export PATH=/home/$utilisateur/.volatility3:"'$PATH' >> /root/.bashrc
    . /home/"$utilisateur"/.bashrc && echo -e "${vert} [ OK ] PATH $utilisateur mis à jour ${neutre}"
    . /root/.bashrc && echo -e "${vert} [ OK ] PATH root mis à jour ${neutre}"
    
    # Test
    vol3.py -h
    sleep 3
}


########    INSTALLER DES OUTILS REGRIPPER V3

function reginst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de Regripper V3.0 ---- ]${neutre}\n"
    cd "$cheminInstall"
    apt-get install -y git libparse-win32registry-perl -y
    
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
    sleep 3
}

########    LES OUTILS DE BUREAUTIQUE

function burinst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation des outils de bureautique ---- ]${neutre}\n"
    apt install -y libemail-outlook-message-perl pst-utils thunderbird  && echo -e "${vert} [ OK ] Outils Bureautique installés ${neutre}"
    sleep 3
}

########    LES OUTILS DE DISQUES

function diskinst() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation des outils de disque ---- ]${neutre}\n"
    apt install -y guymager qemu-utils libewf-dev ewf-tools hdparm sdparm && echo -e "${vert} [ OK ] Outils de disques installés ${neutre}"
    sleep 3
}

########    QUELQUES LOGICIELS FORENSIC 

function mftinst() {
    echo -e "\n##############################################\n"
    # olevba3 # analyzeMFT.py
    echo -e "\n${bleu}[ ---- Début d'installation de oletools analyzeMFT ---- ]${neutre}\n"
    pip install oletools analyzeMFT && echo -e "${vert} [ OK ] oletools analyzeMFT installés ${neutre}"
    decompte 1
    # getfattr # ewfacquire ...
    echo -e "\n${bleu}[ ---- Début d'installation de pff-tools ewf-tools libewf-dev libewf2 attr ---- ]${neutre}\n"
    apt install -y pff-tools ewf-tools libewf-dev libewf2 attr && echo -e "${vert} [ OK ] pff-tools ewf-tools libewf-dev libewf2 attr installés ${neutre}"
    decompte 1
    # Suite plaso : # log2timeline.py # psort.py # psteal.py
    echo -e "\n${bleu}[ ---- Début d'installation de la suite plaso ---- ]${neutre}\n"
    apt install -y plaso && echo -e "${vert} [ OK ] Suite plaso installés ${neutre}"
    decompte 1
    # prefetch.py
    echo -e "\n${bleu}[ ---- Début d'installation de windowsprefetch ---- ]${neutre}\n"
    pip3 install windowsprefetch && echo -e "${vert} [ OK ] windowsprefetch installés ${neutre}"
    decompte 1
    # ShimCacheParser.py 
    echo -e "\n${bleu}[ ---- Début d'installation de ShimCacheParser.py ---- ]${neutre}\n"
    cd "$cheminInstall"
    unzip ./res/ShimCacheParser-master.zip 
    cp -r ShimCacheParser-master /home/"$utilisateur"/
    chmod -R 750 /home/"$utilisateur"/ShimCacheParser-master/ && echo -e "${vert} [ OK ] ShimCacheParser installé dans : /home/$utilisateur/ShimCacheParser-master/  ${neutre}"
    chown -R "$utilisateur": /home/"$utilisateur"/ShimCacheParser-master/
    sleep 3
}

########    INSTALLER LA SUITE SLEUTHKIT

function sleuthkitInstall() {
    # fls / mmls / icat / mactime / 
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de la suite sleuthkit ---- ]${neutre}\n"
    cd "$cheminInstall"
    unzip res/sleuthkit-debian-master.zip 
    cd sleuthkit-debian-master/
    ./configure 
    make
    make install && echo -e "${vert} [ OK ] Suite Sleuthkit installée ${neutre}"
    sleep 3
}

########    INSTALLER L'APPLICATION PYTHON IMAGEMOUNTER - MOTAGE AUTO E01

function imagemounterE01() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de l'application Python ImageMounter pour Image E01 Encase ---- ]${neutre}\n"
    cd "$cheminInstall"
    
    # Dépendences
    apt install -y python3-pip python-setuptools xmount ewf-tools afflib-tools sleuthkit disktype qemu-utils avfs xfsprogs lvm2 vmfs-tools mtd-tools squashfs-tools mdadm cryptsetup libbde-utils libvshadow-utils 
    
    # Installation
    pip3 install pytsk3 python-magic imagemounter && echo -e "${vert} [ OK ] ImageMounter installé - Pour lancer : imount image.E01 ${neutre}"
    
    # Vérification des dépendence obligatoires et facultatives
    imount --check
    echo -e "\n\t${rouge}Vérifier que les dépendences obligatoires sont installées + Appuyer sur une touche pour continuer ...${neutre}"
    read
}

########    FORENSICS-ALL

function forall() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de FORENSICS-ALL ---- ]${neutre}\n"
    apt install -y forensics-all && echo -e "${vert} [ OK ] forensics-all installé ${neutre}"
    sleep 3
}

########    FORENSICS-EXTRA

function forextra() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de FORENSICS-EXTRA ---- ]${neutre}\n"
    apt install -y forensics-extra && echo -e "${vert} [ OK ] forensics-extra installé ${neutre}"
    sleep 3
}

########    FORENSICS-EXTRA-GUI

function forextragui() {
    echo -e "\n##############################################\n"
    echo -e "\n${bleu}[ ---- Début d'installation de FORENSICS-EXTRA-GUI ---- ]${neutre}\n"
    apt install -y forensics-extra-gui && echo -e "${vert} [ OK ] forensics-extra-gui installé ${neutre}"
    sleep 3
}

########    INSTALLATION DE VIRTUALBOX 6.1

function vbox() {
    echo -e "\n##############################################\n"
    # Vérification que l'on est sur une machine physique
    os=$(dmidecode | grep -Ei '(version.*virt)' | awk -F " " '{print $2}')
    if [ "$os" != "VirtualBox" ] ; then
        
        # Téléchargement des clés
        echo -e "\n${bleu}[ ---- Début d'installation et de configuration Virtualbox ---- ]${neutre}\n"
        echo -e "${jaune}[ Téléchargement et ajout des clés publiques de virtualbox ]${neutre}"
        wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
        wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -

        # Modification de la source.list et mise à jour
        echo -e "${jaune}[ Modification des source.list ]${neutre}"
        if [ "$VERSION_OS" = 'ubuntu' ] ; then
            add-apt-repository "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib"
        fi
        if [ "$VERSION_OS" = 'debian' ] ; then
            echo "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib" >> /etc/apt/sources.list
        fi
        apt update && apt -y full-upgrade

        # Installation de virtualbox
        echo -e "${jaune}[ Installation de virtualbox ]${neutre}"
        apt install -y virtualbox-6.1 && echo -e "${vert} [ OK ] Virtualbox $vboxVersion installé ${neutre}"

        # Téléchargement de l'Extension Pack
        vboxVersion=$(dpkg -l | grep -i virtualbox | awk -F " " '{print $3}' | grep -oE '([0-9]{1}\.){2}[0-9]{1,3}')
        echo -e "${jaune}[ Installation de l'extension Pack ]${neutre}"
        wget https://download.virtualbox.org/virtualbox/"$vboxVersion"/Oracle_VM_VirtualBox_Extension_Pack-"$vboxVersion".vbox-extpack
        
        # Installation de l'Extension Pack + acceptation licence
        echo ${ACCEPT_ORACLE_EXTPACK_LICENSE:='y'} | VBoxManage extpack install "Oracle_VM_VirtualBox_Extension_Pack-$vboxVersion.vbox-extpack" && echo -e "${vert} [ OK ] Extension Pack de Virtualbox $vboxVersion installée ${neutre}"

        # Configuration pour pouvoir utiliser l'USB
        echo -e "${jaune}[ Configuration de Virtualbox pour utiliser les clés USB ]${neutre}"
        usermod -aG vboxusers "$utilisateur" && echo -e "${vert} [ OK ] Utilisation de l'USB configuré ${neutre}"

        # Configuration pour le démarrage sur clé USB
        usermod -aG disk "$utilisateur" && echo -e "${vert} [ OK ] Configuration pour démarrage sur clé USB configuré ${neutre}"
        echo -e "${vert}[ ---- Fin d'installation et de configuration Virtualbox ---- ]${neutre}"
        sleep 3
    else
        echo -e "${rouge}Vous êtes sur une machine virtuelle, pas d'installation${neutre}"
        sleep 3
    fi
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

clear
while true ; do 
echo -e "${vert}           ________      ______     _________ ${neutre}"
echo -e "${vert}          /_______/\    /_____/\   /________/\ ${neutre}"
echo -e "${vert}          \__.::._\/    \::::_\/_  \__.::.__\/ ${neutre}"
echo -e "${vert}             \::\ \      \:\/___/\    \::\ \   ${neutre}"
echo -e "${vert}             _\::\ \__    \:::._\/     \::\ \  ${neutre}"
echo -e "${vert}            /__\::\__/\    \:\ \        \::\ \ ${neutre}"
echo -e "${vert}            \________\/     \_\/         \__\/  ${neutre}"               
echo " "
echo -e "\e[2C${bleu}---${neutre}----${rouge}----   [ ${vert}I${rouge}NSTALL ${vert}F${rouge}ORENSICS ${vert}T${rouge}OOLS ]    ${bleu}---${neutre}----${rouge}----${neutre}"
echo " "
    #echo -e "${bleu}Faites votre choix d'installation :${neutre}"
    #echo -e "${vert}-----------------------------------${neutre}"
    echo -e "\e[3C${bleu}[ --    ${souligne}INSTALLATION DE BASE${neutrePolice}     -- ]${neutre}"    
    echo -e "\t[  ${vert}1${neutre} ] - Modification des source.list + Mise à jour des paquets"
    echo -e "\t[  ${vert}2${neutre} ] - Installation des logiciels de base"
    echo -e "\t[  ${vert}3${neutre} ] - Configuration des applications : Wireshark / déscativation IPv6 / Activation du pavé numérique / Tmux / Vim"
    echo -e "\t[  ${vert}4${neutre} ] - Création de l'architecture des dossiers : pour montage des disques windows et linux à analyser"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}ANTI-VIRUS${neutrePolice}     -- ]${neutre}"    
    echo -e "\t[  ${vert}5${neutre} ] - Installation de clamav + Mise à jour des signatures AV"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}REVERSE ENGINEERING${neutrePolice}     -- ]${neutre}"
    echo -e "\t[  ${vert}6${neutre} ] - Installation des outils de Reverse : gdb-peda"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}ANALYSE RAM${neutrePolice}     -- ]${neutre}"    
    echo -e "\t[  ${vert}7${neutre} ] - Installation de volatility 2.6"
    echo -e "\t[  ${vert}8${neutre} ] - Installation de volatility 3"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}ANALYSE REGISTRE${neutrePolice}     -- ]${neutre}"
    echo -e "\t[  ${vert}9${neutre} ] - Installation de Regripper : analyse registre Windows"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}OUTILS BUREAUTIQUE${neutrePolice}     -- ]${neutre}"
    echo -e "\t[ ${vert}10${neutre} ] - Installation des outils de bureautique : thunderbird / readpst / msgconvert"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}ANALYSE DISQUE  + MFT + TIMELINE${neutrePolice}   -- ]${neutre}"
    echo -e "\t[ ${vert}11${neutre} ] - Installation des outils de disques : guymager / qemu / suite ewf / hdparm / sdparm "
    echo -e "\t[ ${vert}12${neutre} ] - Installation de l'outil de disque E01 : Pyhton ImageMounter pour montage auto d'une image E01 encase"
    echo -e "\t[ ${vert}13${neutre} ] - Installation des Outils de Timeline et Artefacts Windows : La suite plaso / ewf / olevba3 / prefetch / ShimCacheParser"
    echo -e "\t[ ${vert}14${neutre} ] - Installation de la suite sleuthkit : mmls / fls / icat / mactime"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}OUTILS FORENSICS SUPPLEMENTAIRES${neutrePolice}     -- ]${neutre}"    
    echo -e "\t[ ${vert}15${neutre} ] - Installation du paquet : forensics-all"
    echo -e "\t[ ${vert}16${neutre} ] - Installation du paquet : forensics-extra"
    echo -e "\t[ ${vert}17${neutre} ] - Installation du paquet : forensics-extra-gui"
    echo -e "\n\e[3C${bleu}[ --    ${souligne}VIRTUALISATION${neutrePolice}     -- ]${neutre}"
    echo -e "\t[ ${vert}18${neutre} ] - Installation et configuration de Virtualbox 6.1 + son Extension Pack"

    echo -e "\n\t[ ${vert}100${neutre} ] - ${vert}Tout installer${neutre}"
    echo -e "\t[  ${rouge}F${neutre} ] - Taper F pour finaliser l'installation..."
    echo -e "\t---> Dans tous les cas, une fois vos installations choisies, terminer par l'option [ F ]\n"
    echo -e "\e[20C[  ${rouge}Q${neutre} ] - Taper ${rouge}Q${neutre} pour ${rouge}quitter${neutre}...\n"
    echo -e "\e[3CEntrer votre choix : \c"
    read INSTALL
    #read -p "Entrer votre choix : " INSTALL
 
    echo

    case $INSTALL in
    "1")
        mjour ;;
    "2")
        installbase ;;
    "3")
        config ;;
    "4")
        creerrepertoires ;;
    "5")
        claminst ;;
    "6")
        gdbinst ;;
    "7")
        volat2 ; validChang ;;
    "8")
        volat3 ; validChang ;;
    "9")
        reginst ;;
    "10")
        burinst ;;
    "11")
        diskinst ;;
    "12")
        imagemounterE01 ;;
    "13")
        mftinst ;;
    "14")
        sleuthkitInstall ;;
    "15")        
        forall ;;
    "16")
        forextra ;;
    "17")
        forextragui ;;
    "18")
        vbox ;;
    "100")
        mjour ; installbase ; config ; creerrepertoires ; claminst ; gdbinst ; volat2 ; volat3 ; reginst ; burinst ; diskinst ; imagemounterE01 ; mftinst ; sleuthkitInstall ; forall ; forextra ; forextragui ; vbox ;;
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


















