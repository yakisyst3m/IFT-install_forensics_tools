#!/bin/bash

# https://github.com/yakisyst3m 
# V2.0

# 2022 01 22    v1.0
# 2022 02 03    v1.1
# 2022 02 17    v1.2
# 2022 03 06    v2.0
# 2022 03 06    v2.1


##################################      INSTALLATION DES OUTILS FORENSICS POUR DEBIAN OU UBUNTU      ######################################"

# VARIABLES : LES VERSIONS / CHEMINS / COULEURS

VERSION_OS=$(egrep '^ID=' /etc/os-release | cut -d "=" -f2)
ENVBUREAU="/etc/mate/"
GESTCONNECTION="/etc/lightdm/"

rouge='\e[1;31m'
vert='\e[1;32m'
jaune='\e[1;33m'
bleu='\e[1;34m' 
violet='\e[1;35m'
neutre='\e[0;m'


######## PREPARATION ###########################################################

utilisateur=$(grep 1000 /etc/passwd | awk -F ":" '{print $1}')


######## VERIFICATION PRESENCE DU DOSSIER D'INSTALLATION AU BON ENDROIT

CH_INSTALL="/home/$utilisateur/Documents/Linux-Post_Install/"

    if [ -d $CH_INSTALL ]
    then
        cd $CH_INSTALL
    else
        echo -e "${rouge}Veuillez copier le dossier 'Linux-Post_Install/' dans : /home/$utilisateur/Documents/ puis relancer le script${neutre}"
        echo -e "${rouge}Veuillez lancer script install.sh${neutre}"
        exit
        fi


######## version os DEBIAN ####################################################

if [ $VERSION_OS = 'debian' ]
then
    ######## MAJ SOURCELIST

    echo -e "${bleu}[ Mise à jour de source.list de Debian ]${neutre}"
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
    
    ## Corrections kernel Debian 11
    echo -e "\n##############################################\n"
    echo -e "${bleu}[ Correction des erreurs au boot et à l'arrêt ]${neutre}"
    apt install -y libblockdev-mdraid2 libblockdev* apt-file 
    apt install -y firmware-linux
    update-initramfs -u -k all && echo -e "${vert} [ OK ] Correction des erreurs au boot et à l'arrêt effectué 1/2 ${neutre}"
    
    # Correction "A job is runnin UID 1000 (34s / 2mi 3s)"

    sed -i '/\[Manager]/a DefaultTimeoutStartSec=20s' /etc/systemd/system.conf 
    sed -i '/\[Manager]/a DefaultTimeoutStopSec=20s' /etc/systemd/system.conf && echo -e "${vert} [ OK ] Correction des erreurs au boot et à l'arrêt effectué 2/2 ${neutre}"
    sleep 2
      
      
        
    ######## version os UBUNTU ############################################################"
    
elif [ $VERSION_OS = 'ubuntu' ]
then
    ######## MAJ SOURCELIST
    
    echo -e "${bleu}[ Mise à jour de source.list de Ubuntu ]${neutre}"
    echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"  > /etc/apt/sources.list
    echo "deb http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse"  >> /etc/apt/sources.list
    echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse"  >> /etc/apt/sources.list
    echo "deb-src http://fr.archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"  >> /etc/apt/sources.list
    echo "deb-src http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse"  >> /etc/apt/sources.list
    echo "deb-src http://fr.archive.ubuntu.com/ubuntu/ focal-updates main restricted universe multiverse"  >> /etc/apt/sources.list
    echo "deb http://fr.archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse"  >> /etc/apt/sources.list

    apt update && apt upgrade -y && echo -e "${vert} [ OK ] Système à jour ${neutre}"
    sleep 2
else
    echo -e "${rouge}Le système d'exploitation n'est ni une distribution Debian, ni une distribution unbuntu : [ Fin de l'installation ]${neutre}"
    exit
fi

######## INSTALL DES LOGICIELS DE BASE #################################################################################

echo -e "\n##############################################\n"
echo -e "${bleu}[ Installation des logiciels de base ]${neutre}"
apt install -y vim htop glances bmon gcc build-essential linux-headers-$(uname -r) make dkms nmap net-tools hping3 arping foremost libimage-exiftool-perl sonic-visualiser wxhexeditor hexedit gparted rsync tcpdump geany wget curl bash-completion tree numlockx gdb minicom git whois nethogs testdisk tmux openssh-server openssl sqlite3 python3.9 python2.7 python3-pip tshark openssl keepassx gufw rename parted p7zip wireshark && echo -e "${vert} [ OK ] Logiciels de Bases Installés ${neutre}"
sleep 2

if [ $VERSION_OS = 'debian' ]
then
apt install -y firmware-linux-nonfree  && echo -e "${vert} [ OK ] Le firmware-linux-nonfree pour Debian Installés ${neutre}"
sleep 2
fi

cp res/gufw.service /etc/systemd/system/ && echo -e "${vert} [ OK ] Firewall Gufw service en place à l'emplacement : /etc/systemd/system/${neutre}"
sleep 2

if [ -d $ENVBUREAU ]
then
    apt install -y caja-open-terminal mate-desktop-environment-extras  && echo -e "${vert} [ OK ] Outils d'environnement de Bureau Mate installés${neutre}"
    sleep 2
fi


######## CONFIGURATION DES APPLICATIONS

# Wireshark
echo -e "\n##############################################\n"
echo -e "${bleu}[ Configuration de WIRESHARK ]${neutre}"
usermod -a -G wireshark $utilisateur
chgrp wireshark /usr/bin/dumpcap
chmod 750 /usr/bin/dumpcap
setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap && echo -e "${vert} [ OK ] Wireshark configuré ${neutre}" || echo -e "${rouge} [ NOK ] Résoudre le problème ${neutre}"
sleep 2

# Désactivation IPv6
echo -e "\n##############################################\n"
echo -e "${bleu}[ Désactivation de l'IPv6 ]${neutre}"

if [ "grep -q 'net.ipv6.conf.all.disable_ipv6' /etc/sysctl.conf" ] ; then # si la ligne existe / -q pour mode silencieux, ne note rien à l'écran
    sed -ri 's/(net\.ipv6\.conf\.all\.disable_ipv6=0|#net\.ipv6\.conf\.all\.disable_ipv6=0|#net\.ipv6\.conf\.all\.disable_ipv6=1)/net\.ipv6\.conf\.all\.disable_ipv6=1/g' /etc/sysctl.conf  && echo -e "${vert} [ OK ] net.ipv6.conf.all.disable_ipv6=1 : paramétré ${neutre}"
else 
    echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf
fi

if [ "grep -q 'net.ipv6.conf.all.autoconf' /etc/sysctl.conf" ] ; then 
    sed -ri 's/(net\.ipv6\.conf\.all\.autoconf=1|#net\.ipv6\.conf\.all\.autoconf=1|#net\.ipv6\.conf\.all\.autoconf=0)/net\.ipv6\.conf\.all\.autoconf=0/g' /etc/sysctl.conf  && echo -e "${vert} [ OK ] net.ipv6.conf.all.autoconf=0 : paramétré ${neutre}"
else
    echo "net.ipv6.conf.all.autoconf=0" >> /etc/sysctl.conf
fi

if [ "grep -q 'net.ipv6.conf.default.disable_ipv6' /etc/sysctl.conf" ] ; then
    sed -ri 's/(net\.ipv6\.conf\.default\.disable_ipv6=0|#net\.ipv6\.conf\.default\.disable_ipv6=0|#net\.ipv6\.conf\.default\.disable_ipv6=1)/net\.ipv6\.conf\.default\.disable_ipv6=1/g' /etc/sysctl.conf  && echo -e "${vert} [ OK ] net.ipv6.conf.default.disable_ipv6=1 : paramétré ${neutre}"
else
    echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.conf
fi

if [ "grep -q 'net.ipv6.conf.default.autoconf' /etc/sysctl.conf" ] ; then
    sed -ri 's/(net\.ipv6\.conf\.default\.autoconf=1|#net\.ipv6\.conf\.default\.autoconf=1|#net\.ipv6\.conf\.default\.autoconf=0)/net\.ipv6\.conf\.default\.autoconf=0/g' /etc/sysctl.conf  && echo -e "${vert} [ OK ] net.ipv6.conf.default.autoconf=0 : paramétré ${neutre}"
else
    echo "net.ipv6.conf.default.autoconf=0" >> /etc/sysctl.conf
fi

sysctl -p
sleep 2

# Pavé numérique
if [ -d $GESTCONNECTION ] # Debian Mate avec lightdm
then
    echo -e "\n##############################################\n"
    echo -e "${bleu}[ Configuration du pavé numérique ]${neutre}"
    sed -i '/\[Seat:\*\]/a greeter-setup-script=/usr/bin/numlockx on' /etc/lightdm/lightdm.conf
    echo "NUMLOCK=on" > /etc/default/numlockx
    grep -q "NUMLOCK=on" /etc/default/numlockx && echo -e "${vert} [ OK ] installé et paramétré pour lightdm ${neutre}"
    sleep 2
fi

if [ $VERSION_OS = 'ubuntu' ] ; then # Ubuntu avec GDM3
    echo -e "\n##############################################\n"
    echo -e "${bleu}[ Configuration du pavé numérique ]${neutre}"
    sed -i '/exit 0/i \if [ -x /usr/bin/numlockx ]; then\nexec /usr/bin/numlockx on\nfi' /etc/gdm3/Init/Default && echo -e "${vert} [ OK ] installé et paramétré pour gdm3 Ubuntu ${neutre}"
    sleep 2
fi

######## COPIE DES FICHIERS DE CONF
# Modif des droits TMUX
echo -e "\n##############################################\n"
echo -e "${bleu}[ Configuration de TMUX ]${neutre}"
cp ./res/.tmux.conf /home/$utilisateur/
cp ./res/.tmux.conf /root/

chown $utilisateur: /home/$utilisateur/.tmux.conf && echo -e "${vert} [ OK ] TMUX Configuré ${neutre}"
sleep 2

# Conf vim
echo -e "\n##############################################\n"
echo -e "${bleu}[ Configuration de VIM ]${neutre}"
echo -e "syntax on\nset number\nset autoindent\nset tabstop=6\nset showmode\nset mouse=a" >> /etc/vim/vimrc && echo -e "${vert} [ OK ] VIM Configuré ${neutre}"
sleep 2


######## ARCHITECTURE DOSSIER   TRAVAIL FORENSIC

#    Cas d'anlyse Windows
#   ----------------------
echo -e "\n##############################################\n"
echo -e "${bleu}[ Création des dossiers qui contiendront les points de montages des disques, RAM, Artefacts Windows et Linux ]${neutre}"
mkdir -p /cases/{w_01,w_02,w_03,w_04}/{firefoxHistory,pst/PJ_outlook,prefetch,malware,mft,dump,evtx,timeline,hivelist,network,filecarving/{photorec,foremost}} && echo -e "${vert} [ OK ] accueil windows : /cases Configuré ${neutre}"
mkdir -p /mnt/{usb1,usb2,win1,win2,linux1,linux2,encase1-E01,encase2-E01,ram1,ram2} && echo -e "${vert} [ OK ] accueil windows : /mnt Configuré ${neutre}"


#    Cas d'analyse linux
#   ----------------------
mkdir -p /cases/{lx_01,lx_02,lx_03,lx_04}/{firefoxHistory,info_OS/{release,grub},cron,history/{cmd,viminfo},mail/{PJ_mail,},malware,dump,log,timeline,login_MDP,network/{ssh,},filecarving/{photorec,foremost}} && echo -e "${vert} [ OK ] accueil linux : /cases Configuré ${neutre}"
sleep 2

########  INSTALLER CLAMAV

echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer clamav et ses mises à jours ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    echo "Début de l'installation et des mises à jour :"
    apt install -y clamav && echo -e "${vert} [ OK ] Clamav installé ${neutre}"
    systemctl stop clamav-freshclam.service && echo -e "${vert} [ OK ] Arrêt du service Clamav ${neutre}"
    freshclam && echo -e "${vert} [ OK ] Mise à jour du service Clamav ${neutre}"
    systemctl start clamav-freshclam.service && echo -e "${vert} [ OK ] Démarrage du service Clamav ${neutre}"
else
    echo -e "${rouge}Pas d'installation de clamav${neutre}"
fi


######## INSTALL GDB-PEDA

echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer GDB et GDB-PEDA ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    # GDB-PEDA pour user
    git clone https://github.com/longld/peda.git /home/$utilisateur/peda
    echo "source /home/$utilisateur/peda/peda.py" >> /home/$utilisateur/.gdbinit  && echo -e "${vert} [ OK ] gdp-peda paramétré pour $utilisateur ${neutre}"

    # Pour root
    cp -r /home/$utilisateur/peda /root/peda
    echo "source /root/peda/peda.py" >> /root/.gdbinit  && echo -e "${vert} [ OK ] gdp-peda paramétré pour root ${neutre}"
else
    echo -e "${rouge}Pas d'installation de GDB et GDB-PEDA${neutre}"
fi

######################## INSTALLATION DE VOLATILITY 2.6 OU 3 #####################################"

echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer Volatility 2.6 ou volatility 3 ? ${neutre}"
echo "[ 1 ] - Installer Volatility 2.6"
echo "[ 2 ] - Installer Volatility 3"
echo "[ Autre touche ] - Pour pour ne pas installer volatility" 
read INSTALL


########    INSTALLER VOLATILITY 2.6



if [ "$INSTALL" = "1" ]
then
    echo -e "\n##############################################\n"
    echo -e "${bleu}[ Installation de Volatility 2.6 ... ]${neutre}"
    sleep 2
    # Préparation avant installation
    cd /home/$utilisateur/Documents/
    echo "Début de l'installation et des mises à jour de Volatility 2.6 :"
    echo "Installation des librairies"
    apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata  && echo -e "${vert} [ OK ] Modules afférent à Volatility 2.6 installés ${neutre}"
    sleep 1
    
    # Installation de python 2
    echo "Installation des outils python 2"
    apt install -y python2 python2.7-dev libpython2-dev
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
    python2 get-pip.py
    python2 -m pip install -U setuptools wheel  && echo -e "${vert} [ OK ] Outils python pour Volatility 2.6 installés ${neutre}"
    sleep 1
    
    # Installation des modules volatility
    echo "Install des dépendences"
    python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
    python2 -m pip install yara
    ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so  && echo -e "${vert} [ OK ] Dépendences de Volatility 2.6 installés ${neutre}"
    sleep 1
    
    # Téléchargement et Installation de volatility 2.6
    python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git  && echo -e "${vert} [ OK ] Volatility 2.6 installé ${neutre}"
    sleep 1
    
    # Configuration du PATH de env pour volatility
    echo "export PATH=/home/$utilisateur/.local/bin:"'$PATH' >> ~/.bashrc
    . ~/.bashrc && echo -e "${vert} [ OK ] PATH $utilisateur mis à jour ${neutre}"
    
    # Test
    vol.py -h
    vol.py --info
    
elif [ "$INSTALL" = "2" ]
then
    echo -e "\n##############################################\n"
    echo -e "${bleu}[ Installation de Volatility 3 ... ]${neutre}"
    sleep 2
    # Préparation avant installation
    cd /home/$utilisateur/
    echo "Début de l'installation et des mises à jour de Volatility 3:"
    echo "Installation des librairies"
    apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata  && echo -e "${vert} [ OK ] Modules afférent à Volatility 3 installés ${neutre}"
    sleep 1

    # Installation de python 3
    echo "Installation des outils python 3"
    apt install -y python3 python3-dev libpython3-dev python3-pip python3-setuptools python3-wheel git && echo -e "${vert} [ OK ] Outils python pour Volatility 3 installés ${neutre}"

    # Téléchargement et Installation de volatility 3
    git clone https://github.com/volatilityfoundation/volatility3.git
    mv volatility3 /home/$utilisateur/.volatility3
    cd /home/$utilisateur/.volatility3
    chmod -R 750 *
    chown -R $utilisateur: * && echo -e "${vert} [ OK ] Volatility 3 téléchargé ${neutre}"
    
    # Installation des modules volatility
    pip3 install -r requirements.txt
    
    # Configuration du PATH de env pour volatility 3
    echo "export PATH=/home/$utilisateur/.volatility3:"'$PATH' >> /home/$utilisateur/.bashrc
    echo "export PATH=/home/$utilisateur/.volatility3:"'$PATH' >> /root/.bashrc
    . /home/$utilisateur/.bashrc && echo -e "${vert} [ OK ] PATH $utilisateur mis à jour ${neutre}"
    . /root/.bashrc && echo -e "${vert} [ OK ] PATH root mis à jour ${neutre}"
    
    # Test
    vol.py -h
    vol.py --info
else
    echo -e "${rouge}Pas d'installation Volatility${neutre}"
fi


########    INSTALLER DES OUTILS REGRIPPER V3


echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer RegRipper3.0 ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    cd /home/$utilisateur/Documents/Debian11-Post_Install/
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
    sed -i "1i #!`which perl`" /usr/local/src/regripper/rip.pl.linux
    sed -i '2i use lib qw(/usr/lib/perl5/);' /usr/local/src/regripper/rip.pl.linux
    md5sum /usr/local/src/regripper/rip.pl.linux && echo -e "${vert} rip.pl a été créé"

    # Copier rip.pl.linux dans /usr/local/bin/rip.pl
    cp regripper/rip.pl.linux /usr/local/bin/rip.pl && echo -e "${vert}Succès /usr/local/src/regripper/rip.pl.linux copié dans /usr/local/bin/rip.pl${neutre}"
    /usr/local/bin/rip.pl  && echo -e "${vert}\nrip.pl a été mis dans : /usr/local/bin/rip.pl !\n\nLe fichier d'origine se trouve dans : /usr/local/src/regripper/rip.pl\n\n${neutre}"
else
    echo -e "${rouge}Pas d'installation RegRipper 3.0${neutre}"
fi

########    LES OUTILS DE BUREAUTIQUE
echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer le Outils Bureautiques : thunderbird / readpst / msgconvert ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    apt install -y libemail-outlook-message-perl pst-utils thunderbird  && echo -e "${vert} [ OK ] Outils Bureautique installés ${neutre}"
else
    echo -e "${rouge}Pas d'installation des outils de bureautique${neutre}"
fi

########    LES OUTILS DE DISQUES
echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer Outils de disque : guymager / qemu / suite ewf / hdparm et sdparm ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    apt install -y guymager qemu-utils libewf-dev ewf-tools hdparm sdparm && echo -e "${vert} [ OK ] Outils de disques installés ${neutre}"
else
    echo -e "${rouge}Pas d'installation des outils de disque${neutre}"
fi

########    QUELQUES LOGICIELS FORENSIC 

echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer les Outils de Timeline et Artefacts Windows : La suite plaso / ewf / olevba3 / prefetch / ShimCacheParser ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    # olevba3 # analyzeMFT.py
    pip install oletools analyzeMFT && echo -e "${vert} [ OK ] oletools analyzeMFT installés ${neutre}"
    sleep 1
    # getfattr # ewfacquire ...
    apt install -y pff-tools ewf-tools libewf-dev libewf2 attr && echo -e "${vert} [ OK ] pff-tools ewf-tools libewf-dev libewf2 attr installés ${neutre}"
    sleep 1
    # Suite plaso : # log2timeline.py # psort.py # psteal.py
    apt install -y plaso && echo -e "${vert} [ OK ] Suite plaso installés ${neutre}"
    sleep 1
    # prefetch.py
    pip3 install windowsprefetch && echo -e "${vert} [ OK ] windowsprefetch installés ${neutre}"
    sleep 1
    # ShimCacheParser.py 
    cd /home/$utilisateur/Documents/Debian11-Post_Install/
    unzip ./res/ShimCacheParser-master.zip 
    cp -r ShimCacheParser-master /home/$utilisateur/
    chmod -R 750 /home/$utilisateur/ShimCacheParser-master/ && echo -e "${vert} [ OK ] ShimCacheParser installé dans : /home/$utilisateur/ShimCacheParser-master/  ${neutre}"
    chown -R $utilisateur: /home/$utilisateur/ShimCacheParser-master/
    echo "export PATH=/home/$utilisateur/ShimCacheParser-master:$PATH" >> /home/$utilisateur/.bashrc
    source /home/$utilisateur/.bashrc
else
    echo -e "${rouge}Pas d'installation de suite forensic${neutre}"
fi

########    FORENSICS-ALL

echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer La suite forensics-all ? ( y / n )${neutre}"
echo -e "${violet}acct aesfix afflib-tools aircrack-ng arp-scan binwalk braa bruteforce-salted-openssl bruteforce-wallet brutespray btscanner bully capstone-tool ccrypt cewl chaosreader chkrootkit cowpatty crack or crack-md5 dc3dd de4dot dirb dislocker dnsrecon doona dsniff ed2k-hash exifprobe ext4magic extundelete ewf-tools fcrackzip forensic-artifacts forensics-colorize galleta grokevt hashid hashrat hydra john mac-robber magicrescue maskprocessor masscan mdk3 mdk4 medusa memdump metacam mfcuk mfoc missidentify myrescue nasty nbtscan ncat ncrack ndiff nmap o-saft ophcrack-cli outguess pasco patator  pff-tools pipebench pixiewps pnscan polenum pompem recoverdm  recoverjpeg reglookup rephrase rfdump rhash rifiuti rifiuti2  rkhunter rsakeyfind safecopy samdump2 scalpel scrounge-ntfs shed sleuthkit smbmap snowdrop ssdeep ssldump statsprocessor stegcracker steghide stegsnow sucrack tableau-parm tcpick testssl.sh undbx unhide unhide.rb vinetto wapiti wfuzz winregfs wipe xmount yara${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    apt install -y forensics-all && echo -e "${vert} [ OK ] forensics-all installé ${neutre}"
else
    echo -e "${rouge}Pas d'installation de suite forensics-all${neutre}"
fi


########    FORENSICS-EXTRA

echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer La suite forensics-extra ? ( y / n )${neutre}"
echo -e "${violet}ancient arc bfbtester bind9-dnsutils binutils brotli bruteforce-luks bzip2 cabextract chntpw clzip comprez crunch cryptmount curl dact dares dcfldd ddrutility dictconv diffstat disktype dmitry dtach erofs-utils ethstatus ethtool exif exiftags exiv2 fatcat fdupes foremost funcoeszz gddrescue gdisk geoip-bin gifshuffle heartbleeder hexcompare hexedit horst hping3 hwinfo imageindex inxi ipgrab ipv6toolkit jdupes less libimage-exiftool-perl lltdscan lrzip lshw lynis lz4 lzma lzop mblaze mboxgrep mc mdns-scan membernator memstat minizip mpack mscompress nasm nast ncompress netcat-openbsd netdiscover ngrep nstreams ntfs-3g nwipe openpace p7zip-full packit parted pcapfix pcaputils pdfcrack pecomato pev plzip png-definitive-guide pngcheck poppler-utils psrip rarcrack reaver rzip secure-delete sipcrack sipgrep sipvicious sngrep squashfs-tools-ng ssh-audit sslscan stepic sxiv tcpdump tcpflow tcpreplay tcptrace tcpxtract telnet testdisk tshark ugrep uni2ascii unzip wamerican wamerican-huge wamerican-insane wamerican-large wamerican-small wbrazilian wbritish wbritish-huge wbritish-insane wbritish-large wbritish-small wbulgarian wcanadian wcanadian-huge wcanadian-insane wcanadian-large wcanadian-small wcatalan weplab wesperanto wfaroese wfrench wgaelic wgerman-medical whatweb whois wirish witalian wmanx wngerman wpolish wportuguese wspanish wswedish wswiss wukrainian wzip xva-img xxd xz-utils zpaq${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    apt install -y forensics-extra && echo -e "${vert} [ OK ] forensics-extra installé ${neutre}"
else
    echo -e "${rouge}Pas d'installation de suite forensics-extra${neutre}"
fi


########    FORENSICS-EXTRA-GUI

echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer La suite forensics-extra-gui ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    apt install -y forensics-extra-gui && echo -e "${vert} [ OK ] forensics-extra-gui installé ${neutre}"
else
    echo -e "${rouge}Pas d'installation de suite forensics-extra-gui${neutre}"
fi

########    INSTALLATION DE VIRTUALBOX 6.1
echo -e "\n##############################################\n"
echo -e "${bleu}Voulez-vous installer Virtualbox ? ( y / n )${neutre}"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    # Téléchargement des clés
    echo -e "${bleu}[ ---- Début d'installation et de configuration Virtualbox ---- ]${neutre}"
    echo -e "${jaune}[ Téléchargement et ajout des clés publiques de virtualbox ]${neutre}"
    wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
    wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -

    # Modification de la source.list et mise à jour
    echo -e "${jaune}[ Modification des source.list ]${neutre}"
    if [ $VERSION_OS = 'ubuntu' ] ; then
        add-apt-repository "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib"
    fi
    if [ $VERSION_OS = 'debian' ] ; then
        echo "deb [arch=amd64] http://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib" >> /etc/apt/sources.list
    fi
    apt update && apt -y full-upgrade

    # Installation de virtualbox
    echo -e "${jaune}[ Installation de virtualbox ]${neutre}"
    apt install -y virtualbox-6.1 && echo -e "${vert} [ OK ] Virtualbox $vboxVersion installé ${neutre}"

    # Installation de l'Extension Pack
    vboxVersion=$(dpkg -l | grep -i virtualbox | awk -F " " '{print $3}' | egrep -o '([0-9]{1}\.){2}[0-9]{1,3}')
    echo -e "${jaune}[ Installation de l'extension Pack ]${neutre}"
    wget https://download.virtualbox.org/virtualbox/$vboxVersion/Oracle_VM_VirtualBox_Extension_Pack-$vboxVersion.vbox-extpack
    VBoxManage extpack install Oracle_VM_VirtualBox_Extension_Pack-$vboxVersion.vbox-extpack && echo -e "${vert} [ OK ] Extension Pack de Virtualbox $vboxVersion installée ${neutre}"

    # Configuration pour pouvoir utiliser l'USB
    echo -e "${jaune}[ Configuration de Virtualbox pour utiliser les clés USB ]${neutre}"
    usermod -aG vboxusers $utilisateur && echo -e "${vert} [ OK ] Utilisation de l'USB configuré ${neutre}"

    # Configuration pour le démarrage sur clé USB
    usermod -aG disk $utilisateur && echo -e "${vert} [ OK ] Configuration pour démarrage sur clé USB configuré ${neutre}"
    echo -e "${vert}[ ---- Fin d'installation et de configuration Virtualbox ---- ]${neutre}"
else
    echo -e "${rouge}Pas d'installation de Virtualbox${neutre}"
fi

########    FINALISATION

chmod -R 750 /home/$utilisateur/
chown -R $utilisateur: /home/$utilisateur/


echo -e "\n##############################################\n"
echo -e "${vert}---------- FIN D'INSTALLATION -----------${neutre}"
echo "Voulez-vous redemérrer maintenant pour valider tous les changements ? ( y / n )"
read INSTALL

if [ "$INSTALL" = "y" ]
then
    reboot
else
    echo -e "${violet}Il faudra redémarrer avant d'utiliser les applications${neutre}"
fi
















