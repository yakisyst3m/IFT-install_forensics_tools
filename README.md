![GitHub last commit](https://img.shields.io/github/last-commit/yakisyst3m/IFT-install_forensics_tools) 
![GitHub release-date](https://img.shields.io/github/release-date/yakisyst3m/IFT-install_forensics_tools)

# Non compatible avec DEBIAN 12 pour le moment !!  / Not compatible with DEBIAN 12 at the moment !!

#  IFT  [ INSTALL FORENSICS TOOLS ]
# Installation automatique des Outils Forensics
## Compatibilité :  
- **Ubuntu :** [ OK ]  
- **Debian 11 :** [ OK ]  

## 1 - Présentation :
**Script d'installation et de configuration des outils Forensics pour Debian et Ubuntu :**    
- Un menu est présent pour installer les outils qui vous intéressent !


## 2 - Installation :
- Lancer le programme : [ Lancer en **root** ]
  ```
  toto@debian:~$ chmod +x *.sh
  toto@debian:~$ sudo ./forencisTools.sh
  ```
<p align="center">
<img src="/img/iftv2.2-1.12 .png" alt="IFT MENU" width="1400"/>
</p>
  
## Quelques infos : Liste des Logiciels installés + exemples d'utilisation :
:radio_button: Reverse :
- gdb + gdb-peda
- radare2

:radio_button: Outils forensics :
- forensics-all
- forensics-extra
- forensics-extra-gui

:radio_button: Machines virtuelles / emulateurs:
- VirtualBox 7 + Extension Pack
- wine32 - wine64
- wine64-tools

:radio_button: Analyse Réseau :
- wireshark
- tshark
- tcpdump

:radio_button: Outils Réseau :
- nmap
- hping3
- wget
- curl
- whois
- nethogs
- net-tools
- arping

:radio_button: HDD :
- gparted
- parted
- testdisk
- guymager
- hdparm
- sdparm
- ImageMounter (montage auto des images .E01)  
*Exemple :*  
```
imout image.E01
```

:radio_button: Hexadécimal :
- wxhexeditor
- hexedit

:radio_button: Métadonnées :
- libimage-exiftool-perl `exiftool`

:radio_button: FileCarving (récupération de données) :
- foremost  
*Exemple :*  
```
foremost -v -t all -i usb.raw -o /cases/w_01/filecarving/foremost/
```
- photorec  
*Exemple :*  
```
photorec TP1-Disque.img 
```

:radio_button: Terminal :
- tmux

:radio_button: Mémoire Vive :
- volatility 2.6
```
vol2.py -h

```  
- volatility 3
```
vol3.py -h
``` 
- ramParserVolatility3
Placer toutes les images .raw des mémoires RAM dans un dossier et lancer l'application.  
L'application va faire l'export CSV et XLSX des résultats de chacun des plugins.  
```
ramParserVolatility3 -h
ramParserVolatility3 -d dossier
```  

:radio_button: Artefacts Windows - LES RUCHES :
- RegRipper 3.0 `Extraire et parser la base de registre`  
*Exemple : UserAssist ---> LISTE PROG LANCES PAR L'UTILISATEUR*
```
rip.pl –r /mnt/win1/Users/xxxxx/NTUSER.DAT –p userassist
```  
*Exemple : shellbags ---> PREFERENCES D'AFFICHAGE DOSSIERS + BUREAU / si Présence = l'utilisateur a parcouru le dossier*
```
rip.pl –r /mnt/win1/Users/xxxxx/AppData/Local/Microsoft/Windows/UsrClass.dat –p shellbags
```  
*Exemple : MRU - Docs récents ---> FICHIERS RECENTS*
```
rip.pl –r /mnt/win1/Users/xxxxx/NTUSER.DAT –p recentdocs
```  
*Exemple : USB ---> PERIPHERIQUES USB*
```
rip.pl –r /mnt/win1/Users/xxxxx/AppData/Local/Microsoft/Windows/UsrClass.dat –p usb
rip.pl –r /mnt/win1/Users/xxxxx/AppData/Local/Microsoft/Windows/UsrClass.dat –p usbdevices
rip.pl –r /mnt/win1/Users/xxxxx/AppData/Local/Microsoft/Windows/UsrClass.dat  –p usbstor
```
- prefetch.py `**APRES 10 secondes**  Les fichiers lancés sont placés automatiquement par Windows dans --> C:/Windows/Prefetch`  
*Exemple :*
```
prefetch.py -c -d /mnt/win1/Windows/Prefetch/ > /cases/w_01/prefetch/prefetch.csv
```
- ShimCacheParser.py `Exécutions lancées depuis le redémarrage + EXECUTABLES PARCOURUS`  
*Exemples : *
```
python2.7 ShimCacheParser.py –h
python2.7 ShimCacheParser.py –i [RUCHE]
python2.7 ShimCacheParser.py -i "/mnt/win1/Windows/System32/config/SYSTEM"| grep cssrs
```

:radio_button: Artefacts Windows - MFT / Timeline :
- fls (suite sleuthkit) ` Lister les fichiers + répertoires : au format BODY`
- mactime (suite sleuthkit) `Création d'une timeline à partir d'un fichier BODY`  
*Exemple création Timeline:*
```
fls -r -o [offset_partition] image.dd –m C: >> /cases/w_01/mft/mft_export.body
mactime –b –d /cases/w_01/mft/export.body > /cases/w_01/mft/mactime.csv
```
*Exemple Lister les fichiers et répertoires récemment supprimés :*
```
fls -d -r -o [offset_partition] Disque.img
```

- mmls (suite sleuthkit) `Rechercher l'Offset de la MFT`  
*Exemple de recherche Offset :*
```
mmls dump_disque.raw
```
- icat (suite sleuthkit) `Exporter un fichier/MFT à partir de son inode`  
*Exemple Export fichier MFT inode = 0 :*
```
icat -o [offset_partition] dump_disque.raw 0 > /cases/w_01/mft/mft.raw
```
- analyseMFT.py `Parser la MFT`  
*Exemple :*
```
analyzeMFT.py -f /cases/w_01/mft/mft.raw -o /cases/w_01/mft/mft.csv
```
- mft_dump (https://github.com/omerbenamram/mft) `Parser le fichier $MFT`  
fichier de sortie : JSON.
```
mft_dump <input_file>
mft_dump $MFT
```    
fichier de sortie : CSV.  
```
mft_dump -o csv <input_file>
```   
extraira tous les flux résidents dans MFT vers des fichiers dans <output_directory>.  
```
mft_dump --extract-resident-streams <output_directory> -o json <input_file>
``` 

- log2timeline (plaso) `Créer une timeline semi-auto en 2 étapes : étape 1/2`
- psort (plaso) `Créer une timeline semi-auto en 2 étapes : étape 2/2`  
*Exemple création Timeline:*
```
log2timeline.py --parsers mft /cases/w_01/timeline/timeline.plaso /cases/w_01/timeline/dump_disque.raw
psort.py -o l2tcsv -w /cases/w_01/timeline/timeline.csv /cases/w_01/timeline/timeline.plaso
```
- psteal (plasa) `Créer une timeline automatiquement !!!! Très LONG à générer - pas top`  
*Exemple création Timeline:*
```
psteal.py –source dump_disque.raw –o l2csv –w timeline.csv
```
- getfattr `Alternate Data Stream - Zone.identifier : PROVENANCE DU FICHIER : Internet ? confiance ou non ? `  
*Exemple Recherche de l'ADS:*
```
getfattr -Rn ntfs.streams.list <fichierAanalyser>
```
:radio_button: Analyse Malware :
- olevba `Analyse des fichiers OLE`  
*Exemple :*
```
olevba fichier.xls
ou
olevba3 fichier.xls
```
- clamav `Antivirus Linux`  
*Exemple :*
```
clamscan -r -i dossier/
clamscan -i fichier
```
*Mise à jour AV :*
```
sudo systemctl stop clamav-freshclam.service
sudo freshclam
sudo systemctl start clamav-freshclam.service
```

:radio_button: Artefacts Windows && Linux - Bases de données navigateurs :
- sqlite3  
*Exemple 1:*
```
sqlite3 -header -csv /home/toto/.mozilla/firefox/zvz8ux8q.default-esr/places.sqlite " select datetime(last_visit_date/1000000, 'unixepoch', 'localtime') AS last_visit_date, url from moz_places " > output.csv
```  
*Exemple Firefox Windows:*
```
chemin=$(find /mnt/win1/Users/ -name "places.sqlite") ; for nom in $(echo $chemin | awk -F "/" '{print $5 }') ; do sqlite3 -header -csv  $chemin " select datetime(last_visit_date/1000000, 'unixepoch', 'localtime') AS last_visit_date, url from moz_places " > /cases/w_01/firefoxHistory/Wn_histFfox-$nom-$(date +%s).csv \; 2>/dev/null ; done
```  
*Exemple Firefox Linux:*
```
chemin=$(find /mnt/linux1/home/ -name "places.sqlite") ; for nom in $(echo $chemin | awk -F "/" '{print $5 }') ; do sqlite3 -header -csv  $chemin " select datetime(last_visit_date/1000000, 'unixepoch', 'localtime') AS last_visit_date, url from moz_places " > /cases/w_01/firefoxHistory/lx_histFfox-$nom-$(date +%s).csv \; 2>/dev/null ; done
```

:radio_button: Export des boîtes mails :
- pff-tools ` Cela va créer un dossier par boîte mail`  
*Exemple :*
```
pffexport user@domaine.pst
```
:radio_button: Les outils bureautiques :
- pst-utils ` convertir une boîte mails .pst en boîte mails .eml `  
*Exemple :*
```
readpst -M -u -b -e toto.tutu@domaine.pst
```
- libemail-outlook-message-perl `convertir un message .msg en .eml`
```
msgconvert monMessage.msg
```
- thunderbird `Boîte mail Open Source`  

