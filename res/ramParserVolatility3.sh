#!/bin/bash

# Installer  openpyxl : pip3 install openpyxl   /   présent dans github     https://github.com/yakisyst3m/IFT-install_forensics_tools.git
# Avoir l'application csv2xlsx.py :         https://github.com/yakisyst3m/IFT-install_forensics_tools.git

utilisateur=$(grep 1000 /etc/passwd | awk -F ":" '{print $1}')
rouge='\e[1;31m'
vert='\e[1;32m'
#jaune='\e[1;33m'
bleu='\e[1;34m' 
#violet='\e[1;35m'
neutre='\e[0;m'
#bleufondjaune='\e[7;44m\e[1;33m'
#souligne="\e[4m"

cpt=1

versionPython=$(dpkg -l | grep -E "python3\.[0-9]" | awk -F " " '{print $3}' | uniq | grep -oE "3\.[0-9]")

for raw in $(ls *.raw) ; do
    cpt="$cpt"
    echo -e "\n${vert}=============================================     MACHINE EN COURS DE PARSING : $cpt        ===============================================${neutre}"
    echo -e "\n\t${vert}[ -- Voici l'image trouvée -- ]${neutre}\n"
    ls $raw
    echo -e "\n\t${rouge}Entrer le nom de machine pour créer le dossier d'export : ${neutre}\n"
    read UCNAME
    mkdir -p "$UCNAME"/{CSV,XLSX}

    # Extraire les info grâce à Volatility 3
    echo -e "${bleu}\n\t[ --    Volatility 3 :  Info MAchine    -- ]${neutre}"
        vol3.py -f $raw windows.info.Info |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_Info.csv

    echo -e "${bleu}\n\t[ --    Volatility 3 :  Processus    -- ]${neutre}"
        vol3.py -f $raw windows.pslist.PsList |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_PsList.csv
        echo -e "\n"
        vol3.py -f $raw windows.pstree.PsTree |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_PsTree.csv

    echo -e "${bleu}\n\t[ --    Volatility 3 :  Ruches    -- ]${neutre}"
        vol3.py -f $raw windows.registry.hivelist.HiveList |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_HiveList.csv
        echo -e "\n"
        vol3.py -f $raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run" |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_HiveList_Key_Run.csv
        echo -e "\n"
        vol3.py -f $raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\RunOnce" |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_HiveList_Key_RunOnce.csv

    echo -e "${bleu}\n\t[ --    Volatility 3 :  Réseau    -- ]${neutre}"
        vol3.py -f $raw windows.netscan.NetScan |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_NetScan.csv
        echo -e "\n"
        vol3.py -f $raw windows.netstat.NetStat |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_NetStat.csv
        echo -e "\n"
        vol3.py -f $raw windows.svcscan.SvcScan |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_SvcScan.csv

    echo -e "${bleu}\n\t[ --    Volatility 3 :  Lignes de commandes    -- ]${neutre}"
        vol3.py -f $raw windows.cmdline.CmdLine |  tee -a "$UCNAME"/CSV/RAM_"$UCNAME"_CmdLine.csv

    # Convertir les CSV en XLSX avec comme délimiteur "tab"
    for i in $(ls "$UCNAME"/CSV/*.csv) ; do
        python"$versionPython" /opt/csv2xlsx.py "$i"
        mv "$UCNAME"/CSV/*.xlsx "$UCNAME"/XLSX/
    done

    echo -e "\n${vert}=============================================     MACHINE $cpt TERMINÉE        ===============================================${neutre}"
    cpt=$(("$cp"+1))
done

chmod -R 750 "$UCNAME"/
chown "$utilisateur": "$UCNAME"/

# indows.bigpools.BigPools, windows.cachedump.Cachedump, windows.callbacks.Callbacks, windows.cmdline.CmdLine, windows.crashinfo.Crashinfo, windows.dlllist.DllList, windows.driverirp.DriverIrp, windows.driverscan.DriverScan, windows.dumpfiles.DumpFiles, windows.envars.Envars, windows.filescan.FileScan, windows.getservicesids.GetServiceSIDs, windows.getsids.GetSIDs, windows.handles.Handles, windows.hashdump.Hashdump, windows.info.Info, windows.ldrmodules.LdrModules, windows.lsadump.Lsadump, windows.malfind.Malfind, windows.memmap.Memmap, windows.mftscan.MFTScan, windows.modscan.ModScan, windows.modules.Modules, windows.mutantscan.MutantScan, windows.netscan.NetScan, windows.netstat.NetStat, windows.poolscanner.PoolScanner, windows.privileges.Privs, windows.pslist.PsList, windows.psscan.PsScan, windows.pstree.PsTree, windows.registry.certificates.Certificates, windows.registry.hivelist.HiveList, windows.registry.hivescan.HiveScan, windows.registry.printkey.PrintKey, windows.registry.userassist.UserAssist, windows.sessions.Sessions, windows.skeleton_key_check.Skeleton_Key_Check, windows.ssdt.SSDT, windows.statistics.Statistics, windows.strings.Strings, windows.svcscan.SvcScan, windows.symlinkscan.SymlinkScan, windows.vadinfo.VadInfo, windows.vadyarascan.VadYaraScan, windows.verinfo.VerInfo, windows.virtmap.VirtMap
