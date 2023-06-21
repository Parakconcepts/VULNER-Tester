#!/bin/bash
source PT-Functions.sh
function BANNER()
{
	figlet "VULNER Tester" 
	echo -e "ThinkCyber Cyberium Arena Penetration Testing Project:\nAutomated tool for Mapping LAN,Checking for Common Vulnerabilities and Testing for Weak Password"
	echo " ____________ _____________________"
	echo "|AUTHOR       : Olalekan Ilori     |"
	echo "|_____________ ____________________|"
	echo "|Student Code : s4                 |"
	echo "|_____________ ____________________|"
	echo "|Class Code   : Unit 0722          |"
	echo "|_____________:____________________|"
	echo "|Instructor   : David Shiffman     |"
	echo "|_____________ ____________________|"
	echo -e "  \n "
}

##CHECKING FOR PERMISSIONS BEFORE PROGRAM RUNS
if [ "$(whoami)" != "root" ]
then
	echo "[-] Exiting.. VULNER must run as root"
	exit
fi

##CHECKING FOR EXISTING/CREATING A LOCAL FOLDER(/TOOL) TO SAVE FILES
function WorkFOLDER()
{
	if [ -d TOOL ]
	then rm -r TOOL 
	fi
	mkdir TOOL
}
##FORMATING USER INTERFACE
function spacer1()
{
		echo "  " >> TOOL/REPORT.txt
}
function spacer2()
{
		echo "  " >> TOOL/REPORT.txt
		echo "  " >> TOOL/REPORT.txt
}
function DoubleDASH()
{
		echo "  " >> TOOL/REPORT.txt
		echo "[==============================]" >> TOOL/REPORT.txt
}
function shortDASH()
{
		echo "----------------------------" >> TOOL/REPORT.txt
}
function longDASH()
{
		echo "--------------------------------------------------------" >> TOOL/REPORT.txt
}
function starSPACE()
{
		echo "[***********************************************************]" >> TOOL/REPORT.txt
}
#ENUMERATING HOSTS WITH OPEN PORTS FOR RUNNING SERVICES
function ENUMSERVC() 							
{	for ips in $(cat TOOL/open_host.lst)
	do
	 echo " Scanning for services on $ips ...."
	 echo " Services Found on $ips ...." >>TOOL/serVersn.lst
	 echo " " >>TOOL/serVersn.lst
	 nmap -sV -p- $ips 2>/dev/null >>TOOL/serVersn.lst
	 spacer1
	 echo " Scan completed and report stored in /TOOL/serVersn.lst"
	 spacer1
	done
	echo "Report Of Services Found" >> TOOL/REPORT.txt
	cat TOOL/serVersn.lst|grep -B 1 open >> TOOL/REPORT.txt ##for record and possible reference later
}

### MAPPING NETWORK DEVICES, LIVE HOSTS AND OPEN PORTS

function NetMAPER()
{
	start=`date +%s`
	startime=`date +%T`
	clear
	echo "Starting Network Devices and Open Ports Mapping Operation..."
##FINDING THE LAN RANGE OF YOUR NETWORK
	s_nmask="$(ip -br addr show |grep -w eth0 |awk ' {print $3}')"
	echo "[*] Your LAN range is $s_nmask" >> TOOL/REPORT.txt
	DoubleDASH

##FINDING THE LIVE HOSTS IN YOUR NETWORK
	nmap -sn $s_nmask -oX TOOL/slan.xml >/dev/null
	host_lst="$(cat TOOL/slan.xml|grep ipv4|sed 's,\", ,g'|awk ' {print $3}')"
	echo "$host_lst" > TOOL/num.lst
	num1="$(cat TOOL/num.lst |wc -l)"
	echo "[*] Found $num1 live hosts on your LAN" >> TOOL/REPORT.txt
	spacer1

##SAVING OS VERSION FOUND ON HOSTS IN NETWORK INTO REPORT
	echo "Host          ---OS Type" >> TOOL/REPORT.txt
	shortDASH
	for i in $(cat TOOL/num.lst)
	do
	 versn="$(nmap -O $i |grep "OS CPE"|awk -F: '{print $4,$5}')"
	if [ -z "$versn" ]
	then
	 versn="OS Not Found"
	fi
	 echo "$i : $versn" >> TOOL/versn.lst
	done
	 cat TOOL/versn.lst >> TOOL/REPORT.txt
	 DoubleDASH
	if [ -a TOOL/mass_Scan.lst ]
	then
	 rm TOOL/mass_Scan.lst
	fi

##ENUMERATING HOSTS WITH OPEN PORTS IN YOUR LAN AND SAVING AS FILE IN CURRENT FOLDER
	echo "Enumerating hosts in $s_nmask  ... "
	echo "_____________________________________ "
	#longDASH
	
	for i in $(cat TOOL/num.lst)
	do 
	 echo " [*] Scanning $i for open ports ...."
	 masscan -p- $i --rate=15000 --banners 2>/dev/null >>TOOL/mass_Scan.lst
	 echo " [*] Scanning for open ports on $i completed."
	 echo " "
	done
	 echo ".......Results of scans for open ports stored in TOOL folder as mass_Scan.lst"
	 echo " "
	 longDASH

##CALCULATING THE TOTAL NUMBER OF OPEN PORTS AND NUMBER OF HOSTS WITH OPEN PORTS
	echo "$(cat TOOL/mass_Scan.lst |awk ' {print $6}')" > TOOL/open_portList.lst
	num2="$(cat TOOL/open_portList.lst |wc -l)"
	num3="$(cat TOOL/open_portList.lst|uniq -c|wc -l)"

##SAVING DETAILS HOSTS WITH OPEN PORTS INTO REPORT
	cat TOOL/open_portList.lst|uniq -c|awk '{print $2}' > TOOL/open_host.lst
	echo "[++] Found $num2 Open ports on $num3 hosts in your LAN " >> TOOL/REPORT.txt
	echo " " >> TOOL/REPORT.txt
	echo "Open ports found on the following hosts:" >> TOOL/REPORT.txt
    #echo "[+] $(cat open_host.lst)"
	for i in $(cat TOOL/open_host.lst);do  echo "[+] $i" >> TOOL/REPORT.txt;done

##ENUMERATING SERVICES RUNNING ON HOSTS WITH OPEN PORTS
	ENUMSERVC


##SCANNING FOR COMMON VULNERABILITIES OF OPEN PORTS
	for lhost in $(cat TOOL/open_host.lst)
	do
	 nmap  -sV  -F  $lhost -oX TOOL/lhost.xml >/dev/null
	 echo "______________________________________________________________________________________________" >>TOOL/lhostCVE.lst
	 echo "| " >>TOOL/lhostCVE.lst
	 echo "|                          [*][*]FOUND VULNERABILITIES FOR $lhost[*][*]" >>TOOL/lhostCVE.lst
	 #versn2="$(nmap -O $lhost |grep "OS CPE"|awk -F: '{print $4,$5}')"
	 searchsploit --nmap TOOL/lhost.xml 2>/dev/null >> TOOL/lhostCVE.lst
	done
	cat TOOL/lhostCVE.lst >> TOOL/REPORT.txt
	echo " "
	echo "Scanning for Vulnerabilities completed successfuly.."
	pathf="$(pwd)"
	echo "Details of common vulnerabilities found is stored in $pathf/TOOL as lhostCVE.lst"
	echo "Report of Entire Scan Stored in $pathf/TOOL/REPORT.txt"
	echo " "
	scandate=`date +%F_%T`
	stoptime=`date +%T`
	end=`date +%s`
	echo "Scan was concluded on: $scandate" >> TOOL/REPORT.txt
	echo "Scan start time: $startime" >> TOOL/REPORT.txt
	echo "Scan stop time: $stoptime" >> TOOL/REPORT.txt
	echo Total duration of scan was `expr $end - $start` seconds >> TOOL/REPORT.txt
	
	###DISPLAYING GENERAL STATISTICS ON TERMINAL
	spacerN
	echo " GENERAL SUMMARY OF NETWORK SCAN"
	longDASHn
	echo "[*] Your LAN range is $s_nmask"
	echo "[*] Found $num1 live hosts on your LAN"
	shwOPEN
	longDASHn
	echo "Report Of Services Found"
	cat TOOL/serVersn.lst|grep -B 1 open
	longDASHn
	TIMEStamp
}
##OPTIONAL SECTION FOR VIEWING COMMON VULNERABILITIES FOUND FOR EACH OS VERSIONS
function ListCVE()
{
	echo " "
	spacerN
	echo -e "Detected Common Vulnerabilities can be viewed from generated report \n"
	echo "Select OS Version to view OS-specific CVEs"
	echo " (01) linux"
	echo " (02) windows"
	echo " (03) vmware"
	echo " (04) unix "
	echo " (05) EXIT "
	echo "  "
	read -p " Enter a number to choose an OS version.. select option (05) to exit: " CHOICE
		case $CHOICE in
			1) 
				echo "[*][*]Found Vulnerabilities for linux"
				starSPACE
				cat TOOL/lhostCVE.lst|grep linux
				echo "  "
				read -p " Press (1) to return to Menu or (0) to Exit " OPN
			    clear
				case $OPN in
					1) 
						ListCVE
					;;
		
					2)
						exit
					;;
				esac
			;;
			2)
				echo "[*][*]Found Vulnerabilities for windows"
				starSPACE
				cat TOOL/lhostCVE.lst|grep windows
				echo "  "
				read -p " Press (1) to return to Menu or (0) to Exit " OPN
			    clear
				case $OPN in
					1) 
						ListCVE
					;;
		
					2)
						exit
					;;
				esac
			;;
			3)
				echo "[*][*]Found Vulnerabilities for vmware"
				starSPACE
				cat TOOL/lhostCVE.lst|grep vmware
				echo "  "
				read -p " Press (1) to return to Menu or (0) to Exit " OPN
			    clear
				case $OPN in
					1) 
						ListCVE
					;;
		
					2)
						exit
					;;
				esac
			;;
			
			4)
				echo "[*][*]Found Vulnerabilities for unix"
				starSPACE
				cat TOOL/lhostCVE.lst|grep unix
				echo "  "
				read -p " Press (1) to return to Menu or (0) to Exit " OPN
			    clear
				case $OPN in
					1) 
						ListCVE
					;;
		
					2)
						exit
					;;
				esac
			;;
			5)
				exit
			;;
		esac

}
function WEAKpassChck()
{
	wstart=`date +%s`
	wstartime=`date +%T`
##*****CHECKING FOR WEAK PASSWORD FUNCTION STARTS HERE******
START_PT

if [ $opChos == 1 ]
then
	chckWEB
elif [ $opChos == 2 ]
then
	chckIPadd
elif [ $opChos == 3 ]
then
	chckLAN
else
	echo " Enter digits 1, 2 or 3 to select options"
	sleep 5
	PROG_STARTS
fi

SELECT_USER
##making a choice of password list to use
echo "You need to provide password list to continue"
echo " 1 - Specify password list"
echo " 2 - Create custom password list"
echo " 0 - Exit"
read -p " Select from options 1 or 2 above or 0 to exit: " opPass

if [ $opPass == 1 ]
then
	SELECT_PASS
elif [ $opPass == 2 ]
then
	CREATE_PASS
elif [ $opPass == 0 ]
then
	START_PT
else
	echo "Enter 1 or 2 to proceed"
	SELECT_USER
fi

#displaying selected parameters
	echo "[==============================]"
	echo "Checking $Chost for weak passwords using following parameters:"
	echo "--------------------------------------------------------"
	echo " [*] Username list as  $wordlist"
	echo " [*] Password list as $passlist"
	echo "[==============================]"
CHKLOGIN
BRUTE_TEST
	wscandate=`date +%F_%T`
	wstoptime=`date +%T`
	wend=`date +%s`
	wTIMEStamp
}

function PROG_STARTS() #function to start running VULNER 
{
	clear
	BANNER
	echo -e "Initiate The VULNER Tester"
	echo -e " [01] - Map Network Device & Open Ports\n [02] - Check For Weak Password Usage"
	read -p "Which Operation Will You Like To Carry Out? Select '01' or '02' to proceed: " selFUNC
if [ "$selFUNC" == "01" ]
then
	NetMAPER
	ListCVE
elif [ "$selFUNC" == "02" ] 
then
	WEAKpassChck
else
	echo "Enter the right options to proceed....exiting "
	exit
fi
}
#####MAIN PROGRAM SEQUENCE STARTS HERE****
clear
BANNER
read -p "This Program will create a new folder called 'TOOL' in $(pwd) and overite any existing one, to coninue enter Yes(Y)/No(N):" PERMIT
if [ "$PERMIT" == "Y" ] || [ "$PERMIT" == "y" ]
then
	WorkFOLDER
	PROG_STARTS
elif [ "$PERMIT" == "N" ] || [ "$PERMIT" == "n" ]
then
	echo "________________________"
	echo ""
	echo "!!!!!!W A R N I N G!!!!!"
	echo "________________________"
	NoOVERWRITE
	START_PT
	WEAKpassChck
	#exit
fi
