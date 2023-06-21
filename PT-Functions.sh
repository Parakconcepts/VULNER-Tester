#!/bin/bash

function longDASHn()    #function for formatting report
{
		echo "--------------------------------------------------------"
		echo " "
}
function spacerN()    #function for formatting report
{
		echo "_____________________________________________________"
		
}
#Functions Checking For Weak password Vulnerabilities In Host

#Selecting host to check for weak password
function chckLAN()			#selecting hosts from LAN scan
 {
	echo "Select Host to Test for password Vulnerability"
	count=0
	for i in $(cat TOOL/open_host.lst)
		do  
			let count+=1
			echo "[$count] $i"
		done
	echo " "
	read -p " Enter an IP address from list above to start test. Enter 0 to exit: " Chost
	if [ $Chost == 0 ]
	then
		exit  
	fi
	clear
 }
function chckWEB()		#selecting hosts using a domain name
 {
	echo " "
	read -p " Enter a Web url (without WWW) to start test. Enter 0 to exit: " Cdomain
	if [ $Cdomain == 0 ]
	then
		exit  
	fi
	Chost="$(nslookup $Cdomain |sed -n "6p"|awk '{print $2}')" ######grep for the ip
	clear
 }
 
function chckIPadd()		#selecting hosts using an IP address
 {
	echo " "
	read -p " Enter an IP address to start. Enter 0 to exit: " Chost
	if [ $Chost == 0 ]
	then
		exit  
	fi
	clear
 }
	
function CHKLOGIN()			#checking for login services on host selected
{
	echo "Checking for login services ....."
	nmap -sV -p- $Chost 2>/dev/null >>TOOL/sV.lst
	cat TOOL/sV.lst|grep -B 1 open >TOOL/opensV.lst			#greps from 1 line before the term open
	cat TOOL/opensV.lst|grep -B 1 open |grep -w "ssh\|ftp\|telnet\|rlogin\|vnc\|rdp\|smtp" >loginSrvc.lst #checking for login service
	loginSrvc="$(cat loginSrvc.lst|wc -l)"  #counting Number of login services
		
	if [ "$loginSrvc" == 0 ]
	then 
		echo " No Login service found"
	else
		echo " "
		echo "$loginSrvc Login services found "
		echo "--------------------------------------------------------" >> TOOL/REPORT.txt
		echo "$loginSrvc Login services found for host $Chost" >> TOOL/REPORT.txt
		longDASH
		echo "$(cat loginSrvc.lst)" >> TOOL/REPORT.txt
		#cat loginSrvc.lst
	fi
}

######function for specifying a user list
function SELECT_USER()
 {
  echo "Select List for Usernames"
  echo " "
  echo $(ls /usr/share/wordlists) > tryuser.lst
  nos=0

	if [ -a tryuser2.lst ]
		then
		rm tryuser2.lst
	fi
	for user in $(cat tryuser.lst|tr " " "\n"|grep "txt\|lst")
		do
			let nos+=1
			echo "($nos) $user" >>tryuser2.lst
		done
  cat tryuser2.lst
  read -p " Enter a number to choose a list . Enter 0 to exit: " Clist
	if [ $Clist == 0 ]
	then
		exit  
	fi
  listitem="$(cat tryuser2.lst|grep $Clist|awk '{print $2}')"  #determines list to use based on the number chosen as Clist
  wordlist="/usr/share/wordlists/$listitem"
  clear
 }

###########specifying a password list
function SELECT_PASS()
 {
	echo "Select List for Password"
	echo " "
#echo $(ls /usr/share/wordlists) > tryuser.lst
	if [ -a trypass.lst ] 
		then
		rm trypass.lst   #removing file if already existing
	fi
ncount=0
	for user in $(cat tryuser.lst|tr " " "\n"|grep "txt\|lst")
		do
			let ncount+=1
			echo "[$ncount] $user" >>trypass.lst
		done
	cat trypass.lst
	read -p " Enter a number to choose a list . Enter 0 to exit: " Cplist
	if [ $Cplist == 0 ]
	then
		exit  
	fi
plsitem="$(cat trypass.lst|grep $Cplist|awk '{print $2}')"
passlist="/usr/share/wordlists/$plsitem"
clear
 }

###########Creating password list
function CREATE_PASS()
 {
read -p " Enter a list of names seperated by comma to create a password list " PassList
echo "$PassList" > PassList.lst
cat PassList.lst|tr "," "\n" > pass.lst
 }

########Using Hydra to bruteforce and check for login
function BRUTE_TEST()
 {
	cat loginSrvc.lst|awk '{print $3}' >login.lst
	echo " "
	if [ "$loginSrvc" == 1 ]
	then
		service="$(cat login.lst)" 
		echo " Bruteforcing hosts for login...."
		#hydra -L $wordlist -P $passlist $Chost $service -t 5
		medusa -h $Chost -U $wordlist -P $passlist -M $service  -O medusaBRUTE.txt -b  > /dev/null
	else
		echo "$loginSrvc login services found, bruteforcing first login service"
		service="$(cat login.lst|head -1)"
		#hydra -L $wordlist -P $passlist $Chost $service -t 5
		medusa -h $Chost -U $wordlist -P $passlist -M $service -O medusaBRUTE.txt -b  > /dev/null	
	fi
	sucsChck="$(cat medusaBRUTE.txt|grep -i success|uniq |awk '{print $NF}')"
	if [ "$sucsChck" == "[SUCCESS]" ]
	then
		validName="$(cat medusaBRUTE.txt|grep -i success|uniq |awk '{print $7}')"
		validPass="$(cat medusaBRUTE.txt|grep -i success|uniq |awk '{print $9}')"
		echo "Successful login attempt found on $Chost using Username- $validName and Password- $validPass "
	else
		echo " "
		echo "No Weak login found on host/Network"
	fi

}

function START_PT()
{
clear
figlet -f small "Scan For Weak Passwords"
echo "Choose type of resource to scan"
echo " 1 - Web add"
echo " 2 - IP address"
echo " 3 - LAN hosts"
read -p " Select from options 1,2 or 3 above: " opChos
}
function NoOVERWRITE()
{
	echo -e "You have chosen not to create a new TOOL folder \nEnsure you have an existing TOOL folder before you continue"
	echo "Switching functions to check for weak login in 15 seconds.... ."
	sleep 15
}

function shwOPEN()
{
	longDASHn
	echo "[++] Found $num2 Open ports on $num3 hosts in your LAN "
	echo " "
	echo "Open ports found on the following hosts:"
    #echo "[+] $(cat open_host.lst)"
	for i in $(cat TOOL/open_host.lst);do  echo "[+] $i";done
}

function TIMEStamp()
{
	longDASHn
	echo "Last Scan was concluded at: $scandate"
	echo Scan start time: $startime
	echo Scan stop time: $stoptime
	echo Total duration of scan was `expr $end - $start` seconds.
}

function wTIMEStamp()
{
echo "Scan was concluded on: $scandate"
echo Scan start time: $wstartime
echo Scan stop time: $wstoptime
echo Total duration of scan was `expr $wend - $wstart` seconds.
}
