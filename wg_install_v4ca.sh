#!/bin/bash

red='\033[1;31m'
green='\033[1;32m'
yellow='\033[1;33m'
plain='\033[0m'

# for makecloud vps
swgp_json_wg0="/etc/swgp-go/server0.json"
swgp_json_wg3="/etc/swgp-go/server3.json"

if [[ ! -z $1 ]]; then
	expert_func=$1
else
	expert_func="no_exp"
fi

function initialCheck() {
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
else
	echo "This script for Ubuntu 18.04 or higher. For other OS use original script"
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer."
	echo "This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os_version" -le 2004 ]]; then
	old_kern=1
else
	old_kern=0
fi
}

function selectExtIP() {
ext_ip=$(dig @resolver4.opendns.com myip.opendns.com +short -4)

if [ -z $ext_ip ]; then
	eth_def=$(ls /sys/class/net | awk '/^e/{print}' | head -n1)
	loc_ip=$(ip a | grep $eth_def | grep inet | awk '{print $2}' | sed 's/\/24//g')
	ext_ip=$loc_ip
fi

read -p "Enter your WAN IP (default $ext_ip): " ip_new

if [[ -z $ip_new ]]; then 
	ip_new=$ext_ip
fi

validIP $ip_new
until [[ $? -eq 0 ]]; do
	echo $ip_new "looks like not good IP"
	read -p "Enter the IP Address " ip_new
	validIP $ip_new
done
		
ip=$ip_new	
}

function getWanIP {
t_wan_ip=$(dig @resolver4.opendns.com myip.opendns.com +short -4)
if [[ -z $t_wan_ip ]]; then
	read wan_name < /etc/wireguard/wan_interface_name.var
	t_wan_ip=$(ip a | grep $wan_name | grep inet | awk '{print $2}' | sed -r 's/\/.+//g')
fi
}

# Проверка правильности IP-адреса:
# Способ применения:
#      validIP IP_АДРЕС
#      if [[ $? -eq 0 ]]; then echo good; else echo bad; fi
#   ИЛИ
#      if validIP IP_ADDRESS; then echo good; else echo bad; fi
#

function validIP() {
  local ip=$1
  local stat=1

  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($ip)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
      && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
  fi
  return $stat
}

function selectIP() {
if [[ $(ip -4 addr | grep inet | grep -vEc '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') -eq 1 ]]; then
	ip=$(ip -4 addr | grep inet | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
else
	number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	echo
	echo "What IPv4 address should the OpenVPN server use?"
	ip -4 addr | grep inet | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | nl -s ') '
	read -p "IPv4 address [1]: " ip_number
	until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
		echo "$ip_number: invalid selection."
		read -p "IPv4 address [1]: " ip_number
	done
	[[ -z "$ip_number" ]] && ip_number="1"
	ip=$(ip -4 addr | grep inet | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed -n "$ip_number"p)
fi
}

function simpleRND() {
	rnd_from=1
	rnd_to=200

	if [[ ! -z "$1" && -z "$2" ]]
		then rnd_from=$1
	fi

	if [[ ! -z "$1" && ! -z "$2" ]]
	then
		rnd_from=$1
		rnd_to=$2			
	fi
	
	rnd_mult=$(( 32767/($rnd_to-$rnd_from+1) ))
	my_rnd=$(( $rnd_from+$RANDOM/$rnd_mult))
}

function simpleRND2() {
	rnd_from=1
	rnd_to=200

	if [[ ! -z "$1" && -z "$2" ]]
		then rnd_from=$1
	fi

	if [[ ! -z "$1" && ! -z "$2" ]]
	then
		rnd_from=$1
		rnd_to=$2			
	fi

	my_rnd=$(($rnd_from+RANDOM%($rnd_to-$rnd_from+1)))
}

function manageMenuExp() {
	MENU_OPTION="menu"
	# echo
	# echo "WireGuard menu"
	echo 
	echo "What do you want to do?"
	echo "   1) Install WG (with obfuscate if posible)"	
	echo "   2) Create WG config"
	echo "   3) Create User config"
	echo "   4) Show User config"
	echo "   5) Create crontab job for repair WG"
	echo "   6) Firewall config"
	echo "   7) Clone WG interface with users from existing WG interface (*expert function)"
	echo "   8) Create obfuscate configs (*expert function)"
	echo "   9) Exit"
	# until [[ -z $MENU_OPTION || $MENU_OPTION =~ ^[1-8]$ ]]; do
	until [[ $MENU_OPTION =~ ^[1-9]$ ]]; do
		read -rp "Select an option [1-9]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		instWGOBFUS
		checkWGOBFUS 1
		MENU_OPTION=0
		manageMenuExp
		;;
	2)
		newWGInt
		MENU_OPTION=0
		manageMenuExp	
		;;
	3)
		newUserConf
		MENU_OPTION=0
		manageMenuExp
		;;	
	4)
		selectWGIntForClients
		showUserNew $t_sel_wg
		MENU_OPTION=0
		manageMenuExp
		;;
	5)
		configCrontab2
		MENU_OPTION=0
		manageMenuExp
		;;		
	6)
		iptablesSettings
		MENU_OPTION=0
		manageMenuExp		
		;;
	7)
		echo 
		echo "This option for cloning non obfuscate WG int"
		echo "to new WG int with obfuscate"
		echo "and cloning all existing users"
		selectWGInt
		newWGInt 1 $t_sel_wg
		MENU_OPTION=0
		manageMenuExp			
		;;
	8)
		doCreateObfusConfigs
		MENU_OPTION=0
		manageMenuExp		
		;;		
	9|"")
		exit 0
		;;
	esac
}

function manageMenuSimple() {
	MENU_OPTION="menu"
	# echo
	# echo "WireGuard menu"
	echo 
	echo "What do you want to do?"
	echo "   1) Install WG (with obfuscate if posible)"	
	echo "   2) Create WG config"
	echo "   3) Create User config"
	echo "   4) Show User config"
	echo "   5) Exit"
	# until [[ -z $MENU_OPTION || $MENU_OPTION =~ ^[1-5]$ ]]; do
	until [[ $MENU_OPTION =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		instWGOBFUS
		checkWGOBFUS 1
		MENU_OPTION=0
		manageMenuSimple
		;;
	2)
		newWGInt
		MENU_OPTION=0
		manageMenuSimple
		;;
	3)
		newUserConf
		MENU_OPTION=0
		manageMenuSimple	
		;;	
	4)
		selectWGIntForClients
		showUserNew $t_sel_wg
		MENU_OPTION=0
		manageMenuSimple
		;;
	5|"")
		exit 0
		;;
	esac
}

function selectWGInt {
wg_conf_num=$(ls /etc/wireguard/wg*.conf 2>/dev/null | wc -l)
if [[ $wg_conf_num -eq 0 ]]; then
	t_sel_wg=""
	echo
	echo -e "${red}No WG interface exist.${plain}"
	return
fi

wg_int_list_num=$(wg | grep interface | wc -l)
wg_int_def=$(wg | grep interface | sort | head -1 | awk '{print $2}')

if [[ $wg_int_list_num -eq 1 ]]; then
	t_sel_wg=$(wg | grep interface | sort | awk '{print $2}')
else
	createWGIntList
	
	echo 
	echo "This WG interfaces exist: $t_list"
	read -p "What interface use? default - $wg_int_def: " t_wg_int
	if [ -z $t_wg_int ]
	then
		 t_wg_int=$wg_int_def
	fi

	checkWGIntExist $t_wg_int
	until [[ $wg_int_exist -eq 1 ]]; do
		echo "$t_wg_int: invalid selection."
		read -p "What interface use? " t_wg_int
		checkWGIntExist $t_wg_int
	done
	t_sel_wg=$t_wg_int
fi
}

function selectWGIntForClients {
wg_conf_num=$(ls /etc/wireguard/wg*.conf 2>/dev/null | wc -l)
if [[ $wg_conf_num -eq 0 ]]; then
	t_sel_wg=""
	echo
	echo -e "${red}No WG interface exist.${plain}"
	return
fi

wg_int_list_num=$(wg | grep interface | wc -l)
wg_int_def=$(wg | grep interface | sort | head -1 | awk '{print $2}')

if [[ $wg_int_list_num -eq 1 ]]; then
	t_sel_wg=$(wg | grep interface | sort | awk '{print $2}')
else
	createWGIntListForClients
	if [[ $int_for_cl_nul -eq 1 ]]; then
		t_sel_wg=$def_int_cl
		echo 
		echo "This WG interface selected: $t_sel_wg"
		echo
	else
		echo 
		echo "This WG interfaces exist: $t_list"
		read -p "What interface use? default - $def_int_cl: " t_wg_int
		if [ -z $t_wg_int ]
		then
			 t_wg_int=$def_int_cl
		fi

		checkWGIntExist $t_wg_int
		until [[ $wg_int_exist -eq 1 ]]; do
			echo "$t_wg_int: invalid selection."
			read -p "What interface use? " t_wg_int
			checkWGIntExist $t_wg_int
		done
		t_sel_wg=$t_wg_int
	fi
fi
}

function checkWGIntExist {
t_int=$1
t_wg_line=$(wg | grep interface | grep $t_int)

if [[ -z $t_wg_line ]]; then
	wg_int_exist=0
else
	wg_int_exist=1
fi
}

function newClientDNS () {
	echo "Select a DNS server for the client, [ENTER] set to default: Google: "
	echo "   1) Google (8.8.8.8)"
	echo "   2) Cloudflare (1.1.1.1)"
	echo "   3) OpenDNS (208.67.222.222)"
	echo "   4) Quad9 (9.9.9.9)"
	echo "   5) AdGuard (94.140.14.14)"
	# echo "   6) Local VPN DNS ($serv_ip)"
	read -p "DNS server [1]: " t_dns
	until [[ -z "$t_dns" || "$t_dns" =~ ^[1-5]$ ]]; do
		echo "$t_dns: invalid selection."
		read -p "DNS server [1]: " t_dns
	done
		# DNS
	case "$t_dns" in
		1|"")
			cl_dns="8.8.8.8, 8.8.4.4"
		;;
		2)
			cl_dns="1.1.1.1, 1.0.0.1"
		;;
		3)
			cl_dns="208.67.222.222, 208.67.220.220"
		;;
		4)
			cl_dns="9.9.9.9, 149.112.112.112"
		;;
		5)
			cl_dns="94.140.14.14, 94.140.15.15"
		;;			
		# 6)
			# cl_dns=$serv_ip
		# ;;
	esac
}

function selectWAN() {
eth_num=$(ls /sys/class/net | awk '/^e/{print}' | wc -l)
eth=$(ls /sys/class/net | awk '/^e/{print}')
	
if [[ "$eth_num" -gt 1 ]]; then
	eth_def=$(ls /sys/class/net | awk '/^e/{print}' | head -n1)

	echo "In your system this network interfaces present:"
	echo $eth
	read -p "Enter the name of the WAN network interface ([ENTER] set to default: $eth_def ): " wan_int_name
	
	if [ -z $wan_int_name ]
	then
		wan_int_name=$eth_def
	fi
else
	wan_int_name=$eth
fi
}

function wgInstall() {
read -p "Install WG? [Y/n]: " inst_soft
if [ -z $inst_soft ]
then
	 inst_soft='Y'
fi

until [[ "$inst_soft" =~ ^[yYnN]*$ ]]; do
	echo "$inst_soft: invalid selection."
	read -p "Install WG? [y/n]: " inst_soft
done

if [[ "$inst_soft" =~ ^[nN]*$ ]]; then
	exit
else
	echo "Install WG"
fi

# if [[ "$os_version" = 1804 ]]; then
	# apt install software-properties-common -y
	# add-apt-repository ppa:wireguard/wireguard -y
	# apt update
	# apt install wireguard-dkms wireguard-tools qrencode iptables dnsutils -y
# fi

if [[ "$os_version" -ge 1804 ]]; then
	apt update
	apt install wireguard qrencode iptables dnsutils -y
fi

# checkForwarding
checkWGOBFUS
configWGInt "wg0" $wg_obfus_inst
}

function checkForwarding {
net_forward="net.ipv4.ip_forward=1"
t_forw=$(grep $net_forward /etc/sysctl.conf | grep -v "#")

if [ -z $t_forw ]; then
	sysctl -w  ${net_forward}
	sed -i "s:#${net_forward}:${net_forward}:" /etc/sysctl.conf
fi
}

function newWGInt {

# checkWGClassic
checkWGOBFUS 0

if [[ $wg_class_inst -eq 0 && $wg_obfus_inst -eq 0 ]]; then
	echo
	echo -e "${red}WG binarys not installed."
	echo -e "Install it before creating interface.${plain}"
	return
fi

if [[ -z $1 ]]; then
	t_clone=0
else
	t_clone=$1
fi

if [[ -z $2 ]]; then
	t_orig_int=""
else
	t_orig_int=$2
fi

max_wg_int_num=$(ls /etc/wireguard/wg*.conf 2>/dev/null | tail -1 | awk -F/ '{print $4}' | sed 's/.conf//g' | sed 's/wg//g')
if [ -z $max_wg_int_num ]; then
	t_wg_int_num=0
else
	t_wg_int_num=$((max_wg_int_num+1))
fi
new_wg_name="wg${t_wg_int_num}"

read -p "Create $new_wg_name interface? [Y/n]: " cr_int
if [ -z $cr_int ]
then
	 cr_int='Y'
fi

until [[ "$cr_int" =~ ^[yYnN]*$ ]]; do
	echo "$cr_int: invalid selection."
	read -p "Create $new_wg_name interface? [y/n]: " cr_int
done

if [[ "$cr_int" =~ ^[nN]*$ ]]; then
	echo "Opereation cancelled"
	exit
else
	echo "Creating $new_wg_name interface"
fi

# checkWGOBFUS
if [[ $wg_obfus_inst -eq 1 ]]; then
	read -p "Use obfuscate? [Y/n]: " t_obf_use
	if [ -z $t_obf_use ]
	then
		 t_obf_use='Y'
	fi

	until [[ "$t_obf_use" =~ ^[yYnN]*$ ]]; do
		echo "$t_obf_use: invalid selection."
		read -p "Use obfuscate?: " t_obf_use
	done
	
	if [[ "$t_obf_use" =~ ^[nN]*$ ]]; then
		t_obfus=0
	else
		t_obfus=1
	fi
else
	t_obfus=0
fi

if [[ $t_clone -eq 0 ]]; then
	configWGInt $new_wg_name $t_obfus
else
	cloneWGIntConf $new_wg_name $t_orig_int $t_obfus
fi
}

function configWGInt {
wg_int=$1
wg_obfus=$2
wg_int_num=$(echo $wg_int | sed 's/wg//g')

if [[ $wg_int_num -eq 0 ]]; then
	cli_conf_folder="clients"
else
	cli_conf_folder="clients${wg_int_num}"
fi

t_pwd=$(pwd)
cd /etc/wireguard
umask 077

serv_privkey=$( wg genkey )
serv_pubkey=$( echo $serv_privkey | wg pubkey )
serv_obfuskey=$( wg genpsk )

selectExtIP

getNearFreePort 53420

read -p "Enter the port, [ENTER] set to default: ${t_port}: " port
if [ -z $port ]
   then port=$t_port
fi

port_bind_line=$(ss -tuna | grep -w $port 2>/dev/null)
until [[ -z $port_bind_line ]]; do
	echo "port $port already in use"
	read -p "Enter the port: " port
	port_bind_line=$(ss -tuna | grep -w $port 2>/dev/null)
done

echo "IP =" $ip
echo "Port=" $port

t_ep="$ip:$port"

getFreeInternalIP "10.50.0.1"
read -p "Enter the server address in the VPN subnet (CIDR format), [ENTER] set to default: ${in_ip}: " serv_ip
if [ -z $serv_ip ]
	then serv_ip=$in_ip
else 
	validIP $serv_ip
	until [[ $? -eq 0 ]]; do
		echo $serv_ip "is not good IP"
		read -p "Enter the IP Address: " serv_ip
		validIP $serv_ip
	done  
fi

t_subnet=$(echo $serv_ip | grep -o -E '([0-9]+\.){3}')

newClientDNS

if [ ! -f ./wan_interface_name.var ]; then
	selectWAN
	echo $wan_int_name > ./wan_interface_name.var
else
	read wan_int_name < ./wan_interface_name.var
fi

cat > ./${wg_int}.conf << EOF
[Interface]
Address = $serv_ip
SaveConfig = false
PrivateKey = $serv_privkey
EOF

if [[ $wg_obfus -eq 1 ]]; then
	obfus_line="ObfuscateKey = $serv_obfuskey"
	echo $obfus_line >> ./${wg_int}.conf
else
	obfus_line=""
fi

cat >> ./${wg_int}.conf << EOF
ListenPort = $port
#PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $wan_int_name -j MASQUERADE;
#PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $wan_int_name -j MASQUERADE;
EOF

# cp -f ./${wg_int}.conf.def ./${wg_int}.conf

if [ -f /lib/systemd/system/wg-quick-local@.service ]; then
	wg_serv_name="wg-quick-local@${wg_int}.service"
else
	wg_serv_name="wg-quick@${wg_int}.service"
fi
systemctl enable $wg_serv_name

cd $t_pwd

read -p "Enter VPN user name, [ENTER] set to default: wg_user: " user_name
if [ -z $user_name ]; then
	user_name="wg_user"
fi
genClientConf $user_name $wg_int 1

if [[ $wg_int_num -eq 0 ]]; then
	iptablesSettings
else
	t_fw_conf=$(iptables-save | grep -w 22 | grep -iw accept)
	t_fw_line=$(iptables-save | grep -w $port | grep -iw accept)
	t_fw_changed=0
	
	if [[ -z $t_fw_conf ]]; then
		return
	fi
	
	if [[ -z $t_fw_line ]]; then
		iptables -A INPUT -p udp --dport $port -j ACCEPT
		t_fw_changed=1
	fi
	
	t_forw_line_i=$(iptables-save | grep -i forward | grep -i accept | grep -w wg+ | grep -w i)
	t_forw_line_o=$(iptables-save | grep -i forward | grep -i accept | grep -w wg+ | grep -w o)
	
	if [[ -z $t_forw_line_i ]]; then
		iptables -A FORWARD -i wg+ -j ACCEPT
		t_fw_changed=1
	fi
	
	if [[ -z $t_forw_line_o ]]; then
		iptables -A FORWARD -o wg+ -j ACCEPT
		t_fw_changed=1
	fi	
	
	if [[ -f /etc/iptables/rules.v4 && $t_fw_changed -eq 1 ]]; then
		netfilter-persistent save
		netfilter-persistent reload
	fi
fi
}

function getNearFreePort {
t_port=$1
port_bind_line=$(ss -tuna | grep -w $t_port 2>/dev/null)

until [[ -z $port_bind_line ]]
do 
	t_port=$(( t_port+1 ))
	port_bind_line=$(ss -tuna | grep -w $t_port 2>/dev/null)
done
}

function getFreeInternalIP {
if [ -z $1 ]; then
	simpleRND2 0 250
	oct3=$my_rnd
	
	def_ip="10.50.${oct3}.1"
else
	def_ip=$1
fi

max_wg_int=$(ls /etc/wireguard/wg*.conf 2>/dev/null | tail -1 )
if [[ ! -z $max_wg_int ]]; then
	t_ip_used_line="used"
	until [[ -z $t_ip_used_line ]]; do
		t_int_ip=$(cat $max_wg_int | grep Address | awk '{print $3}')
		t_int_ip1=$(echo $t_int_ip | awk -F. '{print $1}')
		t_int_ip2=$(echo $t_int_ip | awk -F. '{print $2}')
		t_int_ip3=$(echo $t_int_ip | awk -F. '{print $3}')
		t_int_ip4=1
		
		if [[ $t_int_ip1 -lt 100 ]]; then
			t_int_ip2=$(( t_int_ip2+1 ))
		else
			t_int_ip3=$(( t_int_ip3+1 ))
		fi
		
		in_ip="${t_int_ip1}.${t_int_ip2}.${t_int_ip3}.${t_int_ip4}"
		t_ip_used_line=$(ip a | grep -w $in_ip)
	done
else
	in_ip=$def_ip
	t_ip_used_line=$(ip a | grep -w $in_ip)
	until [[ -z $t_ip_used_line ]]; do
		simpleRND2 0 250
		oct3=$my_rnd
		
		in_ip="10.50.${oct3}.1"
		t_ip_used_line=$(ip a | grep -w $in_ip)
	done
fi
#echo $in_ip
}

function newUserConf {
wg_conf_num=$(ls /etc/wireguard/wg*.conf 2>/dev/null | wc -l)
if [[ $wg_conf_num -eq 0 ]]; then
	echo
	echo -e "${red}No WG interface exist."
	echo -e "Create it before creating user config.${plain}"
	return
elif [[ $wg_conf_num -eq 1 ]]; then
	wg_int_name=$(ls /etc/wireguard/wg*.conf | awk -F/ '{print $4}' | sed 's/.conf//g')
else
	selectWGIntForClients
	wg_int_name=$t_sel_wg
fi

wg_conf_ep_line=$(grep Endpoint /etc/wireguard/${wg_int_name}.conf)
if [[ ! -z $wg_conf_ep_line ]]; then
	echo
	echo -e "${red}${wg_int_name} - this interface not for external connections${plain}"
	echo -e "${red}Select another${plain}"
	return
fi
	
def_client_name="wg_user"
wg_int_num=$(echo $wg_int_name | sed 's/wg//g')

if [[ $wg_int_num -eq 0 ]]; then
	client_conf_path="/etc/wireguard/clients"
	client_conf_path_short="clients"
else
	client_conf_path="/etc/wireguard/clients${wg_int_num}"
	client_conf_path_short="clients${wg_int_num}"
fi

def_client_line=$(ls ${client_conf_path}/${def_client_name} 2>/dev/null)
if [ ! -z $def_client_line ]; then
	simpleRND2 1 99
	def_client_name="wg_user${my_rnd}"
fi

read -p "Enter VPN user name, [ENTER] set to default: $def_client_name: " user_name
if [ -z $user_name ]; then
	user_name=$def_client_name
fi
checkUserNew $user_name $wg_int_name

if [[ $user_check -eq 1 ]]; then
	echo "user $user_name already exist"
else
	genClientConf $user_name $wg_int_name 1
fi
}

function cloneWGIntSub {
t_peer_pub_key_line=$(head -$t_line_end $orig_int_conf_path | tail +$t_line_start | grep PublicKey)
t_peer_pre_key_line=$(head -$t_line_end $orig_int_conf_path | tail +$t_line_start | grep PresharedKey)
t_peer_allowed_ip_line=$(head -$t_line_end $orig_int_conf_path | tail +$t_line_start | grep AllowedIPs | grep -v ^#)
t_peer_allowed_ip=$(echo $t_peer_allowed_ip_line | awk '{print $ 3}')
t_peer_pre_key=$(echo $t_peer_pre_key_line | awk '{print $ 3}')

t_client_conf=$(grep $t_peer_pre_key $orig_client_conf_path/*/*.conf | awk -F: '{print $ 1}' )
t_client_name=$(echo $t_client_conf | awk -F/ '{print $ 5}')

t_peer_priv_key_line=$(grep PrivateKey $t_client_conf)
t_peer_addr_line=$(grep Address $t_client_conf)
t_peer_dns_line=$(grep DNS $t_client_conf)
t_peer_pub_key2_line=$(grep PublicKey $t_client_conf)
t_peer_preshare_key2_line=$(grep PresharedKey $t_client_conf)
t_peer_allowed_ip2_line=$(grep AllowedIPs $t_client_conf)
t_peer_ep_line=$(grep "Endpoint" $t_client_conf)

t_old_mask=$(echo $t_peer_addr_line | grep -o -E '([0-9]+\.){3}')
t_new_mask=$(echo $new_int_ip | grep -o -E '([0-9]+\.){3}')
new_peer_ip_line=${t_peer_addr_line/$t_old_mask/$t_new_mask}
new_peer_allowed_ip_line=${t_peer_allowed_ip_line/$t_old_mask/$t_new_mask}

t_old_port=$(echo $t_peer_ep_line | awk '{print $ 3}' | awk -F: '{print $ 2}')
new_peer_ep_line=${t_peer_ep_line/$t_old_port/$new_port}

echo "" >> $new_int_conf_path
echo "[Peer]" >> $new_int_conf_path
echo $t_peer_pub_key_line >> $new_int_conf_path
echo $t_peer_pre_key_line >> $new_int_conf_path
echo $new_peer_allowed_ip_line >> $new_int_conf_path

mkdir -p ${new_client_conf_path}/${t_client_name}
new_client_full_path=${new_client_conf_path}/${t_client_name}/${t_client_name}.conf

echo "[Interface]" > $new_client_full_path
echo  $t_peer_priv_key_line >> $new_client_full_path

if [[ $t_obfus -eq 1 ]]; then
	echo $t_obfus_line >> $new_client_full_path
fi

echo $new_peer_ip_line >> $new_client_full_path
echo $t_peer_dns_line >> $new_client_full_path
echo "" >> $new_client_full_path
echo "[Peer]" >> $new_client_full_path
echo $t_peer_pub_key2_line >> $new_client_full_path
echo $t_peer_preshare_key2_line >> $new_client_full_path
echo $t_peer_allowed_ip2_line >> $new_client_full_path
echo $new_peer_ep_line >> $new_client_full_path
echo "PersistentKeepalive = 25" >> $new_client_full_path
}

function cloneWGIntConf {
t_new_wg_int=$1
t_orig_wg_int=$2
t_obfus=$3

new_int_conf_path="/etc/wireguard/${t_new_wg_int}.conf"
orig_int_conf_path="/etc/wireguard/${t_orig_wg_int}.conf"

orig_wg_int_num=$(echo $t_orig_wg_int | sed 's/wg//g')
new_wg_int_num=$(echo $t_new_wg_int | sed 's/wg//g')
if [[ $orig_wg_int_num -eq 0 ]]; then
	orig_client_conf_path="/etc/wireguard/clients"
else
	orig_client_conf_path="/etc/wireguard/clients${orig_wg_int_num}"
fi
new_client_conf_path="/etc/wireguard/clients${new_wg_int_num}"

if [[ $t_obfus -eq 1 ]]; then
	checkSWGP $t_orig_wg_int
	if [[ $inst_swgp -eq 1 ]]; then
		t_obfus_key=$t_psk
	else
		generatePSK
		t_obfus_key=$gen_psk
	fi
	t_obfus_line="ObfuscateKey = ${t_obfus_key}"
fi

t_addr_line=$(grep Address $orig_int_conf_path)
t_save_line=$(grep SaveConfig $orig_int_conf_path)
t_priv_key_line=$(grep PrivateKey $orig_int_conf_path)
t_list_port_line=$(grep ListenPort $orig_int_conf_path)
t_obfus_key_line=$(grep ObfuscateKey $orig_int_conf_path)

if [[ ! -z $t_obfus_key_line ]]; then
	t_obfus_line=$t_obfus_key_line
fi

getFreeInternalIP
new_int_ip=$in_ip
t_int_ip=$(echo $t_addr_line | awk '{print $ 3}')
new_addr_line=${t_addr_line/$t_int_ip/$new_int_ip}

t_list_port=$(echo $t_list_port_line | awk '{print $ 3}')
getNearFreePort $t_list_port
new_port=$t_port
new_list_port_line=${t_list_port_line/$t_list_port/$new_port}

echo "Internal IP for $t_new_wg_int Interface: $new_int_ip"
echo "Port for $t_new_wg_int Interface: $new_port"

t_pwd=$(pwd)
cd /etc/wireguard
umask 077

# post_line_num=$(grep -n Post ${t_orig_wg_int}.conf | head -1 | awk -F: '{print $ 1}')

cat > $new_int_conf_path << EOF
[Interface]
$new_addr_line
SaveConfig = false
$t_priv_key_line
EOF

if [[ $t_obfus -eq 1 ]]; then
	echo $t_obfus_line >> $new_int_conf_path
fi
echo $new_list_port_line >> $new_int_conf_path

post_pos1=$(grep -n Post $orig_int_conf_path | head -1 | awk -F: '{print $ 1}')
post_pos2=$(grep -n Post $orig_int_conf_path | tail -1 | awk -F: '{print $ 1}')
cat $orig_int_conf_path | head -$post_pos2 | tail +$post_pos1 >> $new_int_conf_path

t_in_num=0
lines_num=$(cat $orig_int_conf_path | wc -l)
readarray myArr <<< $(grep -n Peer $orig_int_conf_path)
for i in ${myArr[@]}
do
	t_wg_peer=${i}
	t_in_num=$(( t_in_num + 1 ))
	t_peer_num=$(echo $t_wg_peer | awk -F: '{print $1}')
	
	if  [[ $t_in_num -gt 1 ]]; then
		t_line_start=$(( t_prev_peer_num+1 ))
		t_line_end=$(( t_peer_num-2 ))
		
		cloneWGIntSub
		
		echo "User $t_client_name cloned"
	fi
	t_prev_peer_num=$t_peer_num
done
t_line_start=$(( t_prev_peer_num+1 ))
t_line_end=$lines_num

cloneWGIntSub

echo "User $t_client_name cloned"
echo

if [ -f /lib/systemd/system/wg-quick-local@.service ]; then
	systemctl enable wg-quick-local@${t_new_wg_int}.service
else
	systemctl enable wg-quick@${t_new_wg_int}.service
fi

# Restart Wireguard
# serv_line=$(ls /etc/systemd/system/multi-user.target.wants/*@${t_new_wg_int}.service)
# serv_line_grep=$(echo $serv_line | grep "wg-quick-local")

# if [ -z $serv_line_grep ]; then
	# systemctl stop wg-quick@${t_new_wg_int}
	# systemctl start wg-quick@${t_new_wg_int}
# else
	# systemctl stop wg-quick-local@${t_new_wg_int}
	# systemctl start wg-quick-local@${t_new_wg_int}
# fi
serv_line=$(systemctl | grep wg-quick | grep service | grep "$t_new_wg_int" | awk '{print $1}')
systemctl restart $serv_line

cd $t_pwd

t_fw_conf=$(iptables-save | grep -w 22 | grep -iw accept)
t_fw_line=$(iptables-save | grep -w $new_port | grep -iw accept)
t_fw_changed=0

if [[ -z $t_fw_conf ]]; then
	return
fi

t_fw_changed=0
if [[ -z $t_fw_line ]]; then
	iptables -A INPUT -p udp --dport $new_port -j ACCEPT
	echo
	echo "Firewall rule for port $new_port added"
	t_fw_changed=1
fi

if [[ -f /etc/iptables/rules.v4 && $t_fw_changed -eq 1 ]]; then
	netfilter-persistent save
	netfilter-persistent reload
fi
echo
}

function genClientConf {
cli_name=$1
# cli_folder=$2
t_wg_int=$2
# t_first_client=$4
if [[ -z $3 ]]; then
	show_conf=0
else
	show_conf=$3
fi

wg_int_num=$(echo $t_wg_int | sed 's/wg//g')

if [[ $wg_int_num -eq 0 ]]; then
	cli_folder="clients"
else
	cli_folder="clients${wg_int_num}"
fi

cli_conf_folder="/etc/wireguard/${cli_folder}/${cli_name}"
cli_conf_full_path="${cli_conf_folder}/${cli_name}.conf"
cli_conf_full_path_swgp="${cli_conf_folder}/${cli_name}_obfus.conf"
int_conf_path="/etc/wireguard/${t_wg_int}.conf"

if [[ ! -d "/etc/wireguard/${cli_folder}" ]]; then
	t_first_client=1
else
	cli_num=$(ls /etc/wireguard/${cli_folder} | wc -l)
	if [[ $cli_num -eq 0 ]]; then
		t_first_client=1
	else
		t_first_client=0
	fi
fi

checkSWGP $t_wg_int
if [[ $inst_swgp -eq 1 ]]; then
	obfus_line_swgp="ObfuscateKey = ${t_psk}"
else
	obfus_line_swgp=""
fi

if [[ $t_first_client -eq 1 ]]; then
	t_priv_key_conf=$serv_privkey
	t_pub_key_conf=$serv_pubkey
	# t_dns_conf=$cl_dns
	t_dns_line_conf="DNS = ${cl_dns}"
	t_ep_conf=$t_ep
	t_subnet_conf=$t_subnet
	t_last_ip_conf=1
	obfus_line=$(cat $int_conf_path | grep ObfuscateKey)
else
	getAllWGParam $t_wg_int
fi

if [[ $inst_swgp -eq 1 ]]; then
	t_ep_host=$(echo $t_ep_conf | awk -F: '{print $1}')
	t_ep_conf_swgp="${t_ep_host}:${list_port}"
fi

mkdir -p $cli_conf_folder
umask 077

allow_ip="0.0.0.0/0, ::/0"

cli_preshared_key=$(wg genpsk)
cli_privkey=$(wg genkey)
cli_pubkey=$(echo $cli_privkey | wg pubkey)

t_ip=$((t_last_ip_conf+1))
cli_ip="${t_subnet_conf}${t_ip}/32"

cat > $cli_conf_full_path << EOF
[Interface]
PrivateKey = $cli_privkey
EOF

if [[ ! -z $obfus_line ]]; then
	echo $obfus_line >> $cli_conf_full_path
fi

cat >> $cli_conf_full_path << EOF
Address = $cli_ip
$t_dns_line_conf

[Peer]
PublicKey = $t_pub_key_conf
PresharedKey = $cli_preshared_key
AllowedIPs = $allow_ip
Endpoint = $t_ep_conf
PersistentKeepalive=25
EOF

cat >> $int_conf_path << EOF

[Peer]
PublicKey = $cli_pubkey
PresharedKey = $cli_preshared_key
AllowedIPs = $cli_ip
EOF

if [[ -z $obfus_line && ! -z $obfus_line_swgp ]]; then
cat > $cli_conf_full_path_swgp << EOF
[Interface]
PrivateKey = $cli_privkey
$obfus_line_swgp
Address = $cli_ip
$t_dns_line_conf

[Peer]
PublicKey = $t_pub_key_conf
PresharedKey = $cli_preshared_key
AllowedIPs = $allow_ip
Endpoint = $t_ep_conf_swgp
PersistentKeepalive=25
EOF
fi

# Restart Wireguard
# serv_line=$(ls /etc/systemd/system/multi-user.target.wants/*@${t_wg_int}.service)
# serv_line_grep=$(echo $serv_line | grep "wg-quick-local")

if [[ $t_first_client -eq 1 ]]; then
	serv_line=$wg_serv_name
	# systemctl enable $serv_line
	systemctl start $serv_line
else
	serv_line=$(systemctl | grep wg-quick | grep service | grep "$t_wg_int" | awk '{print $1}')
	systemctl restart $serv_line
fi

# if [ -z $serv_line_grep ]; then
	# systemctl stop wg-quick@${t_wg_int}
	# systemctl start wg-quick@${t_wg_int}
# else
	# systemctl stop wg-quick-local@${t_wg_int}
	# systemctl start wg-quick-local@${t_wg_int}
# fi

# Show QR config to display
if [[ $show_conf -eq 1 ]]; then
	echo
	echo "# Display $cli_name.conf QR Code"
	qrencode -t ansiutf8 < $cli_conf_full_path
	echo
	echo "# Display $cli_name.conf "
	cat $cli_conf_full_path
	
	if [[ -f $cli_conf_full_path_swgp ]]; then
		echo
		echo "# Display ${cli_name}_obfus.conf QR Code"
		qrencode -t ansiutf8 < $cli_conf_full_path_swgp
		echo
		echo "# Display ${cli_name}_obfus.conf "
		cat $cli_conf_full_path_swgp
	fi
fi
}

function convertSystemCtl {
wg_quick_local_line=$(ls /lib/systemd/system/wg-quick* | grep local)
t_pwd=$(pwd)
cd /etc/systemd/system/multi-user.target.wants

if [ ! -z $wg_quick_local_line ]; then
	ls wg-quick* | grep -v local | awk -F@ '{print $2}' | while read t_wg_int; do
		systemctl stop wg-quick@${t_wg_int}
		systemctl disable wg-quick@${t_wg_int}
		systemctl enable wg-quick-local@${t_wg_int}
		systemctl start wg-quick-local@${t_wg_int}
	done
fi

cd $t_pwd
}

function iptablesSettings() {
fw_line=$(iptables-save)
if [[ -z $fw_line ]]
	then fw_check="no"
	echo
	echo -e "${red}firewall not configured${plain}"
   
	read -p "Configure Firewall? [Y/n]: " fw
	if [ -z $fw ]
	then
	  fw='Y'
	fi
	
	until [[ "$fw" =~ ^[yYnN]*$ ]]; do
		echo "$fw: invalid selection."
		read -p "Configure Firewall? [y/n]: " fw
	done
	
	if [[ "$fw" =~ ^[yY]$ ]]; then		
		iptables -A INPUT -p tcp --dport 22 -j ACCEPT
		ssh_port=$(cat /etc/ssh/sshd_config | sed -n 's/^.*Port //p')
		if [[ $ssh_port -ne 22 ]]; then
			iptables -A INPUT -p tcp --dport $ssh_port -j ACCEPT
		fi
		
		iptables -P OUTPUT ACCEPT
		iptables -P FORWARD DROP
		iptables -P INPUT DROP

		addCommonRulesFirewall
		addMinimalRulesFirewall		
	fi
else
	fw_check="yes"
	fw_menu_opt="menu"
	fw_forw_rules_num=$(iptables-save | grep -iv docker | grep -w FORWARD | wc -l)
	fw_inp_rules_num=$(iptables-save | grep -iv docker | grep -w INPUT | wc -l)
	fw_masq_rules_num=$(iptables-save | grep -iv docker | grep -w MASQUERADE | wc -l)
	fw_docker_rules_num=$(iptables-save | grep -iw docker | wc -l)
	
	echo
	echo -e "${green}Firewall configured:"
	echo -e "	forward rules - ${fw_forw_rules_num}"
	echo -e "	input rules - ${fw_inp_rules_num}"
	echo -e "	docker rules - ${fw_docker_rules_num}"
	echo -e "	masquerade rules - ${fw_masq_rules_num}${plain}"
	
	echo 
	echo "   1) Full reconfigure Firewall (all rules will be removed)"
	echo "   2) Reconfigure Firewall except docker (docker rules will be saved, all other - removed)"	
	echo "   3) Add minimal WG rules"
	echo "   4) Add common rules"
	echo "   5) Add minimal WG + common rules"
	echo "   6) Nothing to do (Default)"
	until [[ -z "$fw_menu_opt" || "$fw_menu_opt" =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " fw_menu_opt
	done

	case $fw_menu_opt in
	1)
		reconfigureFirewall
		;;
	2)
		reconfigureFirewall
		;;		
	3)
		addMinimalRulesFirewall	
		;;
	4)
		addCommonRulesFirewall	
		;;	
	5)
		addCommonRulesFirewall
		addMinimalRulesFirewall	
		;;
	6|"")
		return
		;;		
	esac	
fi
}

function reconfigureFirewall {
read -p "Reconfigure Firewall? [y/N]: " re_fw
if [ -z $re_fw ]
then
  re_fw='N'
fi

until [[ "$re_fw" =~ ^[yYnN]*$ ]]; do
	echo "$re_fw: invalid selection."
	read -p "Configure Firewall? [y/n]: " re_fw
done

if [[ "$re_fw" =~ ^[yY]$ ]]; then
	iptables -F
	iptables -X
	iptables -t nat -F
	iptables -t nat -X
	iptables -t mangle -F
	iptables -t mangle -X

	iptables -A INPUT -p tcp --dport 22 -j ACCEPT

	ssh_port=$(cat /etc/ssh/sshd_config | sed -n 's/^.*Port //p')
	if [[ $ssh_port -ne 22 ]]; then
		iptables -A INPUT -p tcp --dport $ssh_port -j ACCEPT
	fi
	
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD DROP
	iptables -P INPUT DROP
	
	addCommonRulesFirewall
	addMinimalRulesFirewall
fi
}

function addMinimalRulesFirewall {
read -p "Add Minimal WG rules? [Y/n]: " t_fw
if [ -z $t_fw ]
then
  t_fw='Y'
fi

until [[ "$t_fw" =~ ^[yYnN]*$ ]]; do
	echo "$t_fw: invalid selection."
	read -p "Add Minimal WG rules? [y/n]: " t_fw
done

if [[ "$t_fw" =~ ^[yY]$ ]]; then
	if [ -z $wan_int_name ]
	then
		selectWAN
	fi
	
	t_fw_changed=0
	ssh_port=$(cat /etc/ssh/sshd_config | sed -n 's/^.*Port //p')
	t_ssh_line=$(iptables-save | grep -iw accept | grep -w 22)
	if [[ -z $t_ssh_line ]]; then
		iptables -A INPUT -p tcp --dport 22 -j ACCEPT
	fi

	if [[ $ssh_port -ne 22 ]]; then
		t_ssh_line=$(iptables-save | grep -iw accept | grep -w $ssh_port)
		
		if [[ -z $t_ssh_line ]]; then
			iptables -A INPUT -p tcp --dport $ssh_port -j ACCEPT
			t_fw_changed=1
		fi
	fi

	cat /etc/wireguard/wg*.conf | sed -n 's/^.*Port = //p' | while read t_port; do
		t_wg_line=$(iptables-save | grep -i udp | grep -i accept | grep -w $t_port)
		if [[ -z $t_wg_line ]]; then
			iptables -A INPUT -p udp --dport $t_port -j ACCEPT
			t_fw_changed=1
		fi
	done

	#wg | grep interface | awk '{print $2}' | while read t_wg; do
		t_forw_line_i=$(iptables-save | grep -i forward | grep -i accept | grep -w wg+ | grep -w i)
		t_forw_line_o=$(iptables-save | grep -i forward | grep -i accept | grep -w wg+ | grep -w o)
		
		if [[ -z $t_forw_line_i ]]; then
			iptables -A FORWARD -i wg+ -j ACCEPT
			t_fw_changed=1
		fi
		
		if [[ -z $t_forw_line_o ]]; then
			iptables -A FORWARD -o wg+ -j ACCEPT
			t_fw_changed=1
		fi
	#done

	t_masq_line=$(iptables-save | grep -iw masquerade | grep -w $wan_int_name )
	if [[ -z $t_masq_line ]]; then
		iptables -t nat -A POSTROUTING -o $wan_int_name -j MASQUERADE
		t_fw_changed=1
	fi

	if [[ $t_fw_changed -eq 1 ]]; then
		if [[ ! -f /etc/iptables/rules.v4 ]]; then
			echo "Iptables-persistent not installed"
			echo "Install it"
			echo 
			echo "Answer YES to the all questions during the installation of the package"
			
			apt-get update
			apt install -y iptables-persistent
		else
			echo "Iptables-persistent already installed"
			echo "Update FW rules files"
			netfilter-persistent save
			netfilter-persistent reload
		fi
	fi
fi
}

function addCommonRulesFirewall {
read -p "Add Common rules? [Y/n]: " t_fw
if [ -z $t_fw ]
then
  t_fw='Y'
fi

until [[ "$t_fw" =~ ^[yYnN]*$ ]]; do
	echo "$t_fw: invalid selection."
	read -p "Add Common rules? [y/n]: " t_fw
done

if [[ "$t_fw" =~ ^[yY]$ ]]; then
	json_serv_path="/etc/swgp-go/config.json"
	ssh_port=$(cat /etc/ssh/sshd_config | sed -n 's/^.*Port //p')

	if [ -z $wan_int_name ]
	then
		selectWAN
	fi

	if [ -f $json_serv_path ]; then
		swgp_port=$(grep proxyListen $json_serv_path | awk '{print $2}' | sed 's/[":,]//g')
	fi

	iptables -A INPUT -p icmp -j ACCEPT
	iptables -A INPUT -p tcp --dport 5202 -j ACCEPT
	iptables -A INPUT -p udp --dport 5202 -j ACCEPT
	
	t_ssh_line=$(iptables-save | grep -iw accept | grep -w 22)
	if [[ -z $t_ssh_line ]]; then
		iptables -A INPUT -p tcp --dport 22 -j ACCEPT
	fi

	if [[ $ssh_port -ne 22 ]]; then
		t_ssh_line=$(iptables-save | grep -iw accept | grep -w $ssh_port)
		
		if [[ -z $t_ssh_line ]]; then
			iptables -A INPUT -p tcp --dport $ssh_port -j ACCEPT
		fi
	fi

	if [ ! -z $swgp_port ]; then
		iptables -A INPUT -p udp -m udp --dport $swgp_port -j ACCEPT
	fi

	iptables -A INPUT -p udp --dport 1194 -j ACCEPT
	iptables -A INPUT -p tcp --dport 443 -j ACCEPT
	iptables -A INPUT -p tcp --dport 5555 -j ACCEPT
	iptables -A INPUT -p udp --dport 500 -j ACCEPT
	iptables -A INPUT -p udp --dport 1701 -j ACCEPT
	iptables -A INPUT -p udp --dport 4500 -j ACCEPT
	iptables -A INPUT -p 50 -j ACCEPT
	iptables -A INPUT -p 51 -j ACCEPT

	iptables -A INPUT -i lo -j ACCEPT
	iptables -A FORWARD -o lo -j ACCEPT

	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

	t_masq_line=$(iptables-save | grep -iw masquerade | grep -w $wan_int_name )
	if [[ -z $t_masq_line ]]; then
		iptables -t nat -A POSTROUTING -o $wan_int_name -j MASQUERADE
	fi

	iptables -A FORWARD -i tun0 -j ACCEPT
	iptables -A FORWARD -o tun0 -j ACCEPT

	if [ ! -f /etc/iptables/rules.v4 ]; then
		echo "Iptables-persistent not installed"
		echo "Install it"
		echo 
		echo "Answer YES to the all questions during the installation of the package"
		
		apt-get update
		apt install -y iptables-persistent
	else
		echo "Iptables-persistent already installed"
		echo "Update FW rules files"
		#iptables-save > /etc/iptables/rules.v4
		#ip6tables-save > /etc/iptables/rules.v6
		netfilter-persistent save
		netfilter-persistent reload
	fi
fi
}

function showUserConfigNew() {
t_user=$1
t_wg_int=$2

wg_int_num=$(echo $t_wg_int | sed 's/wg//g')

if [[ $wg_int_num -eq 0 ]]; then
	client_conf_path="/etc/wireguard/clients"
else
	client_conf_path="/etc/wireguard/clients${wg_int_num}"
fi

conf_path_full="${client_conf_path}/$t_user/$t_user.conf"

echo
echo -e "${green}$t_user${plain}"
echo
cat $conf_path_full
echo
qrencode -t ansiutf8 < $conf_path_full
echo

conf_obfus_path_full="${client_conf_path}/${t_user}/${t_user}_obfus.conf"
if [[ -f $conf_obfus_path_full ]]; then
	echo
	echo -e "${green}$t_user obfuscate config${plain}"
	echo
	cat $conf_obfus_path_full
	echo
	qrencode -t ansiutf8 < $conf_obfus_path_full
	echo
fi
}

function checkUserNew() {
user_name=$1
t_wg_int=$2

wg_int_num=$(echo $t_wg_int | sed 's/wg//g')

if [[ $wg_int_num -eq 0 ]]; then
	client_conf_path="/etc/wireguard/clients"
else
	client_conf_path="/etc/wireguard/clients${wg_int_num}"
fi

if [ -d $client_conf_path ]; then
	client_line=$(ls $client_conf_path | grep -x $user_name)
	if [[ -z $client_line ]]
	   then user_check=0
	else
		user_check=1
	fi
else
	user_check=0
fi
}

function showUserNew() {
t_wg_int=$1
if [[ -z $t_wg_int ]]; then
	return
fi

wg_int_num=$(echo $t_wg_int | sed 's/wg//g')

if [[ $wg_int_num -eq 0 ]]; then
	client_conf_path="/etc/wireguard/clients"
else
	client_conf_path="/etc/wireguard/clients${wg_int_num}"
fi

if [[ ! -d $client_conf_path ]]; then
	echo
	echo -e "${red}No users for this interface${plain}"
	return
fi

num_conf=$(ls $client_conf_path | wc -l)

if [[ $num_conf -eq 0 ]]; then
	echo
	echo -e "${red}No users for this interface${plain}"
	return
fi

if [[ $num_conf -eq 1 ]]; then
	tUser=$(ls $client_conf_path)
	showUserConfigNew $tUser $t_wg_int
else
	echo "Clients List:"
	ls --format=single-column --color=always $client_conf_path

	read -p "Enter Client Name: " cli_name
	if [ -z $cli_name ]; then
		echo "Client Name is empty. Exit"
		return
	fi
	
	checkUserNew $cli_name $t_wg_int
	
	if [[ $user_check -eq 1 ]]; then
		showUserConfigNew $cli_name $t_wg_int
	else
		echo "Client $cli_name not exists. Exit"
		return
	fi
fi
}

function checkSWGPServType {
t_serv_line=$(systemctl | grep "Simple WireGuard")
if [[ -z $t_serv_line ]]; then
	t_serv_conf=0
else
	t_serv_conf=1
	t_serv_line_type=$(echo $t_serv_line | grep @)
	if [[ -z $t_serv_line_type ]]; then
		swgp_serv_type=1
	else
		swgp_serv_type=2
	fi
fi
}

function checkSWGP() {
checkSWGPServType
if [[ $t_serv_conf -eq 0 ]]; then
	inst_swgp=0
	return
fi

if [[ -z $1 ]]; then
	t_wg_int_name="wg0"
	if [[ $swgp_serv_type -eq 1 ]]; then
		json_serv_path="/etc/swgp-go/config.json"
	elif [[ $swgp_serv_type -eq 2 ]]; then
		json_serv_path="/etc/swgp-go/server0.json"
	fi
else
	t_wg_int_name=$1
	if [[ $swgp_serv_type -eq 1 ]]; then
		json_serv_path="/etc/swgp-go/config.json"
	elif [[ $swgp_serv_type -eq 2 ]]; then
		t_wg_int_name_num=$(echo $t_wg_int_name | sed 's/wg//g')
		json_serv_path="/etc/swgp-go/server${t_wg_int_name_num}.json"
	fi
fi

if [ -f $json_serv_path ]; then
	inst_swgp=1
	list_port=$(grep proxyListen $json_serv_path | awk '{print $2}' | sed 's/[":,]//g')
	t_psk=$(grep proxyPSK $json_serv_path | awk '{print $2}' | sed 's/[":,]//g')
else
	inst_swgp=0
fi
}

function generatePSK() {
if [ -f /usr/bin/openssl ]; then
	gen_psk=$(openssl rand -base64 32)
elif [ -f /usr/bin/wg ]; then
	gen_psk=$(wg genpsk)
else
	apt install -y openssl
	gen_psk=$(openssl rand -base64 32)
fi
}

function instWGClassic {
checkWGClassic
if [[ $wg_class_inst -eq 1 ]]; then
	return
fi

read -p "Install WG classic? [Y/n]: " inst_soft
if [ -z $inst_soft ]
then
	 inst_soft='Y'
fi

until [[ "$inst_soft" =~ ^[yYnN]*$ ]]; do
	echo "$inst_soft: invalid selection."
	read -p "Install WG classic? [y/n]: " inst_soft
done

if [[ "$inst_soft" =~ ^[nN]*$ ]]; then
	return
fi

apt update && apt install -y wireguard wireguard-tools qrencode iptables dnsutils
}

function instWGOBFUS {
checkWGOBFUS
if [[ $wg_obfus_inst -eq 1 ]]; then
	echo 
	echo -e "${green}WG with obfuscate already installed.${plain}"
	return
fi

read -p "Install WG obfuscate? [Y/n]: " inst_soft
if [ -z $inst_soft ]
then
	inst_soft='Y'
fi

until [[ "$inst_soft" =~ ^[yYnN]*$ ]]; do
	echo "$inst_soft: invalid selection."
	read -p "Install WG obfuscate? [y/n]: " inst_soft
done

if [[ "$inst_soft" =~ ^[nN]*$ ]]; then
	exit
fi

if [[ $old_kern -eq 1 ]]; then
	if [ ! -f wireguard-linux-compat-swgp-dkms.tar.bz2 ]; then
		echo
		echo -e "Required file is missing."
		echo
		instWGClassic
		return
	fi
else
	if [ ! -f wireguard-dkms-swgp.tar.bz2 ]; then
		echo
		echo -e "Required file is missing."
		echo
		instWGClassic
		return
	fi
fi

if [ ! -f wireguard-tools-1.0.20210914-swgp.tar.bz2 ]; then
	echo
	echo -e "Required file is missing."
	echo
	instWGClassic
	return
fi

apt update && apt install -y dkms wireguard-tools qrencode iptables dnsutils
cd /usr/src
if [[ $old_kern -eq 1 ]]; then
	tar -xjf ${orig_path}/wireguard-linux-compat-swgp-dkms.tar.bz2
	dkms add -m wireguard -v 1.0.20240129
	dkms build -m wireguard -v 1.0.20240129
	dkms install -m wireguard -v 1.0.20240129
else
	tar -xjf ${orig_path}/wireguard-dkms-swgp.tar.bz2
	mv wireguard-dkms-swgp wireguard-1.0.20240124
	dkms add -m wireguard -v 1.0.20240124
	dkms build -m wireguard -v 1.0.20240124
	dkms install -m wireguard -v 1.0.20240124
fi

cd $orig_path
tar -xjf wireguard-tools-1.0.20210914-swgp.tar.bz2
cd wireguard-tools-1.0.20210914-swgp/src

make
cp wg /usr/local/bin
cp /usr/bin/wg-quick /usr/local/bin

cp /lib/systemd/system/wg-quick@.service /lib/systemd/system/wg-quick-local@.service
sed -i 's/\/usr\/bin\/wg/\/usr\/local\/bin\/wg/g' /lib/systemd/system/wg-quick-local@.service

rmmod wireguard
modprobe wireguard
}

function repairWGOBFUS {
if [[ -z $1 ]]; then
	force_mode=0
else
	force_mode=$1
fi

checkWGOBFUS

if [[ $force_mode -eq 0 ]]; then
	if [[ $wg_obfus_inst -eq 1 ]]; then
		return
	fi
fi

if [[ $old_kern -eq 1 ]]; then
	dkms build -m wireguard -v 1.0.20240129
	dkms install -m wireguard -v 1.0.20240129
else
	dkms build -m wireguard -v 1.0.20240124
	dkms install -m wireguard -v 1.0.20240124
fi

rmmod wireguard
modprobe wireguard

t_pwd=$(pwd)
wg_quick_local_line=$(ls /lib/systemd/system/wg-quick* | grep local)
cd /etc/systemd/system/multi-user.target.wants

if [ ! -z $wg_quick_local_line ]; then
	ls wg-quick-local* | awk -F@ '{print $2}' | while read t_wg_int; do
		systemctl restart wg-quick-local@${t_wg_int}
	done
fi
cd $t_pwd
}

function checkWGOBFUS {
if [[ -z $1 ]]; then
	echo_mode=0
else
	echo_mode=$1
fi

bin_path_classic="/usr/bin/wg"
bin_path_obfus="/usr/local/bin/wg"

serv_path_classic="/lib/systemd/system/wg-quick@.service"
serv_path_obfus="/lib/systemd/system/wg-quick-local@.service"

modprobe wireguard
wg_module=$(dmesg | grep wireguard)
wg_module_obfus=$(dmesg | grep wireguard | grep obfuscate)

if [[ -z $wg_module ]]; then
	wg_obfus_inst=0
	wg_class_inst=0
elif [[ ! -z $wg_module && -z $wg_module_obfus ]]; then
	wg_obfus_inst=0
	if [[ -f $bin_path_classic ]]; then
		wg_class_inst=1
	else
		wg_class_inst=0
	fi
elif [[ ! -z $wg_module && ! -z $wg_module_obfus ]]; then
	wg_obfus_inst=1
	if [[ -f $bin_path_classic ]]; then
		wg_class_inst=1
	else
		wg_class_inst=0
	fi
elif [[ -f $bin_path_obfus && -f $serv_path_obfus ]]; then
	wg_obfus_inst=1
	if [[ -f $bin_path_classic ]]; then
		wg_class_inst=1
	else
		wg_class_inst=0
	fi
fi

if [[ $echo_mode -eq 1 ]]; then
	if [[ $wg_obfus_inst -eq 1 ]]; then
		echo -e "${green}WG obfuscate installed${plain}"
	else
		echo -e "${red}WG obfuscate not installed${plain}"
	fi
fi
}

function checkWGDkms {
if [[ -z $1 ]]; then
	echo_mode=0
else
	echo_mode=$1
fi

if [[ ! -f /usr/sbin/dkms ]]; then
	if [[ $echo_mode -eq 1 ]]; then
		echo
		echo -e "${red}DKMS not installed${plain}"
	fi
	return
else
	echo
	echo -e "${green}DKMS installed${plain}"	
fi
t_kern=$(uname -a | awk '{print $3}')
t_dkms=$(dkms status | grep wireguard)
t_dkms_kern=$(dkms status | grep wireguard | grep $t_kern)

t_obfus_service="/lib/systemd/system/wg-quick-local@.service"
t_obfus_bin="/usr/local/bin/wg"
repair_need=0

if [[ ! -z $t_dkms && -z $t_dkms_kern ]]; then
	wg_obfus_inst=1
	wg_obfus_load=0
	repair_need=1
	
	echo
	echo -e "${red}DKMS module exist, but not for current kernel. Repair required.${plain}"
elif [[ -f $t_obfus_service && -f $t_obfus_bin && -z $t_dkms_kern ]]; then
	wg_obfus_inst=1
	wg_obfus_load=0
	repair_need=1
	
	echo
	echo -e "${red}Obfuscate binary exist, but not loaded. Repair required.${plain}"
fi

if [[ $repair_need -eq 1 ]]; then
	read -p "Repair WG obfuscate binary? [Y/n]: " t_repair
	if [ -z $t_repair ]
	then
		 t_repair='Y'
	fi

	until [[ "$t_repair" =~ ^[yYnN]*$ ]]; do
		echo "$t_repair: invalid selection."
		read -p "Repair WG obfuscate binary? [y/n]: " t_repair
	done

	if [[ "$t_repair" =~ ^[yY]*$ ]]; then
		repairWGOBFUS
		
		t_dkms=$(dkms status | grep wireguard)
		t_dkms_kern=$(dkms status | grep wireguard | grep $t_kern)
		wg_module_obfus=$(dmesg | grep wireguard | grep obfuscate)
		
		if [[ ! -z $t_dkms && ! -z $t_dkms_kern && ! -z $wg_module_obfus ]]; then
			echo -e "${green}Repaired successfully${plain}"
		else
			echo -e "${red}Repair not successfull${plain}"
		fi
	fi
fi
}

function checkWGClassic {
if [[ -f /usr/bin/wg ]]; then
	wg_class_inst=1
else
	wg_class_inst=0
fi
}

function checkKernel {
kern1=$(uname -a | awk '{print $3}' | awk -F- '{print $1}' | awk -F. '{print $1}')
kern2=$(uname -a | awk '{print $3}' | awk -F- '{print $1}' | awk -F. '{print $2}')
}

function createWGIntList {
t_list=""
readarray myArr <<< $(wg | grep interface | sort | awk '{print $2}')
for i in ${myArr[@]}
do 
	t_int=${i}
	t_list="$t_list $t_int"
done
}

function createWGIntListForClients {
t_list=""
j=0

readarray myArr <<< $(wg | grep interface | sort | awk '{print $2}')
for i in ${myArr[@]}
do 
	t_int=${i}
	checkWGIntForClients $t_int
	if [[ $wg_for_cl -eq 1 ]]; then
		t_list="$t_list $t_int"
		j=$j+1
		if [[ $j -eq 1 ]]; then
			def_int_cl=$t_int
		fi
	fi
done
int_for_cl_nul=$j
}

function checkWGIntForClients {
t_wg_int_cl=$1
wg_conf_ep_line=$(grep Endpoint /etc/wireguard/${t_wg_int_cl}.conf)
if [[ ! -z $wg_conf_ep_line ]]; then
	wg_for_cl=0
else
	wg_for_cl=1
fi
}

function showWGIntInfo {
wg_int_num=$(wg 2>/dev/null | grep interface | wc -l)
if [[ $wg_int_num -eq 0 ]]; then
	echo
	echo -e "${red}No WG Interfaces configured${plain}"
	return
elif [[ $wg_int_num -eq 1 ]]; then
	echo
	echo -e "${green}This WG Interface configured:${plain}"
else
	echo
	echo -e "${green}This WG Interfaces configured:${plain}"
fi

readarray myArr <<< $(wg | grep interface | awk '{print $2}' | sort)
for i in ${myArr[@]}
do
	t_int=${i}
	t_wg_int_num=$(echo $t_int | sed 's/wg//g')
	int_conf_path="/etc/wireguard/${t_int}.conf"

	if [[ $t_wg_int_num -eq 0 ]]; then
		client_conf_path="/etc/wireguard/clients"
	else
		client_conf_path="/etc/wireguard/clients${t_wg_int_num}"
	fi
	
	if [[ -d $client_conf_path ]]; then
		t_user_num=$(ls $client_conf_path | wc -l)
	else
		t_user_num=0
	fi

	obfus_line=$(cat $int_conf_path | grep ObfuscateKey)
	if [[ -z $obfus_line ]]; then
		t_obfus="off"
	else
		t_obfus="on"
	fi
	
	if [[ $t_obfus = "on" ]]; then
		echo -e "${green}${t_int} (obfuscate: ${t_obfus}, users: ${t_user_num})${plain}"
	else
		echo -e "${yellow}${t_int} (obfuscate: ${t_obfus}, users: ${t_user_num})${plain}"
	fi
done
}

function getAllWGParam {
t_int=$1
wg_int_num=$(echo $t_int | sed 's/wg//g')
int_conf_path="/etc/wireguard/${t_int}.conf"

if [[ $wg_int_num -eq 0 ]]; then
	client_conf_path="/etc/wireguard/clients"
else
	client_conf_path="/etc/wireguard/clients${wg_int_num}"
fi

obfus_line=$(cat $int_conf_path | grep ObfuscateKey)
if [[ ! -z $obfus_line ]]; then
	t_obfus_key_conf=$(echo $obfus_line | awk '{print $3}')
fi

t_priv_key_conf=$(cat $int_conf_path | grep PrivateKey | awk '{print $3}')
t_pub_key_conf=$(cat $client_conf_path/*/*.conf | grep PublicKey | head -1 | awk '{print $3}')
t_dns_line_conf=$(cat $client_conf_path/*/*.conf | grep DNS | head -1)
t_ep_conf=$(cat $client_conf_path/*/*.conf | grep Endpoint | head -1 | awk '{print $3}')

last_ip=$(cat $int_conf_path | grep AllowedIPs | grep -v "#" | tail -1 | awk '{print $3}' | sed 's/\/32//' | sed 's/,//')
last_ip1=$(echo $last_ip | awk -F. '{print $1}')
last_ip2=$(echo $last_ip | awk -F. '{print $2}')
last_ip3=$(echo $last_ip | awk -F. '{print $3}')
t_subnet_conf="$last_ip1.$last_ip2.$last_ip3."

t_last_ip_conf=$(echo $last_ip | awk -F. '{print $4}')
}

function showFirstInfo {
t_kern=$(uname -a | awk '{print $3}')
t_os_ver=$(cat /etc/os-release | grep PRETTY_NAME | awk -F= '{print $ 2}' | sed 's/"//g')
t_os_short_ver=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')

if [[ "$t_os_short_ver" -le 2004 ]]; then
	kern_type="Old kernel type"
else
	kern_type="New kernel type"
fi

echo 
echo -e "${green}${t_os_ver}${plain}"
echo -e "${green}${kern_type}: ${t_kern}${plain}"

checkWGOBFUS 1
showWGIntInfo
checkWGDkms 1
}

function configCrontab2() {
local exe_str="/root/wg_repair/wg_repair_launcher.sh"
checkCrontab

if [[ $cron_conf2 -eq 1 ]]; then
	cronMenu
	if [[ $delete_cron -eq 1 ]]; then
		delCron
		return
	elif [[ $reconfig_cron -eq 0 ]]; then
		return
	fi
else
	read -p "Configure Crontab for WG repair? [Y/n]: " cron
	if [[ -z $cron ]]; then
		cron='Y'
	fi

	until [[ "$cron" =~ ^[yYnN]*$ ]]; do
		echo "$cron: invalid selection."
		read -p "Configure Crontab? [y/n]: " cron
	done
fi

if [[ $cron_conf -eq 1 ]]; then
	grep -v $exe_str /var/spool/cron/crontabs/root | grep -v '^#' | grep -v '^$' > mycron
fi

if [[ "$cron" =~ ^[yY]$ ]]; then
	checkPrepare
	
	echo "@reboot  ${exe_str}" >> mycron
	echo "@hourly  ${exe_str}" >> mycron
	crontab mycron
	rm mycron 
	
	echo "Crontab configured"
	#crontab -l
fi
}

function delCron {
local exe_str="/root/wg_repair/wg_repair_launcher.sh"

grep -v $exe_str /var/spool/cron/crontabs/root | grep -v '^#' | grep -v '^$' > mycron
cron_line_num=$(cat mycron | wc -l)
if [[ $cron_line_num -eq 0 ]]; then
	crontab -r
else
	crontab mycron
fi
rm mycron
}

function checkCrontab() {
local exe_str="/root/wg_repair/wg_repair_launcher.sh"
if [ -f /var/spool/cron/crontabs/root ]; then
	cron_conf=1
	cron_line=$(grep "$exe_str" /var/spool/cron/crontabs/root)
	if [[ ! -z $cron_line ]]
		then cron_conf2=1
	fi
else
	cron_conf=0
	cron_conf2=0
fi
}

function checkPrepare() {
if [ ! -d ~/wg_repair ]; then
	mkdir ~/wg_repair
fi

if [[ ! -f ~/wg_repair/wg_repair.sh ]]; then
	if [[ ! -f wg_repair.sh ]]; then
		wget https://github.com/Paulus13/wireguard-swgp/raw/main/wg_repair.sh
	fi
	mv wg_repair.sh ~/wg_repair
	chmod +x ~/wg_repair/wg_repair.sh
else
	chmod +x ~/wg_repair/wg_repair.sh
fi

if [[ ! -f ~/wg_repair/wg_repair_launcher.sh ]]; then
	if [[ ! -f wg_repair_launcher.sh ]]; then
		wget https://github.com/Paulus13/wireguard-swgp/raw/main/wg_repair_launcher.sh
	fi
	mv wg_repair_launcher.sh ~/wg_repair
	chmod +x ~/wg_repair/wg_repair_launcher.sh
else
	chmod +x ~/wg_repair/wg_repair_launcher.sh
fi
}

function cronMenu() {
	MENU_OPTION="menu"
	# echo
	# echo "Crontab menu"
	echo 
	echo "What do you want to do?"
	echo "   1) Reconfigure crontab for WG repair"
	echo "   2) Delete crontab configuration for WG repair"
	echo "   3) Do Nothing"
	# until [[ -z $MENU_OPTION || $MENU_OPTION =~ ^[1-3]$ ]]; do
	until [[ $MENU_OPTION =~ ^[1-3]$ ]]; do
		read -rp "Select an option [1-3]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		reconfig_cron=1
		delete_cron=0
		;;
	2)
		reconfig_cron=1
		delete_cron=1
		;;
	3)
		reconfig_cron=0
		delete_cron=0
		;;		
	esac
}

function createObfusConfig {
if [[ -z $1 || -z $2 ]]; then
	return 1
else
	clien_conf_folder=$1
	t_conf_folder=$2
fi

t_obfus_line="ObfuscateKey = ${t_psk}"

full_conf_folder=${clien_conf_folder}/${t_conf_folder}
t_conf="${t_conf_folder}.conf"
t_bfus_conf="${t_conf_folder}_obfus.conf"

if [[ ! -f "${full_conf_folder}/${t_bfus_conf}" ]]; then
	if [[ -f "${full_conf_folder}/${t_conf}" ]]; then
		readarray lines < "${full_conf_folder}/${t_conf}"
		for line in "${lines[@]}";
		do
			priv_key_in=$(echo $line | grep PrivateKey)
			ep_in=$(echo $line | grep Endpoint)
			
			if [[ ! -z $priv_key_in ]]; then
				echo $line >> "${full_conf_folder}/${t_bfus_conf}"
				echo $t_obfus_line >> "${full_conf_folder}/${t_bfus_conf}"	
			elif [[ ! -z $ep_in ]]; then
				t_ip=$(echo $line | awk '{print $3}' | awk -F: '{print $1}')
				new_ep_line="Endpoint = ${t_ip}:${list_port}"
				# new_ep_line=$obfus_ep_line
				echo $new_ep_line >> "${full_conf_folder}/${t_bfus_conf}"
			else
				echo $line >> "${full_conf_folder}/${t_bfus_conf}"
			fi
		done
		echo "${t_bfus_conf} created"
	else
		echo "Folder $t_conf_folder does not contain conf file"
	fi
else
	echo "${t_bfus_conf} already exist"
fi
}

function doCreateObfusConfigs {
wg_conf_num=$(ls /etc/wireguard/wg*.conf 2>/dev/null | wc -l)
if [[ $wg_conf_num -eq 0 ]]; then
	echo
	echo -e "${red}No WG interface exist."
	echo -e "Create it before creating user config.${plain}"
	return
elif [[ $wg_conf_num -eq 1 ]]; then
	wg_int_name=$(ls /etc/wireguard/wg*.conf | awk -F/ '{print $4}' | sed 's/.conf//g')
else
	selectWGIntForClients
	wg_int_name=$t_sel_wg
fi

wg_int_num=$(echo $wg_int_name | sed 's/wg//g')

if [[ $wg_int_num -eq 0 ]]; then
	client_conf_path="/etc/wireguard/clients"
	client_conf_path_short="clients"
else
	client_conf_path="/etc/wireguard/clients${wg_int_num}"
	client_conf_path_short="clients${wg_int_num}"
fi

checkSWGP $wg_int_name
if [[ $inst_swgp -eq 0 ]]; then
	echo "SWGP not installed"
	return 1
fi

# getWanIP
# obfus_ep_line="Endpoint = ${t_wan_ip}:${list_port}"

for i in `ls $client_conf_path`
do
	createObfusConfig $client_conf_path ${i}
done
}

orig_path=$(pwd)
initialCheck
showFirstInfo
checkForwarding

exp_line1=$(echo $expert_func | grep -iw "exp")
exp_line2=$(echo $expert_func | grep -iw "expert")

if [[ ! -z $exp_line1 || ! -z $exp_line2 ]]; then
	manageMenuExp
else
	manageMenuSimple
fi