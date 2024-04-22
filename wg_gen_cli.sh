#!/bin/bash


# for makecloud vps
swgp_json_wg0="/etc/swgp-go/server0.json"
swgp_json_wg3="/etc/swgp-go/server3.json"


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

function selectWGIntForClients {
wg_conf_num=$(ls /etc/wireguard/wg*.conf 2>/dev/null | wc -l)
if [[ $wg_conf_num -eq 0 ]]; then
	t_sel_wg=""
	echo
	echo -e "${red}No WG interface exist.${plain}"
	return
fi

wg_int_list_num=$(wg | grep interface | wc -l)
wg_int_def=$(wg | grep interface | head -1 | awk '{print $2}')

if [[ $wg_int_list_num -eq 1 ]]; then
	t_sel_wg=$(wg | grep interface | awk '{print $2}')
else
	createWGIntListForClients
	
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

function genClientConf {
cli_name=$1
t_wg_int=$2
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

function createWGIntListForClients {
t_list=""
j=0

readarray myArr <<< $(wg | grep interface | awk '{print $2}')
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


orig_path=$(pwd)
initialCheck

if [[ ! -z $1 ]]; then
	t_cli_name=$1
else
	t_cli_name="vpnuser_${my_rnd}"
fi

if [[ ! -z $2 ]]; then
	t_wg_int=$2
else
	simpleRND2 1 99
	t_wg_int="wg3"
fi

