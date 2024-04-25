#!/bin/bash

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

function checkWGClassic {
if [[ -f /usr/bin/wg ]]; then
	wg_class_inst=1
else
	wg_class_inst=0
fi
}

function getVMName {
t_hostname=$(hostname)
if [ -f /root/vps_name.var ]; then
	read VM_NAME < /root/vps_name.var
else
	read -p "Enter VM name, [ENTER] set to default: ${t_hostname}: " VM_NAME
	if [ -z $VM_NAME ]; then
		VM_NAME=$t_hostname
	fi
	echo $VM_NAME > /root/vps_name.var
fi
}

function getWGConfig {
if [[ ! -f id_ed25519 ]]; then
	echo "Priv Key for connect not exist. Exit"
	exit
fi

chmod 600 id_ed25519
cp id_ed25519 /root/.ssh
chmod 600 /root/.ssh/id_ed25519

if [[ -f ./wg.conf ]]; then
	rm ./wg.conf
fi

getVMName
ssh root@45.67.32.79 -p 5234 "/root/wg/wg_gen_cli.sh "$VM_NAME" wg3" > ./wg.conf

if [[ ! -f ./wg.conf ]]; then
	echo "WG config not received. Exit"
	exit
fi
}

function makeRealWGConf {
genWGIntName

int_privkey_line=$(grep PrivateKey ./wg.conf)
int_addr_line=$(grep Address ./wg.conf)
peer_pubkey_line=$(grep PublicKey ./wg.conf)
peer_preshare_key_line=$(grep PresharedKey ./wg.conf)
peer_allow_ip_line="AllowedIPs = 10.50.13.0/24, 192.168.10.0/24"
ep_line="Endpoint = 127.0.0.1:${my_port_num}"

echo "[Interface]" > $my_wg_int_path
echo $int_privkey_line >> $my_wg_int_path
echo $int_addr_line >> $my_wg_int_path
echo "" >> $my_wg_int_path
echo "[Peer]" >> $my_wg_int_path
echo $peer_pubkey_line >> $my_wg_int_path
echo $peer_preshare_key_line >> $my_wg_int_path
echo $peer_allow_ip_line >> $my_wg_int_path
echo $ep_line >> $my_wg_int_path
echo "PersistentKeepalive=25" >> $my_wg_int_path
}

function genSWGPCliName {
	swgp_cli_conf_path="/etc/swgp-go"
	swgp_cli_conf_name="client.json"
	swgp_cli_conf_full_path="${swgp_cli_conf_path}/${swgp_cli_conf_name}"
	
	if [[ -f $swgp_cli_conf_full_path ]]; then
		swgp_cli_conf_exist=1
	else
		swgp_cli_conf_exist=0
	fi
	
	t_num=0
	until [[ $swgp_cli_conf_exist -eq 0 ]]; do
		t_num=$(( t_num+1 ))
		swgp_cli_conf_name="client${t_num}.json"
		swgp_cli_conf_full_path="${swgp_cli_conf_path}/${swgp_cli_conf_name}"
		
		if [[ -f $swgp_cli_conf_full_path ]]; then
			swgp_cli_conf_exist=1
		else
			swgp_cli_conf_exist=0
		fi
	done
}

function genSWGPCliName2 {
	swgp_cli_conf_path="/etc/swgp-go"
	num_cli=$(ls /etc/swgp-go/client*.json 2>/dev/null | wc -l)
	if [[ $num_cli -eq 0 ]]; then
		swgp_cli_conf_name="client.json"
		swgp_cli_conf_full_path="${swgp_cli_conf_path}/${swgp_cli_conf_name}"
	else
		max_num_cli=$(ls /etc/swgp-go/client*.json | tail -1 | awk -F/ '{print $4}' | sed 's/.json//' | sed 's/client//')
		if [[ -z $max_num_cli ]]; then
			my_num_cli=1
		else	
			my_num_cli=$(( max_num_cli+1 ))
		fi
		swgp_cli_conf_name="client${my_num_cli}.json"
		swgp_cli_conf_full_path="${swgp_cli_conf_path}/${swgp_cli_conf_name}"		
	fi
}

function genWGIntName {
max_num_wg=$(ls /etc/wireguard/wg*.conf | tail -1 | awk -F/ '{print $4}' | sed 's/.conf//' | sed 's/wg//')
my_num_wg=$(( max_num_wg+1 ))

my_wg_int="wg${my_num_wg}"
my_wg_int_path="/etc/wireguard/${my_wg_int}.conf"
}

function getFreeSWGPCliPort {
swgp_cli_num=$(ls /etc/swgp-go/client*.json 2>/dev/null | wc -l)
if [[ $swgp_cli_num -eq 0 ]]; then
	swgp_cli_free_port=20222
elif [[ $swgp_cli_num -eq 1 ]]; then
	max_port_num=$(grep wgListen /etc/swgp-go/client*.json | awk '{print $2}' | sed 's/[:",]//g')
	my_port_num=$(( max_port_num+1 ))
elif [[ $swgp_cli_num -gt 1 ]]; then
	max_port_num=$(grep wgListen /etc/swgp-go/client*.json | awk '{print $3}' | sed 's/[:",]//g' | sort | tail -1)
	my_port_num=$(( max_port_num+1 ))
fi
}

function createSWGPCliConf {
genSWGPCliName2
getFreeSWGPCliPort

cat > $swgp_cli_conf_full_path << EOF
{
    "clients": [
        {
            "name": "makecloud_ruvds",
            "wgListen": ":$my_port_num",
            "wgFwmark": 0,
            "wgTrafficClass": 0,
            "proxyEndpoint": "45.67.32.79:20220",
            "proxyMode": "zero-overhead",
            "proxyPSK": "f2aEwhlZVrujiXQ6S2q2hhZhjZSFaq4NPNsAKj6fVTE=",
            "proxyFwmark": 0,
            "proxyTrafficClass": 0,
            "mtu": 1500,
            "batchMode": "",
            "relayBatchSize": 0,
            "mainRecvBatchSize": 0,
            "sendChannelCapacity": 0
        }
    ]
}
EOF
}

function checkPrepareNFSMount {
mkdir -p /mnt/backup
nfs_installed=$(dpkg -l | grep nfs-common)
if [[ -z $nfs_installed ]]; then
	apt update
	apt install -y nfs-common
fi

mnt_line=$(cat /etc/fstab | grep VPSBackup)
if [[ -z $mnt_line ]]; then
	echo "192.168.10.10:/volume1/VPSBackup /mnt/backup nfs rw,noauto 0 0" >> /etc/fstab
fi
}


if [[ ! -f id_ed25519 ]]; then
	echo "Priv Key for connect not exist. Exit"
	exit
fi

checkWGClassic
if [[ $wg_class_inst -eq 0 ]]; then
	echo "Wireguard not installed, install it before run this script."
	exit
fi

checkSWGP
if [[ $inst_swgp -eq 0 ]]; then
	echo "SWGP not installed. Install and configure it before run this script."
	exit
fi

if [[ $swgp_serv_type -eq 1 ]]; then
	echo "SWGP installed, but service configured as type 1. Reconfigure it to type 2"
	exit	
fi

checkPrepareNFSMount

createSWGPCliConf
swgp_cli_name=$(echo $swgp_cli_conf_name | sed 's/.json//')
systemctl enable swgp-go@${swgp_cli_name}
systemctl start swgp-go@${swgp_cli_name}

getWGConfig
makeRealWGConf
systemctl enable wg-quick@${my_wg_int}
systemctl start wg-quick@${my_wg_int}