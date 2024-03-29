#!/bin/bash

log_path="/root/wg_repair"
log_file="${log_path}/wg_repair.log"
log_file_tmp="${log_path}/tmp.log"

mkdir -p $log_path

function initialCheck() {
if [ "$EUID" -ne 0 ]; then 
  write_log "running under non root user"
  exit
fi

if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
else
	write_log "Bad OS (not Ubuntu)"
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	write_log "Bad OS (old version Ubuntu)"
	exit
fi

if [[ "$os_version" -le 2004 ]]; then
	old_kern=1
else
	old_kern=0
fi
}

function repairWGOBFUS {
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
bin_path_classic="/usr/bin/wg"
bin_path_obfus="/usr/local/bin/wg"

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
fi
}

function checkWGDkms {
if [[ ! -f /usr/sbin/dkms ]]; then
	write_log  "dkms not installed"
	return
fi
t_kern=$(uname -a | awk '{print $3}')
t_dkms=$(dkms status | grep wireguard)
t_dkms_kern=$(dkms status | grep wireguard | grep $t_kern)

if [[ ! -z $t_dkms && -z $t_dkms_kern ]]; then
	wg_obfus_inst=1
	wg_obfus_load=0
	
	write_log "repair needed, try to repair"
	repairWGOBFUS
	
	t_dkms=$(dkms status | grep wireguard)
	t_dkms_kern=$(dkms status | grep wireguard | grep $t_kern)
	wg_module_obfus=$(dmesg | grep wireguard | grep obfuscate)
	
	if [[ ! -z $t_dkms && ! -z $t_dkms_kern && ! -z $wg_module_obfus ]]; then
		write_log  "repaired successfully"
	else
		write_log  "repair not successfull$"
	fi
else
	write_log "repair not needed"
fi
}

write_log() {
t_str=$1
t_str_up=$(echo $t_str | grep -i "repair not needed")

my_date=$(date '+%d %b %Y %H:%M:%S')
# t_day=$(date '+%d')
t_out_str="${my_date}  ${t_str}"

if [[ ! -f $log_file ]]; then
	echo $t_out_str > $log_file
	return
fi

rows_num=$(cat $log_file | wc -l)
last_row_day=$(tail -1 $log_file | awk '{print $1}')

if [ ! -z "$t_str_up" ]; then
	if [ -z "$rows_num" ]; then
		echo $t_out_str >> $log_file
	elif [ $rows_num -gt 1 ]; then
		last_str_up=$(tail -1 $log_file | grep -i "repair not needed" | awk '{print $4}')
		last_str_up2=$(tail -2 $log_file | grep -i "repair not needed" | grep -w "$last_row_day" | wc -l)
		if [[ ! -z "$last_str_up2" && $last_str_up2 -lt 2 ]]; then
			echo $t_out_str >> $log_file
		fi
		if [ ! -z "$last_str_up" ]; then
			grep -v "$last_str_up" $log_file > $log_file_tmp
			mv $log_file_tmp $log_file
		fi
		echo $t_out_str >> $log_file
	else
		echo $t_out_str >> $log_file
	fi
else
	echo $t_out_str >> $log_file
fi
}

function checkUptime {
up_main_val=$(uptime -p | awk '{print $2}')
up_main_unit=$(uptime -p | awk '{print $3}')

if [[ $up_main_val == "0" && $up_main_unit == "minutes" ]]; then
	write_log "reboot detected, wait 30 sec"
	sleep 30
fi
}

checkUptime
initialCheck
checkWGDkms