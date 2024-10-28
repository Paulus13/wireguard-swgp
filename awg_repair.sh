#!/bin/bash

log_path="/root/awg_repair"
log_file="${log_path}/awg_repair.log"
log_file_tmp="${log_path}/tmp.log"

mkdir -p $log_path


function initialCheck() {
if [ "$EUID" -ne 0 ]; then 
  write_log2 "running under non root user"
  exit
fi

if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
else
	write_log2 "Bad OS (not Ubuntu)"
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	write_log2 "Bad OS (old version Ubuntu)"
	exit
fi

if [[ "$os_version" -le 2004 ]]; then
	old_kern=1
	kern_type=1
elif [[ "$os_version" -le 2204 ]]; then
	old_kern=0
	kern_type=2
# elif [[ "$os_version" -le 2404 ]]; then
else
	old_kern=0
	kern_type=3
fi
}

function repairAWG {
if [[ -z $1 ]]; then
	case $kern_type in
	1)
		t_mod_ver="1.0.20240922"
		;;
	2)
		t_mod_ver="1.0.20240923"
		;;
	3)
		t_mod_ver="1.0.20240924"
		;;
	esac
else
	t_mod_ver=$1
fi

# if [[ $kern_type -eq 1 ]]; then
	# dkms build -m amneziawg -v 1.0.20240922
	# dkms install -m amneziawg -v 1.0.20240922
# elif [[ $kern_type -eq 2 ]]; then
	# dkms build -m amneziawg -v 1.0.20240923
	# dkms install -m amneziawg -v 1.0.20240923
# elif [[ $kern_type -eq 3 ]]; then
	# dkms build -m amneziawg -v 1.0.20240924
	# dkms install -m amneziawg -v 1.0.20240924
# fi

dkms build -m amneziawg -v $t_mod_ver
dkms install -m amneziawg -v $t_mod_ver

rmmod amneziawg
modprobe amneziawg

t_pwd=$(pwd)
awg_quick_line=$(ls /lib/systemd/system/awg-quick*)
cd /etc/systemd/system/multi-user.target.wants

if [ ! -z $awg_quick_line ]; then
	ls awg-quick* | awk -F@ '{print $2}' | while read t_awg_int; do
		systemctl restart awg-quick@${t_awg_int}
	done
fi
cd $t_pwd
}

function checkAWG {
bin_path_classic="/usr/bin/wg"
bin_path_awg="/usr/bin/awg"

serv_path_classic="/lib/systemd/system/wg-quick@.service"
serv_path_awg="/lib/systemd/system/awg-quick@.service"

modprobe wireguard
modprobe amneziawg
wg_module=$(dmesg | grep wireguard)
wg_module_awg=$(dmesg | grep amneziawg)

if [[ -z $wg_module ]]; then
	wg_class_inst=0
else
	wg_class_inst=1
fi

if [[ -z $wg_module_awg ]]; then
	awg_inst=0
else
	awg_inst=1
fi
}

function checkAWGDkms {
if [[ ! -f /usr/sbin/dkms ]]; then
	write_log2  "dkms not installed"
	return
fi
t_kern=$(uname -a | awk '{print $3}')
t_dkms=$(dkms status 2>/dev/null | grep amneziawg)
t_dkms_ver=$(dkms status 2>/dev/null | grep amneziawg | tail -n1 | awk '{print $1}' | awk -F/ '{print $2}' | sed 's/,$//')
t_dkms_kern=$(dkms status 2>/dev/null | grep amneziawg | grep $t_kern)

t_awg_service="/lib/systemd/system/awg-quick@.service"
t_awg_bin="/usr/bin/awg"
repair_need=0

if [[ ! -z $t_dkms && -z $t_dkms_kern ]]; then
	awg_inst=1
	awg_load=0
	repair_need=1
	
	echo
	write_log2 "DKMS module exist, but not for current kernel. Repair required, try to repair."
elif [[ -f $t_awg_service && -f $t_awg_bin && -z $t_dkms_kern ]]; then
	awg_inst=1
	awg_load=0
	repair_need=1
	
	echo
	write_log2 "AWG binary exist, but not loaded. Repair required, try to repair."
fi

if [[ $repair_need -eq 1 ]]; then
	repairAWG $t_dkms_ver
	
	t_dkms=$(dkms status | grep amneziawg)
	t_dkms_kern=$(dkms status | grep amneziawg | grep $t_kern)
	awg_module=$(dmesg | grep amneziawg)
	
	if [[ ! -z $t_dkms && ! -z $t_dkms_kern && ! -z $awg_module ]]; then
		write_log2 "repaired successfully"
	else
		write_log2 "repair not successfull"
	fi
else
	write_log2 "repair not needed"
fi
}


function checkWGDkms {
if [[ ! -f /usr/sbin/dkms ]]; then
	write_log2  "dkms not installed"
	return
fi
t_kern=$(uname -a | awk '{print $3}')
t_dkms=$(dkms status 2>/dev/null | grep wireguard)
t_dkms_kern=$(dkms status 2>/dev/null | grep wireguard | grep $t_kern)

t_obfus_service="/lib/systemd/system/wg-quick-local@.service"
t_obfus_bin="/usr/local/bin/wg"

if [[ ( ! -z $t_dkms && -z $t_dkms_kern ) || ( -f $t_obfus_service && -f $t_obfus_bin && -z $t_dkms_kern ) ]]; then
	wg_obfus_inst=1
	wg_obfus_load=0
	
	write_log2 "repair needed, try to repair"
	repairWGOBFUS
	
	t_dkms=$(dkms status | grep wireguard)
	t_dkms_kern=$(dkms status | grep wireguard | grep $t_kern)
	wg_module_obfus=$(dmesg | grep wireguard | grep obfuscate)
	
	if [[ ! -z $t_dkms && ! -z $t_dkms_kern && ! -z $wg_module_obfus ]]; then
		write_log2  "repaired successfully"
	else
		write_log2  "repair not successfull$"
	fi
else
	write_log2 "repair not needed"
fi
}

function write_log2 {
t_str=$1

my_date=$(date '+%d %b %Y %H:%M:%S')
t_out_str="${my_date}  ${t_str}"

if [[ ! -f $log_file ]]; then
	echo $t_out_str > $log_file
else
	echo $t_out_str >> $log_file
fi
}

function compactLog {
max_empty_log_lines=40
empty_log_lines=$(cat $log_file | grep -i "repair not needed" | wc -l)
if [[ $empty_log_lines -ge $max_empty_log_lines ]]; then
	last_lines_reboot=$(cat $log_file | tail -8 | grep -iv "repair not needed")
	if [[ -z $last_lines_reboot ]]; then
		cat $log_file | grep -iv "repair not needed" > $log_file_tmp
		cat $log_file | tail -8 >> $log_file_tmp
		mv $log_file_tmp $log_file
	else
		cat $log_file | grep -iv "repair not needed" > $log_file_tmp
		mv $log_file_tmp $log_file
	fi
fi

# log_lines_num=$(cat $log_file | wc -l)
# if [[ $log_lines_num -gt 200 ]]; then
	# grep -v "repair not needed" $log_file > $log_file_tmp
	# mv $log_file_tmp $log_file
# fi
}

function checkUptime {
up_main_val=$(uptime -p | awk '{print $2}')
up_main_unit=$(uptime -p | awk '{print $3}')

if [[ $up_main_val == "0" && $up_main_unit == "minutes" ]]; then
	write_log2 "reboot detected, pause 30 sec"
	sleep 30
fi
}

checkUptime
initialCheck
checkAWGDkms
compactLog