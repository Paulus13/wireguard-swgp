#!/bin/bash

script_path_share="/mnt/backup/scripts"
script_name_share="wg_repair.sh"
script_full_path_share="${script_path_share}/${script_name_share}"

script_path_local="/root/wg_repair"
script_name_local="wg_repair.sh"
script_full_path_local="${script_path_local}/${script_name_local}"

log_path="/root/wg_repair"
log_file="${log_path}/wg_repair.log"

function checkPrivNetAvailable {
p_loss=$(ping -qw 3 192.168.10.10 2>/dev/null | grep 'packet loss' | cut -d ' ' -f 6 | sed 's/%//')
if [[ $p_loss -eq 100 ]]; then
	net_avail=0
else
	net_avail=1
fi
}

function checkFSTab {
fstab_line=$(grep VPSBackup /etc/fstab)
if [[ ! -z $fstab_line ]]; then
	fstab_in=1
else
	fstab_in=0
fi
}

function checkNFSMount {
mount_line=$(df -h | grep VPSBackup)
if [[ ! -z $mount_line ]]; then
	nfs_mount=1
else
	nfs_mount=0
fi
}

function mountNFSBackup {
checkNFSMount
if [[ $nfs_mount -eq 0 ]]; then
	checkPrivNetAvailable
	if [[ $net_avail -eq 1 ]]; then
		checkFSTab
		if [[ $fstab_in -eq 1 ]]; then
			mount /mnt/backup
		else
			mount -o rw 192.168.10.10:/volume1/VPSBackup /mnt/backup
		fi
		
		checkNFSMount
		if [[ $nfs_mount -eq 1 ]]; then
			mount_success=1
			# echo "NFS backup folder mounted successfully" >> ~/backup.log
		else
			mount_success=0
			# echo "NFS backup folder not mounted" >> ~/backup.log
		fi
	else
		mount_success=0
		# echo "NFS backup folder not mounted" >> ~/backup.log
	fi
else
	mount_success=1
	# echo "NFS backup folder mounted successfully" >> ~/backup.log
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

echo $t_out_str >> $log_file
fi
}


mountNFSBackup

if [[ $mount_success -eq 1 ]]; then
	share_script_change_time=$(stat -c %Y $script_full_path_share)
	local_script_change_time=$(stat -c %Y $script_full_path_local)
	
	if [[ $share_script_change_time -gt $local_script_change_time ]]; then
		cp $script_full_path_share $script_full_path_local
		write_log "Script updated from share script folder"
	fi
fi

exec $script_full_path_local
