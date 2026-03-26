#!/bin/bash
# ecryptfs_remount.sh
# Automatically mounts /home/pi/data.enc to /home/pi/data.view with your passphrase

# Configuration
ENC_DIR="/home/pi/data.enc"
DEC_DIR="/home/pi/data.view"
PASS="Bicdroid123"
ECRYPTFS_MODULE="/home/pi/ecryptfs/ecryptfs.ko"

# Function to mount
mount_ecryptfs() {
    echo "Mounting eCryptfs..."
    sudo mount -t ecryptfs "$ENC_DIR" "$DEC_DIR" -o "key=passphrase:passphrase_passwd=$PASS,\
ecryptfs_cipher=aes,\
ecryptfs_key_bytes=16,\
ecryptfs_passthrough=n,\
ecryptfs_enable_filename_crypto=n"
    if [ $? -eq 0 ]; then
        echo "Mounted successfully at $DEC_DIR"
    else
        echo "Mount failed!"
    fi
}

# Function to unmount and reload module
reload_module() {
    echo "Unmounting $DEC_DIR..."
    sudo umount "$DEC_DIR"
    echo "Removing eCryptfs module..."
    sudo rmmod ecryptfs
    echo "Reloading eCryptfs module..."
    sudo insmod "$ECRYPTFS_MODULE"
    echo "Module reloaded."
}

# Main
echo "Starting eCryptfs remount procedure..."
reload_module
mount_ecryptfs
echo "Done."