#!/bin/sh
MOD="kiomem"
DEV="/dev/$MOD"
rmmod "$MOD"
insmod "../${MOD}.ko"
MAJOR="$(awk '$2 == "kiomem"{print $1}' /proc/devices)"
mknod "$DEV" c "$MAJOR" 0
chmod 666 "$DEV"
