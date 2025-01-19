#!/bin/sh -e

BUSYBOX=$1
LINUX=$2

mkdir -p /tmp/img
cp init /tmp/img/init
cp -R $BUSYBOX/* /tmp/img/
mkdir -p /tmp/img/lib/modules/6.12.9/kernel/drivers/char/
cp -R "$LINUX/lib/modules/6.12.9/kernel/drivers/char/tpm/" "/tmp/img/lib/modules/6.12.9/kernel/drivers/char/"
cd /tmp/img
find . -print0 | cpio --create --null --reproducible --format=newc --owner=+0:+0 >../initrd.cpio
strip-nondeterminism /tmp/initrd.cpio
mkdir -p "$out"
xz -c --check=crc32 </tmp/initrd.cpio >"$out"/initrd.cpio.xz
