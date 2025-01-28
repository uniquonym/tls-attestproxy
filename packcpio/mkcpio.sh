#!/bin/sh -e

BUSYBOX="$1"
# LINUX="$2"
PROXYBINARY="$3"

mkdir -p img/bin
cp init img/init
mkdir -p img/etc/udhcpc
cp udhcpc-script img/etc/udhcpc/default.script
cp "$PROXYBINARY" img/bin/tls-attestproxy
cp -R "$BUSYBOX"/* img/
mkdir -p img/lib/modules/6.12.9/kernel/drivers/char/
# Only required if TPM driver is module (it's currently built in).
# cp -R "$LINUX/lib/modules/6.12.9/kernel/drivers/char/tpm/" "img/lib/modules/6.12.9/kernel/drivers/char/"
cd img
find . -print0 | cpio --create --null --reproducible --format=newc --owner=+0:+0 > ../initrd.cpio
strip-nondeterminism ../initrd.cpio
mkdir -p "$out"
xz -c --check=crc32 <../initrd.cpio >"$out"/initrd.cpio.xz
