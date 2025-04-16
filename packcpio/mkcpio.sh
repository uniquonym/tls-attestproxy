#!/bin/sh -e

CLOSURE="$1"
# LINUX="$2"

mkdir -p img/bin
cp /proc/$$/exe img/bin/sh
cp init img/init
mkdir -p img/etc/udhcpc
cp udhcpc-script img/etc/udhcpc/default.script
export -p > img/etc/nixenv
# Only required if TPM driver is module (it's currently built in).
# mkdir -p img/lib/modules/6.12.9/kernel/drivers/char/
# cp -R "$LINUX/lib/modules/6.12.9/kernel/drivers/char/tpm/" "img/lib/modules/6.12.9/kernel/drivers/char/"
for FSITEM in $(cat $CLOSURE); do
    mkdir -p img/$FSITEM
    cp -r $FSITEM/ img/nix/store
done
cd img
find . -print0 | cpio --create --null --reproducible --format=newc --owner=+0:+0 --file=../initrd.cpio
strip-nondeterminism ../initrd.cpio
mkdir -p "$out"
xz -c --check=crc32 <../initrd.cpio >"$out"/initrd.cpio.xz
