#!/bin/sh -e

TARGET=$1
LINUX=$2
INITRAM=$3
SIGNNSS=$4

mkdir -p "$out"
mkdir -p bootfiles

if [ "$TARGET" = "x86_64-linux" ]; then
    KERNEL=bzImage
    GRUBARCH=x86_64-efi
    ARCH=x86_64
    faketime '1970-01-01 00:00:00+00' pesign -s -i "$LINUX/bzImage" -o bootfiles/bzImage -n "$SIGNNSS" -c SNAKEOIL
else
    KERNEL=linux.xz
    GRUBARCH=arm64-efi
    ARCH=aarch64
    cp "$LINUX" bootfiles/linux.xz
fi

cp "$INITRAM/initrd.cpio.xz" bootfiles/initrd.cpio.xz

mkdir -p bootfiles/EFI/boot
grub-mkimage -O $GRUBARCH \
             -o boot.efi \
             -p "(hd0)/EFI/boot" \
             --disable-shim-lock \
             tpm fat normal boot linux configfile xzio gzio serial terminal
faketime '1970-01-01 00:00:00+00' pesign -s -i boot.efi -o boot-signed.efi -n "$SIGNNSS" -c SNAKEOIL

if [ "$TARGET" = "x86_64-linux" ]; then
  cp boot-signed.efi bootfiles/EFI/boot/bootx64.efi
else
  cp boot-signed.efi bootfiles/EFI/boot/bootaa64.efi
fi
  
cat >bootfiles/EFI/boot/grub.cfg <<_END_
serial --speed=115200 --unit=0
terminal_input serial
terminal_output serial
set root=(hd0)
linux /$KERNEL console=ttyS0,38400n8
initrd /initrd.cpio.xz
boot
_END_
grub-script-check bootfiles/EFI/boot/grub.cfg

mkdir -p bootfiles/state

# Size calculation based off the NixOS CD build process (nixpkgs/nixos/modules/installer/cd-dvd/iso-image.nix)
find . -exec touch --date=2000-01-01 {} +
# Round up to the nearest multiple of 1MB, for more deterministic du output
# Add 2 MB for persistent state (TPM objects etc...)
usage_size=$(( ($(du -s --block-size=1M --apparent-size . | tr -cd '[:digit:]') + 2) * 1024 * 1024 ))
# Make the image 110% as big as the files need to make up for FAT overhead
image_size=$(( ($usage_size * 110) / 100 ))

IMAGE="$out/tlsattest-$ARCH.rawdisk"
truncate --size=$image_size "$IMAGE"
mkfs.vfat --invariant -i 96502828 -n EFIBOOT "$IMAGE"

# Force a fixed order in mcopy for better determinism, and avoid file globbing
for d in $(find bootfiles -type d -printf '%P\n' | sort); do
  faketime "2000-01-01 00:00:00" mmd -i "$IMAGE" "::/$d"
done
for f in $(find bootfiles -type f -printf '%P\n' | sort); do
  mcopy -pvm -i "$IMAGE" "bootfiles/$f" "::/$f"
done


fsck.vfat -vn "$IMAGE"
