#!/bin/sh -e

LINUX=$1
INITRAM=$2

mkdir -p "$out"
mkdir -p bootfiles
cp $LINUX bootfiles/linux.xz
cp "$INITRAM/initrd.cpio.xz" bootfiles/initrd.cpio.xz

mkdir -p bootfiles/EFI/boot
grub-mkimage -O arm64-efi \
             -o bootfiles/EFI/boot/bootaa64.efi \
             -p "(hd0)/EFI/boot" \
             tpm fat normal boot linux configfile xzio gzio
cat >bootfiles/EFI/boot/grub.cfg <<_END_
set root=(hd0)
linux /linux.xz
initrd /initrd.cpio.xz
boot
_END_
grub-script-check bootfiles/EFI/boot/grub.cfg

# Size calculation based off the NixOS CD build process (nixpkgs/nixos/modules/installer/cd-dvd/iso-image.nix)
find . -exec touch --date=2000-01-01 {} +
# Round up to the nearest multiple of 1MB, for more deterministic du output
usage_size=$(( $(du -s --block-size=1M --apparent-size . | tr -cd '[:digit:]') * 1024 * 1024 ))
# Make the image 110% as big as the files need to make up for FAT overhead
image_size=$(( ($usage_size * 110) / 100 ))

IMAGE="$out/tlsattest-aarch64.rawdisk"
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
