# How to build
The tls-attestproxy will obtain attestations that depend on the exact hash of
the built software - so it is essential that the built image is byte-for-byte equal
to what is expected.

tls-attestproxy is designed to run on aarch64 (ARM) cloud instances, but to be cross-compiled
from x86_64.

# Verifying the PCR hashes

The /binpcrlog can be downloaded from a running tls-attestproxy instance at path /binpcrlog.
This doesn't verify the value, but it provides the information needed to calculate the
correct hash and check the PCRs are legitimately supposed to have a given value.

Tools needed:

* tpm2-tools includes `tpm2_eventlog`.
* sha256sum
* pesign

Download the log file and analyse it with `tpm2_eventlog`.

The key is to check all the key steps for gaps that don't make sense.
Before the first `EV_SEPARATOR` is firmware - need to trust the cloud
provider has checked this is secure.

After the `EV_SEPARATOR` events, look for `EV_EFI_BOOT_SERVICES_APPLICATION`.

Mount a known good image (from a reproducible build matching what will
run in prod) with mount (it is a fat32 image).
Check the bootloader EFI is legitimate. e.g. if you mounted the image
at `/tmp/test`, use: `pesign --hash -i /tmp/test/EFI/boot/bootaa64.efi`.

The hash should match the digest on the `EV_EFI_BOOT_SERVICES_APPLICATION`
event exactly.

Look for the EV_IPL line with "(hd0)/EFI/boot/grub.cfg\0". Check the digest
matches the output for sha256sum over EFI/boot/grub.cfg (e.g. sha256sum /tmp/test/EFI/boot/grub.cfg).

Expect to see grub_cmds matching what is in grub.cfg.

Check the EV_IPL with "/linux.xz\0" - the digest should match what you calculate
with sha256sum from linux.xz in the mounted image.

Likewise the event with string "/initrd.cpio.xz\0" should match the sha256sum
for that file.

After that, expect a "grub_cmd: boot\0" only.

It is normal for there to be a final `EV_EFI_BOOT_SERVICES_APPLICATION` event on PCR 4
after bootaa64.efi. This is because grub creates an image in memory for the kernel,
and boots into it. Due to headers, this doesn't match the SHA256 of the header file.
As long as you've checked there are no unexpected commands on PCR 8 (e.g. grub commands
that might chainload into an untrusted EFI) or PCR 9 (e.g. loading an unsafe kernel or
initramfs), the hash of this final record doesn't impact security. That said, it should
of course be consistent between a local trusted build of the image, and the cloud hashes,
so can be validated that way if desired.
