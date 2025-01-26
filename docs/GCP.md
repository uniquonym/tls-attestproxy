# Notes on GCP

They have a "Shielded Instance" option which is available even for their low cost shared CPU instances
like f1-micro.

However, it seems to be similar to the AWS offering - you get a vTPM (although Measured
Boot didn't seem to work for me - still needs to be confirmed why). The normal NVRAM
indices didn't seem to have an attestation certificate.

The "Confidential VM" instance option costs a lot more - it is only available on N2D, C3D, or C2D
instance families, which don't offer shared cores. The lowest cost seems to be about
$45.52/month on-demand.

For Confidential VM instances, Google does provide a Google-signed certificate that chains up to
a Google root CA.

This means that only the GCP Confidential Computing generated certificates will work for
bootstrapping TLS attestation back to a Google root CA. However, it could be possible to
use the expensive instance type to bootstrap the process, and then use a TLS attestation
to verify the public EK was fetched from the cloud provider (AWS or GCP). It could use
ZKPs to roll up the certificate chain into a single proof that a particular EK is
resident at a cloud provider, across arbitrary layers.

This might be more viable if we can get `/sys/kernel/security/tpm0/binary_bios_measurements` to
show up on GCP without Confidential VM - otherwise, working out the correct PCR values
is going to be a pain / nearly impossible. This is potentially just due to the kernel
that comes with the default images not having the right options and modules (TPM seems
to be built in).
On another reboot, `/sys/kernel/security/tpm0/binary_bios_measurements` was there!
Not sure why I didn't find it the first time - may have been an intermittent failure
or a slightly different hardware type.

It doesn't seem to show up on the `e2-micro` instance type however, only `f1-micro`.
But on a reboot as a 'Skylake or later' f1-micro, still not there. Turning on
secure boot made it work.

Even:
`grub-install --no-uefi-secure-boot --install-modules="boot linux ext2 fat squash4 part_msdos part_gpt normal efi_gop iso9660 search search_fs_file search_fs_uuid search_label tpm" -v`
doesn't seem to work - boot happens but doesn't result in `binary_bios_measurements`. The logs show no EFI table with the logs being passed through - this is likely because the firmware is failing to provide them when secure boot is disabled for some reason.

Maybe we can sign it with a public "snakeoil" private key just to keep secure boot happy without it really being secure - but being reproducible - so that EFI GetEventLogs works with GCP.

Progress to trying to figure out template for generate an EK for signing (which there
is a cert for).
```
root@vtpmtest:/home/andrew# tpm2_createek -c ek.ctx -f tpmt -u ekdef.pub
root@vtpmtest:/home/andrew# tpm2_print -t TPMT_PUBLIC ./ekdef.pub 
```
Probably need to flip decrypt and sign - check we get same key.
Can pass template to createek.
