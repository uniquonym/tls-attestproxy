# Notes on AWS
tls-attestproxy isn't currently useful on AWS, because they don't provide an EK cert.

They do provide an AWS API that provides the EK pub from outside the instance, but this is not
really enough for non-interactive zero-knowledge use like we want. TLS attestation could prove
that an EK public key was legitimately from AWS - but needing TLS attestation to implement TLS
attestation means that the (as of now) AWS isn't yet useful for tls-attestproxy.

https://repost.aws/questions/QUWzHj71c4TTWDbYP5RYCwHA/how-to-provision-nitrotpm mentions the limitations.

As of 2025-01-25, the TPM2 still doesn't have an EK certificate in NVRAM - after booting a Debian AMI with tpm2 enabled, and using tpm2-tools to query it:

```
# tpm2_getekcertificate -o cert.pem --offline
ERROR: Must specify the EK public key path
Usage: tpm2_getekcertificate [<options>] <arguments>
Where <options> are:
    [ -o | --ek-certificate=<value>] [ -X | --allow-unverified] [ -u | --ek-public=<value>] [ -x | --offline]
    [ --raw]
```
