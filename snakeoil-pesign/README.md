# About

This repository contains a "snakeoil" NSS certificate registry.

Warning: The private key for the snakeoil cert is freely available on the public
Internet; it does not provide any actual security in secureboot, and is only for
working around EFI firmware that requires secureboot for certain functionality
to work, when you otherwise don't actually want secureboot.

There are binary databases under nss. You could recreate them, but that involves random
data, so the result won't be reproducible.

Steps to recreate:

* mkdir nss
* head -c200 /dev/zero > /tmp/zero
* faketime '1970-01-01 00:00:00+00' certutil -Nd nss # Enter for passwords (leave blank)
* faketime '1970-01-01 00:00:00+00' certutil -Sd nss -n SNAKEOIL -t C -s cn=snakeoil -v 12000 -Z SHA256 -x -z /tmp/zero
* certutil -Lrd nss -n SNAKEOIL >snakeoil.crt
* Note despite using a constant seed, it isn't reproducible currently. However, it is only used for signatures, not for any executable content, so there is minimal risk in making the fixed database part of the build source.

# Signing

Running pesign against the nss database is reproducible, with the caveat that faketime needs to be used with a constant time.

Example:
```
faketime '1970-01-01 00:00:00+00' pesign -s -i test.efi -o test-sign-2.efi -n nss -c SNAKEOIL
```
