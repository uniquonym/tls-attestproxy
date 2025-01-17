# How to build
The tls-attestproxy will obtain attestations that depend on the exact hash of
the built software - so it is essential that the built image is byte-for-byte equal
to what is expected.

tls-attestproxy is designed to run on aarch64 (ARM) cloud instances, not AMD64.
So you need to install qemu-user-binfmt, and add (adjust as appropriate to your system):
```
extra-platforms = aarch64-linux arm-linux
extra-sandbox-paths = /usr/libexec/qemu-binfmt /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static /usr/bin/qemu-arm-static
```
to /etc/nix/nix.conf to build on AMD64. Be sure to restart nix-daemon after.

