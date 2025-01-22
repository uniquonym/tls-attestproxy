# How to build
The tls-attestproxy will obtain attestations that depend on the exact hash of
the built software - so it is essential that the built image is byte-for-byte equal
to what is expected.

tls-attestproxy is designed to run on aarch64 (ARM) cloud instances, but to be cross-compiled
from x86_64.
