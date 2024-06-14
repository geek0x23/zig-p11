# zig-p11

This project is a Zig module for PKCS#11.  PKCS#11 is wrapped with a thin layer that brings the interface closer to idiomatic Zig.

For now this exists for me to play around and learn zig while doing something more productive than just a simple "Hello, World!" application.  Maybe someday this library will be usable, but probably not.

## Testing

When testing, the project will attempt load [p11-kit](https://github.com/p11-glue/p11-kit/) from `/lib64/p11-kit-proxy.so`.  This is because Zig's `std.DynLib.open` doesn't support searching system paths.

I've shipped a script (`run-tests.sh`) which supports running tests against [NSS](https://firefox-source-docs.mozilla.org/security/nss/index.html) and [SoftHSM](https://github.com/opendnssec/SoftHSMv2).  This script will take over `~/.config/pkcs11` and `~/.config/softhsm2` and store specific configuration files there.
