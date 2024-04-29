# zig-p11

This project is for me to play around and learn zig while doing something more productive than just a simple "Hello, World!" application.  Maybe someday this library will be usable, but probably not.

## SoftHSM2

First make a place for your config to live:

```
mkdir -p ~/.config/softhsm2
```

Create a file called `softhsm2.conf` in `~/.config/softhsm2` with the following contents:

```
directories.tokendir = /some/path/for/tokens
objectstore.backend = file
log.level = DEBUG
slots.removable = false
```

Finally, initialize a new empty token:

```
softhsm2-util --init-token --slot 0 --label "zig-p11" --pin 1234 --so-pin 1234
```

## Testing

The unit tests will use the module path `/lib64/softhsm/libsofthsm.so` by default.  To run the unit tests with a different module path, specify the appropriate build option:

```
zig build test -Dpkcs11-module=/path/to/your/module
```

SoftHSM sends all logs to syslog.  The following rsyslog config file can help when debugging:

```
:programname, isequal, "p11"
*.* /var/log/zig-p11
```
