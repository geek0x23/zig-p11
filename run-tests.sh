#!/bin/sh
DIR=$(dirname $(realpath -s "$0"))

# configure SoftHSM
if [ ! -L "${HOME}/.config/softhsm2/softhsm2.conf" ]; then
    mkdir -p "${HOME}/.config/softhsm2"
    ln -s "${DIR}/softhsm2.conf" "${HOME}/.config/softhsm2/softhsm2.conf"
fi

# Configure p11-kit
rm -rf "${HOME}/.config/pkcs11/modules"
mkdir -p "${HOME}/.config/pkcs11/modules"

# reset tokens
rm -rf "${DIR}/tokens"
mkdir -p "${DIR}/tokens"
modutil -dbdir "sql:${DIR}/tokens" -create -force > /dev/null
modutil -dbdir "sql:${DIR}/tokens" -changepw "NSS Certificate DB" -newpwfile "${DIR}/p11-kit/nss.pin" -force > /dev/null
softhsm2-util --init-token --slot 0 --label "zig-p11" --pin 1234 --so-pin 1234 > /dev/null

# configure p11-kit
case $1 in
    nss-debug)
        ln -s "${DIR}/p11-kit/nss-debug.module" "${HOME}/.config/pkcs11/modules/nss-debug.module"
        ;;
    nss)
        ln -s "${DIR}/p11-kit/nss.module" "${HOME}/.config/pkcs11/modules/nss.module"
        ;;
    softhsm2-debug)
        ln -s "${DIR}/p11-kit/softhsm2-debug.module" "${HOME}/.config/pkcs11/modules/softhsm2-debug.module"
        ;;
    softhsm2)
        ;&
    *)
        ln -s "${DIR}/p11-kit/softhsm2.module" "${HOME}/.config/pkcs11/modules/softhsm2.module"
        ;;
esac


zig build && zig-out/bin/p11-tests
