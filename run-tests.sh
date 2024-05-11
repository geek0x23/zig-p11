#!/bin/sh
DIR=$(dirname $(realpath -s "$0"))

# configure SoftHSM
if [ ! -L "${HOME}/.config/softhsm2/softhsm2.conf" ]; then
    mkdir -p "${HOME}/.config/softhsm2"
    ln -s "${DIR}/softhsm2.conf" "${HOME}/.config/softhsm2/softhsm2.conf"
fi

# reset SoftHSM tokens
rm -rf "${DIR}/tokens"
mkdir -p "${DIR}/tokens"
softhsm2-util --init-token --slot 0 --label "zig-p11" --pin 1234 --so-pin 1234 > /dev/null

zig build test --summary all
