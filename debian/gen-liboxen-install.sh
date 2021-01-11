#!/bin/bash

set -e

UPSTREAM_VER="$1"
LIBOXEN_VER="${UPSTREAM_VER/[^0-9.]*/}"
if ! grep -q "^Package: liboxen$LIBOXEN_VER\$" debian/control; then
    echo -e "\nError: debian/control doesn't contain the correct liboxen$LIBOXEN_VER version; you should run:\n\n    ./debian/update-liboxen-ver.sh\n"
    exit 1
fi

for sublib in "" "-wallet"; do
    if ! [ -f debian/liboxen$sublib$LIBOXEN_VER ]; then
        rm -f debian/liboxen$sublib[0-9]*.install
        sed -e "s/@LIBOXEN_VER@/$LIBOXEN_VER/" debian/liboxen$sublib.install.in >debian/liboxen$sublib$LIBOXEN_VER.install
    fi
done
