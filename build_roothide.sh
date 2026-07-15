#!/bin/sh
set -e
cd "$(dirname "$0")"
# shellcheck disable=SC1091
. ./devkit/roothide.sh
echo "THEOS=$THEOS"
echo "SCHEME=$THEOS_PACKAGE_SCHEME"
make clean
make package FINALPACKAGE=1
echo "deb(s):"
ls -la packages 2>/dev/null || ls -la .theos/_ 2>/dev/null || true
find . -name '*.deb' -maxdepth 3 -print
