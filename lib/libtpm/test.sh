#!/usr/bin/env bash
cd $(dirname "$0")

CFLAGS="-g -ggdb -O0 -Wall -Wextra -Werror -I../../include -I../../slof -I../../lib/libc/include -DMAIN"
LDFLAGS="-lcrypto"

echo "SHA-1 test:"
gcc ${CFLAGS} sha.c -o sha-test ${LDFLAGS} || exit 1
./sha-test || exit 1
rm -f sha-test

echo "SHA-256 test:"
gcc ${CFLAGS} sha256.c -o sha256-test ${LDFLAGS} || exit 1
./sha256-test || exit 1
rm -f sha256-test

echo "SHA-384 & 512 test:"
gcc ${CFLAGS} sha512.c -o sha512-test ${LDFLAGS} || exit 1
./sha512-test || exit 1
rm -f sha512-test

echo "All tests passed"
exit 0
