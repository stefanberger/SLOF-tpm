#!/usr/bin/env bash
cd $(dirname "$0")

function fail() {
	echo "Test failed"
	exit 1
}

CC=${HOSTCC:-gcc}
CFLAGS="-Wall -Wextra -Werror -I../../include -I../../slof -I../../lib/libc/include -DMAIN"
LDFLAGS="-lcrypto"

echo "SHA-1 test:"
${CC} ${CFLAGS} sha.c -o sha-test ${LDFLAGS} || exit 1
./sha-test || fail
rm -f sha-test

echo "SHA-256 test:"
${CC} ${CFLAGS} sha256.c -o sha256-test ${LDFLAGS} || exit 1
./sha256-test || fail
rm -f sha256-test

echo "SHA-384 & 512 test:"
${CC} ${CFLAGS} sha512.c -o sha512-test ${LDFLAGS} || exit 1
./sha512-test || fail
rm -f sha512-test

echo "All tests passed"
exit 0
