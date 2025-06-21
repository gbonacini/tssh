#!/usr/bin/env bash

make -f ./makefile.dist 
./configure
make 

mkdir -p ./deb/tssh_ubuntu_amd64_22_04/usr/local/man/man1
mkdir -p ./deb/tssh_ubuntu_amd64_22_04/usr/local/bin
mkdir    ./deb/tssh_ubuntu_amd64_22_04/DEBIAN

cp ./src/tssh   ./deb/tssh_ubuntu_amd64_22_04/usr/local/bin
cp ./doc/tssh.1 ./deb/tssh_ubuntu_amd64_22_04/usr/local/man/man1

VERSION=$(cat ./version | tr -d '\n')

cat > ./deb/tssh_ubuntu_amd64_22_04/DEBIAN/control << EOF
Package: tssh
Version: ${VERSION}
Maintainer: gbonacini
Depends: libssl3 
Architecture: amd64
Homepage: https://github.com/gbonacini
Description: tssh is a ssh experimental client
EOF

fakeroot dpkg --build ./deb/tssh_ubuntu_amd64_22_04

./configure WITH_LTO=yes
make clean all

mkdir -p ./deb/tssh_ubuntu_amd64_22_04_lto/usr/local/man/man1
mkdir -p ./deb/tssh_ubuntu_amd64_22_04_lto/usr/local/bin
mkdir    ./deb/tssh_ubuntu_amd64_22_04_lto/DEBIAN

cp ./src/tssh   ./deb/tssh_ubuntu_amd64_22_04_lto/usr/local/bin
cp ./doc/tssh.1 ./deb/tssh_ubuntu_amd64_22_04_lto/usr/local/man/man1

cat > ./deb/tssh_ubuntu_amd64_22_04_lto/DEBIAN/control << EOF
Package: tssh
Version: ${VERSION}
Maintainer: gbonacini
Depends: libssl3 
Architecture: amd64
Homepage: https://github.com/gbonacini
Description: tssh is a ssh experimental client
EOF

fakeroot dpkg --build ./deb/tssh_ubuntu_amd64_22_04_lto
