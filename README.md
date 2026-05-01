Description:
============

Tssh is a SSH 2 client I wrote in C++11 (now updated to C++20) from scratch, starting from the RFCs.

Debug mode can print for every packet sent a detailed dump, with a description of their purpose. This is a screeshoot of the output that the program produces in debug mode, with the contents of the initial packets exchange:

![alt text](screenshoots/handshake.png "Tssh screenshoot")

FEATURES:
=========

This alpha version implements the basic functions to connect the client to a remote SSH2 server, opening an iteractive shell, with or without an allocated pty.

At the moment, only few cryptographic algorithms are implemented:

- Kex: diffie-hellman-group14-sha1 (rsa-sha and rsa-sha2-256 2048 bits), diffie-hellman-group14-sha256;
- Block encryption: AES 128 bits (aes128-ctr);
- HMAC: hmac-sha1, hmac-sha2-256;

That provides the base to connect to all the reasonably modern server configurations.

Prerequisites:
==============

The program is intended to be used in a *nix environment and it is tested on various Linux distributions and OS X:

- Ubuntu 22.04.5 LTS  ARM
- Ubuntu 22.04.2 LTS  ARM
- Ubuntu 22.04.4 LTS  X86-64
- MacOS  14.7.4       ARM 
- MacOS  13.6.7       ARM 
- MAcOS  12.6.8       X86-64

using, as compiler, one in this list:

- gcc version 9.3.0 (Ubuntu 9.3.0-17ubuntu1~20.04)
- gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04) 
- gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
- Apple clang version 14.0.3 (clang-1403.0.22.14.1)
- Apple clang version 15.0.0 (clang-1500.1.0.2.5)
- Apple clang version 16.0.0 (clang-1600.0.26.6)

and, as ssh server, one of the following:

- OpenSSH_8.9p1  Ubuntu 22.04.2 LTS                 ARM
- OpenSSH_9.0p1, LibreSSL 3.3.6  MacOs  13.5        ARM
- OpenSSH_8.6p1, LibreSSL 3.3.6  MacOs  12.6.8      x86_64
- OpenSSH_8.9p1 Ubuntu-3ubuntu0.3, OpenSSL 3.0.2 15 x86_64
- OpenSSH_8.9p1 Ubuntu-3ubuntu0.7, OpenSSL 3.0.2 15 ARM      
- OpenSSH_8.9p1 Ubuntu-3ubuntu0.10, OpenSSL 3.0.2 15 Mar 2022

The only external dependency is the OpenSSL library, used for the cryptographic functions.
I could introduce alternatives to OpenSSL in the next versions.
This program is intended to be used with an OpenSSL version equal or superior to:

- OpenSSL 3.0.10 LTS

tested  with:

- OpenSSL 3.0.10 LTS

( This means that with OS X, an upgrade is mandatory).

To compile the program, this tools/libraries are necessary:

- a c++ compiler ( with c++11 support);
- automake/autoconf;
- libtool;
- OpenSSL 3.0.10 ("dev" packages) 

Legacy Version:
===============

To compile this software with the old OpenSSL versiona 1.0.x, use the CryptoImpl.cpp in the 'legacy' directory, replacing the one present in the 'src' directory and the configure.ac file present in the root directory with the one available in the 'legacy' directory.

The old version was tested in the following OSs:

- RHEL7 Linux  x86_64;
- Debian 7 ("wheezy");
- Ubuntu 16.04 LTS;
- Ubuntu 14.04 LTS;
- OS X 10.10.5;
- OS X 10.15.7;

with these compilers:

- Apple clang version 12.0.0 (clang-1200.0.32.29)
- clang version 4.0.0;
- clang version 3.8.1;
- gcc version 4.8.5 20150623 (Red Hat 4.8.5-4) (GCC);
- gcc version 4.8.4 (Ubuntu 4.8.4-2ubuntu1~14.04.3);
- gcc version 4.7.2 (Debian 4.7.2-5);
- Apple LLVM version 6.0 (clang-600.0.57) (based on LLVM 3.5svn)

and this OpenSSL version:

- OpenSSL 1.0.2h;

and, as ssh server, one of the following:

- OpenSSH_6.0p1
- OpenSSH_6.2p2
- OpenSSH_6.6.1p1
- OpenSSH_7.2p2
- OpenSSH_8.2p1 


Installation:
=============

- create compilation scripts:
```shell
  make -f makefile.dist
```
- launch the configure script:
```shell
  ./configure
```
    or
```shell
  ./configure WITH_LTO=yes
```
    to compile with LTO optimization (see https://en.wikipedia.org/wiki/Interprocedural_optimization ).
    Native code generation is disabled by default to permit portable packaging. To activate it locally add WITH_NATIVE=yes to configure parameter list.
- Compile the program:
```shell
  make
```
- Install the program and the man page:
```shell
  sudo make install
```

CMake:
======

- create build directory at the same level of ./src/ :
```shell
   mkdir build
```
- Launch CMake, OSX environment doesn't require parameters:
```shell
    cmake ..
```
  on Linux environments we have some options, we can request native code generation:
```shell
    cmake -DUSE_MARCH_NATIVE=ON  ..
```
  also, if available Fil-C and an OpenSSL library compiled with that compiler, we can compile the project usint them specifying:
```shell
    -DUSE_FIL_C_WITH_SSL=[OPEN_SSL_FIL-C_PATH] 
```
  for example:
```shell
    cmake -DUSE_FIL_C_WITH_SSL=/home/bg/_Compiledir/_Fil-C/fil-c/pizfix/lib/  ..
```
  we also can require both those features:
```shell
    cmake -DUSE_MARCH_NATIVE=ON -DUSE_FIL_C_WITH_SSL=/home/bg/_Compiledir/_Fil-C/fil-c/pizfix/lib/  ..
```
- Last step is make execution:
```shell
    make -j$(nproc)
```
  

Fil-c Based Building
====================

- From version 0.80: I started to compile this program with Fil-C ( see https://fil-c.org for details);
- In short, Fil-C is a Clang extension that, "using a combination of concurrent garbage collection and invisible capabilities (InvisiCaps)", permits to obtain builds of C/C++ programs that are memory safe, like Rust programs are;
- I compiled Fil-C from source but you can obtains some pre-compiled packages from its Github page ( https://github.com/pizlonator/fil-c/ );
- You also need an OpenSSL version compiled with Fil-C: you can use the "opt bundle" of Fil-C, that includes OpenSSL and its dependencies, or you can compile Fil-C using the proper script that builds also the optional libraries;
- With Fil-C installed, you can compile this program with it, obtain a memory safe build of tssh;
- Fil-C compiling is not compatible with WITH_LTO=yes;
- In order to do that, you have to use configure with the WITH_FILC option specifying the Fil-C path, for example:
```shell
 ./configure WITH_FILC=/home/bg/.links/filc++
```

Instructions:
=============

See the man page included in the release.

Key creation: rsa-sha2-256 
==========================

OpenSSH introduced a new default proprietary format for DH keys, that is not supported by this program, that, instead use the standard PEM format.
This means that when you create the SSH keys, you need to add an extra parameter when you create a rsa-sha2-256 key pair, for example:
```shell
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM
```
Connection example (server is configured to use port 2222):
```shell
./tssh  -i id_rsa -l bg -p2222 192.168.1.13
```
See man page for further details.

Important Notes:
================

At the moment I consider this program an instrument to study the SSH internals and a base for some security test applications.
This program is an alpha version and, at the moment, it's considered experimental. In particular, it doesn't represent an alternative to consolidated program like the OpenSSH client: the programmers of that tool (and its equivalents ) implemented plenty of security features that, at the moment, are not present in my program. So keep in mind that in some situation the use of this software should be avoided.

Note that the "-d" flag will print on stderr all the packets exchanged before and after the authentication, and the current status of the client. 

*** This means that sensible data will be visualized on the screen ! *** 

So if you are thinking to use this program in environment with security restrictions,  reflect on the consequences before using it!


