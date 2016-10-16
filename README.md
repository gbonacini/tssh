Description:
============

Tssh is a SSH 2 client I wrote in C++11 from scratch starting from the RFCs.

This is a screeshoot of the output that the program produce in debug mode, with the contents of the initial packets exchange:

![alt text](screenshoots/handshake.png "Tssh screenshoot")

FEATURES:
=========

This alpha version implements the basic functions to connect the client to a remote SSH2 server, opening an iteractive shell, with or without an allocated pty.

At the moment, only few cryptographic algorithms are implemented:

- Kex: diffie-hellman-group14-sha1 (rsa 2048 bits);
- Block encryption: AES 128 bits (aes128-ctr);
- HMAC: hmac-sha1;

That provides the base to connect to all the reasonably modern server configurations.

Prerequisites:
==============

The program is intended to be used in a *nix environment and it is tested on various Linux distributions and OS X:

- RHEL7 Linux  x86_64;
- Debian 7 ("wheezy");
- Ununtu 16.04 LTS;
- OS X 10.10.5;

using, as compiler, one in this list:

- clang version 4.0.0;
- clang version 3.8.1;
- gcc version 4.8.5 20150623 (Red Hat 4.8.5-4) (GCC);
- gcc version 4.7.2 (Debian 4.7.2-5);
- Apple LLVM version 6.0 (clang-600.0.57) (based on LLVM 3.5svn)

and, as ssh server, one of the following:

- OpenSSH_6.0p1
- OpenSSH_6.2p2
- OpenSSH_6.6.1p1
- OpenSSH_7.2p2

The only external dependency is the OpenSSL libraryi, used for the cryptographic functions.
I could introduce alternatives to OpenSSL in the next versions.
This program is intended to be used with an OpenSSL version equal or superior to:

- OpenSSL 1.0.2h;

( This means that with OS X, an upgrade is mandatory).

To compile the program, this tools/libraries are necessary:

- a c++ compiler ( with c++11 support);
- automake/autoconf;
- libtool;
- OpenSSL 1.0.2h or superior ("dev" packages);

Installation:
=============

- launch the configure script:
  ./configure
- Compile the program:
  make
- Istall the program and the man page:
  sudo make install

Important Notes:
================

At the moment I consider this program an instrument to study the SSH internals and a base for some security test applications.
This program is an alpha version and, at the moment, it's considerated experimental. In particular, it doesn't represent an alternative to consolidated program like the OpenSSH client: the programmers of that tool (and its equivalents ) implemented plenty of security features that, at the moment, are not present in my program. So keep in mind that in some situation the use of this software should be avoided.

Note that the "-d" flag will print on stderr all the packets exchanged before and after the authentication, and the current status of the client. 

*** This means that sensible data will be visualized on the screen ! *** 

So if you are thinking to use this program in envirnonment with security restrictions,  reflect before on the conseguences before using it!


