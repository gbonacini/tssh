#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([tssh], m4_esyscmd([ tr -d '\n' < version ]))

CXXFLAGS=""
LDFLAGS=""

AC_CONFIG_SRCDIR([src/Main.cpp])

AC_CONFIG_HEADER([include/config.h])

LT_INIT
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE([disable])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_FILES([Makefile
		src/Makefile])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks OpenSSL 
AC_CHECK_LIB([crypto],[EVP_DigestVerifyInit],[],[AC_MSG_FAILURE([could not find lib crypto])])
AC_CHECK_LIB([ssl],[RSA_set0_key],[],[AC_MSG_FAILURE([could not find lib ssl])])

AC_CANONICAL_HOST
case $host_os in
  darwin* )
              OPTIMIZATION="-O3 "
              if test "x$CC" = xgcc; then
                    CXXFLAGS=" -std=c++20 -g -Weverything \
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security \
                             -Wno-deprecated-declarations -Wno-documentation -Wno-c++98-compat \
                             -Wno-padded -Wno-c++98-compat-pedantic -Wno-undefined-func-template ${INC_SSL_CUSTOM}"
		    LDFLAGS="$LDFLAGS ${LIB_SSL_CUSTOM}"
              else
                    CXXFLAGS=" -std=c++20 ${OPTIMIZATION} -g -Wall "
		    LDFLAGS="$LDFLAGS ${LIB_SSL_CUSTOM}"
              fi

        ;;
  linux*)
              OPTIMIZATION="-O3 "
              if test "x$CC" = xgcc; then
                    CXXFLAGS=" -std=c++20 -g -Wall -Wextra \
                             -D_FORTIFY_SOURCE=2 ${OPTIMIZATION} -fstack-protector \
                             --param=ssp-buffer-size=4 -Wformat -Werror=format-security ${INC_SSL_CUSTOM}"
                    LDFLAGS="$LDFLAGS ${LIB_SSL_CUSTOM}-Wl,-z,relro"
              else
                    CXXFLAGS=" -std=c++20 ${OPTIMIZATION} -g -Wall "
		    LDFLAGS="$LDFLAGS ${LIB_SSL_CUSTOM}"
              fi
        ;;
    *)
            CXXFLAGS=" -std=c++20  -O3 -g -Wall "
	    LDFLAGS="$LDFLAGS ${LIB_SSL_CUSTOM}"
            #AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac



AC_OUTPUT
