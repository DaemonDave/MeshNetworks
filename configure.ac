#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#
# mesh-werx is my local build of the meshnetwork - Release Candidate 12 - using the   Apache License Version 2.0, January 2004
# no build files except the Makefile are altered. 
# 
# This will be the build-purpose instantiation for the stampede project.
#

AC_PREREQ([2.71])
AC_INIT([mesh-werx], [0.1], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([ILibMulticastSocket.c])
AC_CONFIG_HEADERS([config.h])

# Setup GNU Autotools 
AM_INIT_AUTOMAKE([subdir-objects])


AC_CONFIG_MACRO_DIRS([m4])





# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AM_PROG_AR

# defining autotools libtool to allow shared libraries that can use dlopen with position independent code
LT_PREREQ([2.2])
AC_LIBTOOL_DLOPEN
LT_INIT([dlopen])

# Checks for libraries.
# updated to include recent functions
# Added libc  for many functions rolled into current libc:
AC_CHECK_LIB([c], [___pthread_mutex_clocklock])
# FIXME: Replace 'main' with a function in '-ldl':
AC_CHECK_LIB([dl], [_ITM_registerTMCloneTable])
# FIXME: Replace 'main' with a function in '-lpthread':
AC_CHECK_LIB([pthread], [_ITM_deregisterTMCloneTable])
# FIXME: Replace 'main' with a function in '-lsqlite3':
AC_CHECK_LIB([sqlite3], [sqlite3_vmprintf])
# FIXME: Replace 'main' with a function in '-lssl':
#AC_CHECK_LIB([ssl], [PR_SetError])
# FIXME: Replace 'main' with a function in '-lz':
AC_CHECK_LIB([z], [inflateSync])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h netinet/in.h stdint.h sys/ioctl.h sys/socket.h sys/statfs.h sys/time.h sys/timeb.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_CHECK_TYPES([ptrdiff_t])


####
#
#  NOTE - made OpenSSL into a local library only so that it can travel with the mesh network without being dependent on the local kernel's version. 
#
####

# OPENSSL libraries  via pkg-config
#OPENSSL_PKG_CFLAGS=$(pkg-config --cflags libssl)
#OPENSSL_PKG_LDFLAGS=$(pkg-config --libs libssl)
 
#AC_SUBST(OPENSSL_PKG_CFLAGS)
#AC_SUBST(OPENSSL_PKG_LDFLAGS)

# By using the PKG_CHECK_MODULES macro, Autoconf-generated configure scripts can retrieve pkg-config data automatically. 
#  As an example, adding this line to your configure.ac file:
# PKG_CHECK_MODULES([DEPS], [glib-2.0 >= 2.24.1])
# will cause the resulting configure script to ensure that the installed version of glib-2.0 is greater than or equal to version 
# 
# 2.24.1 as well as append to variables DEPS_CFLAGS and DEPS_LIBS the output of pkg-config --cflags glib-2.0 and pkg-config --libs glib-2.0, 
# respectively. You then use the $(DEPS_CFLAGS) and $(DEPS_LIBS) variables in the _CFLAGS and _LDADD primaries:
#
#  bin_PROGRAMS = hello
#  hello_CFLAGS = $(DEPS_CFLAGS)
#  hello_SOURCES = hello.c
#  hello_LDADD = $(DEPS_LIBS)
#
#
#  PKG_CHECK_MODULES
#PKG_CHECK_MODULES([SSL], [libssl == 1.1.0])


#AC_CHECK_HEADERS([openssl/ssl.h])
#AC_CHECK_HEADERS([openssl/x509v3.h])
#AC_CHECK_HEADERS([openssl/pkcs7.h])
#AC_CHECK_HEADERS([openssl/pkcs12.h])
AC_CHECK_HEADERS([openssl/conf.h])
AC_CHECK_HEADERS([openssl/engine.h])
AC_CHECK_HEADERS([openssl/pem.h])
AC_CHECK_HEADERS([openssl/sha.h])
AC_CHECK_HEADERS([openssl/rand.h])
AC_CHECK_HEADERS([openssl/aes.h])
AC_CHECK_HEADERS([openssl/hmac.h])
AC_CHECK_HEADERS([openssl/types.h])
AC_CHECK_HEADERS([openssl/evp.h])



AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([stdarg.h])

AC_CHECK_HEADERS([zlib.h])

AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([errno.h])

AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([net/if.h])
AC_CHECK_HEADERS([net/if_arp.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([sys/ioctl.h])





# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([fdatasync gethostbyname gethostname gettimeofday memmove memset mkdir select socket strcasecmp strncasecmp strstr strtol strtoul tzset])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
