#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([execap], [0.8], [https://code.google.com/p/execap/issues])
AC_CONFIG_SRCDIR([findexe.c])
AM_INIT_AUTOMAKE([execap], [0.8])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for required libraries
AC_CHECK_LIB([crypto], [MD5], [], AC_MSG_ERROR[OpenSSL Crypto library is required for this program])
AC_CHECK_LIB([pcap], [pcap_open_live], [], AC_MSG_ERROR[PCAP/libpcap library is required for this program])
AC_CHECK_LIB([pthread], [pthread_create], [], AC_MSG_ERROR[pthread library is required for this program])

# Check for the extra PCAP features
AC_MSG_CHECKING(for newer PCAP features)
AC_TRY_LINK([
#include <pcap/pcap.h>
], [
pcap_t *pch;
pcap_create((char *)0, (char *)0);
pcap_set_buffer_size(pch, 1000);
], [
AC_MSG_RESULT(yes)
OLDPCAP=0
AC_SUBST(OLDPCAP)
], [
AC_MSG_RESULT(no)
OLDPCAP=1
AC_SUBST(OLDPCAP)
])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h unistd.h pcap/pcap.h pcap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 inet_ntoa memset select strdup])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

