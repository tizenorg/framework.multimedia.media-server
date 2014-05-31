#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([media-server], [1.0])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h:config.in])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# for platform setting
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Check target
if ! (test "x$ARCH" = "xarmel" -o "x$ARCH" = "xi386"); then
    echo "$ARCH"
#      ARCH=ARM
fi

#if test "x$MACHINE" = "xfloater"; then
    CPPFLAGS="$CPPFLAGS -D _FM_GENERIC_ -D EXPORT_API=\"__attribute__((visibility(\\\"default\\\")))\""
    echo ""
    echo $CPPFLAGS
    echo "### check point ###"
    echo ""
#fi

CPPFLAGS="${CPPFLAGS} -DRND_LINUX"

#For supporting Large file
CPPFLAGS="${CPPFLAGS} -D_FILE_OFFSET_BITS=64"

# FMS_DEBUG - File Manager Service debug options
# To open debug options:
# export FMS_DEBUG=1 or configure --enable-debug
AC_ARG_ENABLE([debug],
              [AS_HELP_STRING([--enable-debug], [Enable debug options])],
              [case "x$enableval" in
               xyes) debug=true;;
               xno)  debug=false;;
               *)      AC_MSG_ERROR([Bad value %enableval for --enable-debug]);;
               esac],
              [debug=false])
if test "x$debug" = "xtrue" -o "x$FMS_DEBUG" = "x1"; then
    FMS_DEBUG_FLAGS="-D FEXPLORER_DEBUG -g"
else
    FMS_DEBUG_FLAGS=""
fi
AC_SUBST(FMS_DEBUG_FLAGS)

# Checks for libraries.
PKG_CHECK_MODULES(GTHREAD, gthread-2.0)
AC_SUBST(GTHREAD_CFLAGS)
AC_SUBST(GTHREAD_LIBS)

PKG_CHECK_MODULES(GLIB, glib-2.0)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DLOG, dlog)
AC_SUBST(DLOG_CFLAGS)
AC_SUBST(DLOG_LIBS)

PKG_CHECK_MODULES(PHONESTATUS, vconf)
AC_SUBST(PHONESTATUS_CFLAGS)
AC_SUBST(PHONESTATUS_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-glib-1)
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(SQLITE, sqlite3)
AC_SUBST(SQLITE3_CFLAGS)
AC_SUBST(SQLITE3_LIBS)

PKG_CHECK_MODULES(DB_UTIL, db-util)
AC_SUBST(DB_UTIL_CFLAGS)
AC_SUBST(DB_UTIL_LIBS)

dnl use notification --------------------------------------------------------------------------
AC_ARG_ENABLE(notification, AC_HELP_STRING([--enable-notification], [using notification]),
[
   case "${enableval}" in
       yes) USE_NOTIFICATION=yes ;;
        no) USE_NOTIFICATION=no ;;
         *) AC_MSG_ERROR(bad value ${enableval} for --enable-notification) ;;
   esac
],[USE_NOTIFICATION=yes])
if test "x$USE_NOTIFICATION" = "xyes"; then
	#ticker noti library
	PKG_CHECK_MODULES(STATUS, notification)
	AC_SUBST(STATUS_CFLAGS)
	AC_SUBST(STATUS_LIBS)
fi
AM_CONDITIONAL(USE_NOTIFICATION, test "x$USE_NOTIFICATION" = "xyes")


dnl use deviced  --------------------------------------------------------------------------
AC_ARG_ENABLE(deviced, AC_HELP_STRING([--enable-deviced], [using deviced]),
[
   case "${enableval}" in
       yes) USE_DEVICED=yes ;;
        no) USE_DEVICED=no ;;
         *) AC_MSG_ERROR(bad value ${enableval} for --enable-deviced) ;;
   esac
],[USE_DEVICED=yes])
if test "x$USE_DEVICED" = "xyes"; then
	PKG_CHECK_MODULES(LIBPMCONTROL, deviced)
	AC_SUBST(LIBPMCONTROL_CFLAGS)
	AC_SUBST(LIBPMCONTROL_LIBS)
else
        PKG_CHECK_MODULES(LIBPMCONTROL, pmapi)
        AC_SUBST(LIBPMCONTROL_CFLAGS)
        AC_SUBST(LIBPMCONTROL_LIBS)
fi
AM_CONDITIONAL(USE_DEVICED, test "x$USE_DEVICED" = "xyes")

dnl use security server --------------------------------------------------------------------------
AC_ARG_ENABLE(security-server, AC_HELP_STRING([--enable-security-server], [using security-server]),
[
   case "${enableval}" in
       yes) USE_SECURITY=yes ;;
        no) USE_SECURITY=no ;;
         *) AC_MSG_ERROR(bad value ${enableval} for --enable-security-security) ;;
   esac
],[USE_SECURITY=yes])
if test "x$USE_SECURITY" = "xyes"; then
	#sercurity server
	PKG_CHECK_MODULES(SECURITY, security-server)
	AC_SUBST(SECURITY_CFLAGS)
	AC_SUBST(SECURITY_LIBS)
fi
AM_CONDITIONAL(USE_SECURITY, test "x$USE_SECURITY" = "xyes")

#Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/file.h sys/vfs.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday memset mkdir strcasecmp strstr])

AC_CONFIG_FILES([Makefile
				 libmedia-utils.pc
				 ])
AC_OUTPUT
