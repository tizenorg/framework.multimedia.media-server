ACLOCAL_AMFLAGS = -I m4

SUBDIRS = .

AM_CPPFLAGS = $(FMS_DEBUG_FLAGS)

AM_LDFLAGS=-Wl,--as-needed -Wl,--hash-style=both

### pkgconfig ###
pkgconfigdir = $(libdir)/pkgconfig
dist_pkgconfig_DATA = libmedia-utils.pc

### libmedia-utils.la ###
lib_LTLIBRARIES = libmedia-utils.la
libmedia_utils_la_SOURCES = lib/media-util-noti.c \
                            lib/media-util-ipc.c \
                            lib/media-util-db.c \
                            lib/media-util-register.c

libmedia_utils_la_CFLAGS = -I${srcdir}/lib/include \
                              $(GLIB_CFLAGS) \
			      $(DLOG_CFLAGS) \
			      $(DBUS_CFLAGS) \
			      $(SQLITE3_CFLAGS) \
			      $(DB_UTIL_CFLAGS) \
			      $(PHONESTATUS_CFLAGS)

libmedia_utils_la_LIBADD  =   $(GLIB_LIBS) \
                              $(DLOG_LIBS) \
                              $(DBUS_LIBS) \
			      $(SQLITE3_LIBS) \
			      $(DB_UTIL_LIBS) \
			      $(PHONESTATUS_LIBS)


### file-manager-server ###
bin_PROGRAMS = media-server \
		media-scanner \
		mediadb-update

media_server_SOURCES = src/common/media-common-utils.c \
                       src/common/media-common-external-storage.c \
                       src/server/media-server-db-svc.c \
                       src/server/media-server-db.c \
                       src/server/media-server-socket.c \
                       src/server/media-server-thumb.c \
                       src/server/media-server-scanner.c \
                       src/server/media-server-main.c 

media_server_CFLAGS = -I${srcdir}/src/common/include \
		      -I${srcdir}/src/server/include \
                      -I${srcdir}/lib/include \
                             $(GTHREAD_CFLAGS) \
                             $(GLIB_CFLAGS) \
                             $(DLOG_CFLAGS) \
			     $(PHONESTATUS_CFLAGS) \
			     $(DBUS_CFLAGS)
if USE_NOTIFICATION
media_server_CFLAGS += $(STATUS_CFLAGS)
endif

media_server_CFLAGS += $(LIBPMCONTROL_CFLAGS)

media_server_CFLAGS += $(SECURITY_CFLAGS)

media_server_CFLAGS += -fPIE

media_server_LDFLAGS = -pie

media_server_LDADD = libmedia-utils.la \
			      $(GLIB_LIBS) \
                              $(GTHREAD_LIBS) \
                              $(PHONESTATUS_LIBS) \
                              $(DLOG_LIBS) \
			      $(AUL_LIBS) \
			      $(DBUS_LIBS) \
                              -ldl
if USE_NOTIFICATION
media_server_LDADD += $(STATUS_LIBS)
endif

media_server_LDADD += $(LIBPMCONTROL_LIBS)

media_server_LDADD += $(SECURITY_LIBS)



media_scanner_SOURCES = src/common/media-common-utils.c \
                	src/common/media-common-external-storage.c \
                       	src/scanner/media-scanner-db-svc.c \
                       	src/scanner/media-scanner-scan.c \
                       	src/scanner/media-scanner-socket.c \
                       	src/scanner/media-scanner.c

media_scanner_CFLAGS = -I${srcdir}/lib/include \
                       -I${srcdir}/src/common/include \
		       -I${srcdir}/src/scanner/include \
                             $(GTHREAD_CFLAGS) \
                             $(GLIB_CFLAGS) \
                             $(PHONESTATUS_CFLAGS) \
                             $(DLOG_CFLAGS) \
                             $(DBUS_CFLAGS)
if USE_NOTIFICATION
media_scanner_CFLAGS += $(STATUS_CFLAGS)
endif

media_scanner_CFLAGS += $(LIBPMCONTROL_CFLAGS)

media_scanner_CFLAGS += -fPIE

media_scanner_LDFLAGS = -pie

media_scanner_LDADD = libmedia-utils.la \
                              $(GLIB_LIBS) \
                              $(GTHREAD_LIBS) \
                              $(PHONESTATUS_LIBS) \
                              $(DLOG_LIBS) \
                              $(DBUS_LIBS) \
                              -ldl
if USE_NOTIFICATION
media_scanner_LDADD += $(STATUS_LIBS)
endif

media_scanner_LDADD += $(LIBPMCONTROL_LIBS)

mediadb_update_SOURCES = src/mediadb-update.c

mediadb_update_CFLAGS = -I${srcdir}/lib/include \
                             $(GTHREAD_CFLAGS) \
                             $(GLIB_CFLAGS)

mediadb_update_CFLAGS += -fPIE

mediadb_update_LDFLAGS = -pie

mediadb_update_LDADD = libmedia-utils.la \
                              $(GLIB_LIBS) \
                              $(GTHREAD_LIBS)

### includeheaders ###
includeheadersdir = $(includedir)/media-utils
includeheaders_HEADERS = lib/include/media-util-noti-common.h \
			 lib/include/media-util-noti.h \
                         lib/include/media-util-register.h \
                         lib/include/media-util-err.h \
                         lib/include/media-util-db.h \
                         lib/include/media-util-ipc.h \
                         lib/include/media-util.h \
                         lib/include/media-server-ipc.h
