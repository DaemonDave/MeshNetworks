#
#   Meshnetwork 
#
#   Meshnetwork command line program from console       t-mesh
#   Meshnetwork service daemon   						meshd
#   Meshnetwork library of functions. 					libmeshnetwork.la
#   
#
#

ACLOCAL_AMFLAGS = -I m4 



AM_CFLAGS  = -g -Wall -D_POSIX -D_DEBUG -fno-strict-aliasing  

AM_LDFLAGS =  -lpthread -ldl -lssl -lcrypto  -lsqlite3 -lz 

#porting over to make sure this automake system will work

# daemon program to run in the background:

# sslecho program to test SSL operation using OpenSSL demo:
bin_PROGRAMS = sslecho meshd

# ORIGINAL WORKING setup with no changes
#sslecho_SOURCES = sslecho.c
#sslecho_CFLAGS  = -O0 -g3 -W -Wall  
#sslecho_LDFLAGS  = -L./
#sslecho_LDADD   = -lssl -lcrypto 
# NEW WORKING VERSION
#
# Plan A was just shift code over en masse. That ran into all kinds of errors, now I am just going to pull the sweater through the needle eye one file at a time starting with sublibraries - starting with Intel code.
# Realization: refactoring whole libraries ends up being a waste of time when you can't extract the dependencies clear enough to stop dependencies' tautologies
# WORKING SAVED 
#sslecho_SOURCES = new_sslecho.c \
#					ILibParsers.c\
#					HECILinux.c \
#					ILibAsyncSocket.c\
#					ILibAsyncUDPSocket.c\
#					ILibAsyncServerSocket.c\
#					ILibWebClient.c\
#					ILibWebServer.c\
#					ILibMulticastSocket.c
#  Working without meshnetwork
#sslecho_SOURCES = new_sslecho.c \
#					ILibParsers.c\
#					HECILinux.c \
#					ILibAsyncSocket.c\
#					ILibAsyncUDPSocket.c\
#					ILibAsyncServerSocket.c\
#					ILibWebClient.c\
#					ILibWebServer.c\
#					ILibMulticastSocket.c\
#					PTHICommand.c
# Experiement with mesh code below
sslecho_SOURCES = new_sslecho.c \
					ILibParsers.c \
					HECILinux.c \
					ILibAsyncSocket.c \
					ILibAsyncUDPSocket.c \
					ILibAsyncServerSocket.c \
					ILibWebClient.c \
					ILibWebServer.c \
					ILibMulticastSocket.c \
					PTHICommand.c \
					timestamp.c \
					globals.c \
					meshconfig.c \
					meshcore.c
					
#
# 					
# 					meshctrl.c
#
#   meshctrl and then utils.c but utils may be 
#  					meshconfig.c
#					meshinfo.c
#					
#					
					
#

#
# Two hardest to integrate are meshcore and meshcontrol.
# Best to start with the ctor/dtor first.
#					
				
sslecho_CFLAGS  = -O0 -g3 -W -Wall  -I./include/openssl -I./include/crypto

sslecho_LDFLAGS  = -L./
sslecho_LDADD   = -lssl -lcrypto 

# OPENSSL SPECIFIC VARIABLES
# VERY IMPORTANT ENV. VARIABLE TO FIND LOCAL HEADERS
OPENSSL_INCS_LOCATION=-Iinclude
# VERY IMPORTANT ENV. VARIABLE TO FIND LOCAL LIBRARIES
OPENSSL_LIBS_LOCATION=-L./


# Make convenience library for the combined functions

### PROBLEM - won't compile or create a proper 
### SOLVED - old makefile was around to go first
lib_LTLIBRARIES = libmeshnetwork.la

#
#  STAGED COMPILATION:
#
# As source codes are like a collander of wet noodles (data objects) and red meatballs (function objects) all jumbled together, 
# you need to treat them in sequence to remove illogical circular references, redundant references, and missing connections to references.
# The best way to deconflict what may not have been clear by reading the code, start by compiling one file that appears to be isolated.
# Make sure that can compile without extra references, and then you have the base of objects that can be build on that 
#  This is staged compilation, it is the slow methodical way to complete fixing the problems the original developers couldn't see. 
#
#


libmeshnetwork_la_SOURCES     		=  ILibWebServer.c \
									utils.c\
									meshinfo.c \
									meshdb.c \
									meshcore.c \
									meshctrl.c \
									PTHICommand.c \
									HECILinux.c \
									ILibMulticastSocket.c \
									ILibAsyncUDPSocket.c \
									ILibParsers.c \
									ILibAsyncServerSocket.c \
									ILibWebClient.c \
									ILibAsyncSocket.c
									
														
#									
#									
#									
#									

								
libmeshnetwork_la_CFLAGS			= $(AM_CFLAGS) $(SSL_CFLAGS) -Iinclude 

libmeshnetwork_la_LDFLAGS			= -version-info 0:0:0

libmeshnetwork_la_LIBADD			= $(AM_LDFLAGS) $(SSL_LDFLAGS)

# test program for the library
check_PROGRAMS		= t-mesh t-database t-database2 t-database3 t-database4 t-database5 t-database6  t-database7 t-databasessl t-insertblob t-retrieveblob  t-retrieveint  t-insertblobpem  t-sqlite3 t-retrieveblobpem t-insertblobkey t-retrieveblobkey t_meshdb
   

# test the meshnetwork databases only
t_database_SOURCES 	=  test-database.c meshdb.c ILibParsers.c utils.c

t_database_CFLAGS	= -I/usr/include

t_database_LDFLAGS	= -L/lib64

t_database_LDADD	= /lib64/libsqlite3.so.0




# this example inserts data into table into created test.db database
t_sqlite3_SOURCES 	=  test-sqlite3.c
t_sqlite3_CFLAGS	= 
t_sqlite3_LDFLAGS	= -L/lib64
t_sqlite3_LDADD		= -lc /lib64/libsqlite3.so.0




# this example inserts data into table into created test.db database
t_insertblobkey_SOURCES 	=  test-insertblobkey.c
t_insertblobkey_CFLAGS		= 
t_insertblobkey_LDFLAGS	= -L/lib64
t_insertblobkey_LDADD		= -lc /lib64/libsqlite3.so.0


# this example inserts data into table into created test.db database
t_retrieveblobkey_SOURCES 	=  test-retrieveblobkey.c
t_retrieveblobkey_CFLAGS		= 
t_retrieveblobkey_LDFLAGS	= -L/lib64
t_retrieveblobkey_LDADD		= -lc /lib64/libsqlite3.so.0


# this example inserts data into table into created test.db database
t_insertblobpem_SOURCES 	=  test-insertblobpem.c
t_insertblobpem_CFLAGS		= 
t_insertblobpem_LDFLAGS	= -L/lib64
t_insertblobpem_LDADD		= -lc /lib64/libsqlite3.so.0


# this example inserts data into table into created test.db database
t_retrieveblobpem_SOURCES 	=  test-retrieveblobpem.c
t_retrieveblobpem_CFLAGS		= 
t_retrieveblobpem_LDFLAGS	= -L/lib64
t_retrieveblobpem_LDADD		= -lc /lib64/libsqlite3.so.0


# this example inserts data into table into created test.db database
t_insertblob_SOURCES 	=  test-insertblob2.c
t_insertblob_CFLAGS		= 
t_insertblob_LDFLAGS	= -L/lib64
t_insertblob_LDADD		= -lc /lib64/libsqlite3.so.0

# this example inserts data into table into created test.db database
t_retrieveblob_SOURCES 	=  test-retrieveblob.c
t_retrieveblob_CFLAGS		= 
t_retrieveblob_LDFLAGS	= -L/lib64
t_retrieveblob_LDADD		= -lc /lib64/libsqlite3.so.0

# this example inserts data into table into created test.db database
t_retrieveint_SOURCES 	=  test-retrieveint.c
t_retrieveint_CFLAGS		= 
t_retrieveint_LDFLAGS	= -L/lib64
t_retrieveint_LDADD		= -lc /lib64/libsqlite3.so.0





##
# These are the tutorialspoint examples that really work with sqlite3 version 3.3.X
# https://www.tutorialspoint.com/sqlite/sqlite_c_cpp.htm
# 
# Use these to make the original mesh database formats and confirm that the data works.
#
# Ironically, it might make more sense to have a server...
#
# Or a set of process daemons that conduct file operations in the background by the OS.... 
# Using crontab and crond exploiting safe, proven solutions. Something I haven't done
# with a lot of protoypes.
# 
# All these can be made into database specific command execution daemons.
##

# test the meshnetwork databases only

# this example inserts data into table into created test.db database
t_database7_SOURCES 	=  test-database7.c
t_database7_CFLAGS	= 
t_database7_LDFLAGS	= -L/lib64
t_database7_LDADD	= -lc /lib64/libsqlite3.so.0




# this example inserts data into table into created test.db database
t_database6_SOURCES 	=  test-database6.c
t_database6_CFLAGS	= 
t_database6_LDFLAGS	= -L/lib64
t_database6_LDADD	= -lc /lib64/libsqlite3.so.0




# test the meshnetwork databases only
# this example inserts data into table into created test.db database
t_database5_SOURCES 	=  test-database5.c
t_database5_CFLAGS	= 
t_database5_LDFLAGS	= -L./
t_database5_LDADD	= -lc

# test the meshnetwork databases only
# this example create table into test.db database
t_database4_SOURCES 	=  test-database4.c
t_database4_CFLAGS	= 
t_database4_LDFLAGS	= -L./
t_database4_LDADD	= -lc

# test the meshnetwork databases only
# this example inserts records into test.db database
t_database3_SOURCES 	=  test-database3.c
t_database3_CFLAGS	= 
t_database3_LDFLAGS	= -L./
t_database3_LDADD	= -lc

# test the meshnetwork databases only
# This one selects records to an inserted database and displays them
t_database2_SOURCES 	=  test-database2.c
t_database2_CFLAGS	= 
t_database2_LDFLAGS	= -L./
t_database2_LDADD	= -lc

# test the meshnetwork databases only
# This one selects records to an inserted database and displays them
t_databasessl_SOURCES 	=  test-databasessl.c
t_databasessl_CFLAGS	= 
t_databasessl_LDFLAGS	= -L./
t_databasessl_LDADD	= -lc



# test the meshnetwork databases only
# this example inserts records into test.db database
t_meshdb_SOURCES 	=  test-meshdb.c meshdb.c
t_meshdb_CFLAGS		=  
t_meshdb_LDFLAGS	= -L./
t_meshdb_LDADD		= -lc 





t_mesh_SOURCES 	= unittest.c 
# main.c 
t_mesh_CFLAGS	= -Iinclude 
t_mesh_LDFLAGS	= -L./
t_mesh_LDADD	= -lssl -lcrypto libmeshnetwork.la



# A Mesh network Daemon to accomodate many programs / processes/forks / threads all using same mesh network from global mesh agents
meshd_SOURCES 	= ServiceMain.c 

meshd_CFLAGS	= 	$(CFLAGS)
meshd_LDADD		= libmeshnetwork.la $(LDFLAGS)

#	
.PHONY:	dox create-dox

######

# the doxygen phony for random autodocumentation
dox:
	doxygen Doxyfile
	

create-dox:
	doxygen -g 
