
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef intel_mdb
#include "meshdb.h"
#endif
/*
** CAPI3REF: One-Step Query Execution Interface
** METHOD: sqlite3
**
** The sqlite3_exec() interface is a convenience wrapper around
** [sqlite3_prepare_v2()], [sqlite3_step()], and [sqlite3_finalize()],
** that allows an application to run multiple statements of SQL
** without having to use a lot of C code.
**
** ^The sqlite3_exec() interface runs zero or more UTF-8 encoded,
** semicolon-separate SQL statements passed into its 2nd argument,
** in the context of the [database connection] passed in as its 1st
** argument.  ^If the callback function of the 3rd argument to
** sqlite3_exec() is not NULL, then it is invoked for each result row
** coming out of the evaluated SQL statements.  ^The 4th argument to
** sqlite3_exec() is relayed through to the 1st argument of each
** callback invocation.  ^If the callback pointer to sqlite3_exec()
** is NULL, then no callback is ever invoked and result rows are
** ignored.
**
** ^If an error occurs while evaluating the SQL statements passed into
** sqlite3_exec(), then execution of the current statement stops and
** subsequent statements are skipped.  ^If the 5th parameter to sqlite3_exec()
** is not NULL then any error message is written into memory obtained
** from [sqlite3_malloc()] and passed back through the 5th parameter.
** To avoid memory leaks, the application should invoke [sqlite3_free()]
** on error message strings returned through the 5th parameter of
** sqlite3_exec() after the error message string is no longer needed.
** ^If the 5th parameter to sqlite3_exec() is not NULL and no errors
** occur, then sqlite3_exec() sets the pointer in its 5th parameter to
** NULL before returning.
**
** ^If an sqlite3_exec() callback returns non-zero, the sqlite3_exec()
** routine returns SQLITE_ABORT without invoking the callback again and
** without running any subsequent SQL statements.
**
** ^The 2nd argument to the sqlite3_exec() callback function is the
** number of columns in the result.  ^The 3rd argument to the sqlite3_exec()
** callback is an array of pointers to strings obtained as if from
** [sqlite3_column_text()], one for each column.  ^If an element of a
** result row is NULL then the corresponding string pointer for the
** sqlite3_exec() callback is a NULL pointer.  ^The 4th argument to the
** sqlite3_exec() callback is an array of pointers to strings where each
** entry represents the name of corresponding result column as obtained
** from [sqlite3_column_name()].
**
** ^If the 2nd parameter to sqlite3_exec() is a NULL pointer, a pointer
** to an empty string, or a pointer that contains only whitespace and/or
** SQL comments, then no SQL statements are evaluated and the database
** is not changed.
**
** Restrictions:
**
** <ul>
** <li> The application must ensure that the 1st parameter to sqlite3_exec()
**      is a valid and open [database connection].
** <li> The application must not close the [database connection] specified by
**      the 1st parameter to sqlite3_exec() while sqlite3_exec() is running.
** <li> The application must not modify the SQL statement text passed into
**      the 2nd parameter of sqlite3_exec() while sqlite3_exec() is running.
** </ul>
*/
// typedef int (*sqlite3_callback)(void*,int,char**, char**);

int print_yes(void* a, int b, char**c, char**d)
{
	
	printf("command returned a= %d  b=%d\n", (int )a,b );
	return 0;
}
sqlite3_callback print_stuff = print_yes;


/**  \note  Dave, if you forget what you are doing in this file, you discovered that the meshnetworks was populated with 
 * function calls for sqlite3 but there was no evidence the developers did actual testing, the SQL calls didn't work on the 
 * command line so you suspected the entire file was bogus.
 * 
 * So your next task is to program, step by step, the sqlite3 function calls and verify they work.
 * 
 * Why?
 * 
 * You discovered the sqlite3 was a serverless DB and so you want to experiment with it for things like massively parallel megacities processes and perhaps low level small MCU operation.
 * 
 * You don't know per se where your research will land up so this is prudent to go slow and make sure it works.
 * 
 * */

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 


#ifndef intel_mdb
#include "meshdb.h"
#endif


int main( int argc, char *argv[] )
{

//struct util_cert selfcert;
//struct util_cert selftlscert;
//struct util_cert selftlsclientcert;
	
	//! Extract out meshdb operations and make sure they work.

	// taken from meshctrl
    int l =0, i=0;
    char* str;
	sqlite3 *db = NULL;    
    char* szPathPtr = "mesh.db";
    // error messages received
     char *zErrMsg;
	//! \var rc is the global rc from the database functions
	int rc;

    // Mesh Setup
    l = mdb_open( 1 );// using local here

    //! ported over  to make this create certificates on the test
    printf("Generating database...\r\n", l);

	

    printf(" returned value: %d \n", l);
   	// Generate a new node certificate
    printf("Generating util_mkCert...\r\n");   	
//	l = util_mkCert(NULL, &selfcert, 2048, 10000, "RootCertificate", CERTIFICATE_ROOT);
/*	
    MSG("Generating util_to_p12...\r\n"); 	
	l = util_to_p12(selfcert, "hidden", &str);
	mdb_set("SelfNodeCert", str, l);
	util_free(str);


			// Generate a new TLS certificate
			l = util_mkCert(&selfcert, &selftlscert, 2048, 10000, "localhost", CERTIFICATE_TLS_SERVER);
			l = util_to_p12(selftlscert, "hidden", &str);
			mdb_set("SelfNodeTlsCert", str, l);
			util_free(str);

			// Generate a new TLS client certificate
			l = util_mkCert(&selfcert, &selftlsclientcert, 2048, 10000, "localhost", CERTIFICATE_TLS_CLIENT);
			l = util_to_p12(selftlsclientcert, "hidden", &str);
			mdb_set("SelfNodeTlsClientCert", str, l);
			util_free(str);

			MSG("Certificates ready.\r\n");
			break;

    // Get our current serial number, add 1 more for safety.
    g_serial = mdb_get_i("nodeserial") + 1;

    // Setup the session secret key
    g_SessionRandomId = g_serial;
    util_random(32, g_SessionRandom);

    // Compute our own NodeID & setup packet used for multicast at the same time
    util_keyhash(selfcert, g_selfid);
    ((unsigned short*)g_selfid_mcast)[0] = PB_NODEID;
    ((unsigned short*)g_selfid_mcast)[1] = 36;
    memcpy(g_selfid_mcast + 4, g_selfid, UTIL_HASHSIZE);

    // Compute our latest node block
    ctrl_GetCurrentSignedNodeInfoBlock(&str);

    // Setup local subscriptions
    memset(ctrl_SubscriptionChain, 0, sizeof(struct LocalSubscription) * 8);	// Clear the subscription list
    ctrl_SubscriptionLoopback.sin_family = AF_INET;								// IPv4
#ifdef WINSOCK2
    ctrl_SubscriptionLoopback.sin_addr.S_un.S_addr = 0x0100007F;				// 127.0.0.1
#else
    ctrl_SubscriptionLoopback.sin_addr.s_addr = 0x0100007F;						// 127.0.0.1
#endif

    return 0;
    */	
	


/*

   printf("mesh database opening %d \n", rc);
	//SQLITE_API int sqlite3_open(
	//const char *filename,   // Database filename (UTF-8) 
	//sqlite3 **ppDb          // OUT: SQLite db handle  
	//);
	rc =  sqlite3_open(   szPathPtr,    &db           );
	
//	printf("mesh database opened %d \n", rc);
	
	
	// internal content stuff:
	//SQLITE_API int sqlite3_exec(
	//sqlite3*,                                  /* An open database */
	//const char *sql,                           /* SQL to be evaluated */
	//int (*callback)(void*,int,char**,char**),  /* Callback function */
	//void *,                                    /* 1st argument to callback */
	//char **errmsg                              /* Error msg written here */
	//};
	// SELECT tbl_name FROM sqlite_master WHERE type = 'table'
	//rc = sqlite3_exec(db, "SELECT ID from COMPANY WHERE NAME = 'Paul'", print_stuff, &i, "Create blocks Table Failed \n");
//	rc = sqlite3_exec(db, "SELECT ID from COMPANY WHERE NAME = 'Allen'", print_stuff, &i, &zErrMsg);
//	printf("command returned rc = %d a= %d \n", rc,  (int )(i) );
	
	
	///! start by making the database load in the 
//    rc =   sqlite3_close(  db  );

//   printf("mesh database closed %d \n", rc);
   return 0;
 
}
