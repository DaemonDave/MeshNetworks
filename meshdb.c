/*
   Copyright 2009 Intel Corporation

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
#ifndef intel_mdb
#include "meshdb.h"
#endif


/*! 
 * SQLite Storage Classes

Each value stored in an SQLite database has one of the following storage classes −
Sr.No. 	Storage Class & Description
1 	

NULL

The value is a NULL value.
2 	

INTEGER

The value is a signed integer, stored in 1, 2, 3, 4, 6, or 8 bytes depending on the magnitude of the value.
3 	

REAL

The value is a floating point value, stored as an 8-byte IEEE floating point number.
4 	

TEXT

The value is a text string, stored using the database encoding (UTF-8, UTF-16BE or UTF-16LE)
5 	

BLOB

The value is a blob of data, stored exactly as it was input.

SQLite storage class is slightly more general than a datatype. The INTEGER storage class, for example, includes 6 different integer datatypes of different lengths.
SQLite Affinity Type

SQLite supports the concept of type affinity on columns. Any column can still store any type of data but the preferred storage class for a column is called its affinity. Each table column in an SQLite3 database is assigned one of the following type affinities −
Sr.No. 	Affinity & Description
1 	 TEXT

This column stores all data using storage classes NULL, TEXT or BLOB.
2 	NUMERIC

This column may contain values using all five storage classes.
3 	INTEGER

Behaves the same as a column with NUMERIC affinity, with an exception in a CAST expression.
4 	REAL

Behaves like a column with NUMERIC affinity except that it forces integer values into floating point representation.
5 	NONE

A column with affinity NONE does not prefer one storage class over another and no attempt is made to coerce data from one storage class into another.
SQLite Affinity and Type Names

Following table lists down various data type names which can be used while creating SQLite3 tables with the corresponding applied affinity.
Data Type 						Affinity

    INT
    INTEGER
    TINYINT
    SMALLINT					INTEGER
    MEDIUMINT
    BIGINT
    UNSIGNED BIG INT
    INT2
    INT8

	

    CHARACTER(20)
    VARCHAR(255)
    VARYING CHARACTER(255)	    TEXT
    NCHAR(55)
    NATIVE CHARACTER(70)
    NVARCHAR(100)
    TEXT
    CLOB

	

    BLOB					 no datatype specified
   

	NONE

    REAL					REAL
    DOUBLE
    DOUBLE PRECISION
    FLOAT

	

    NUMERIC
    DECIMAL(10,5)			NUMERIC
    BOOLEAN
    DATE   				    DATETIME

	
Boolean Datatype

SQLite does not have a separate Boolean storage class. Instead, Boolean values are stored as integers 0 (false) and 1 (true).
Date and Time Datatype

SQLite does not have a separate storage class for storing dates and/or times, but SQLite is capable of storing dates and times as TEXT, REAL or INTEGER values.
Sr.No. 		Storage  Class & Date Formate
1 			TEXT     A date in a format like "YYYY-MM-DD HH:MM:SS.SSS"
2 			REAL     The number of days since noon in Greenwich on November 24, 4714 B.C.
3 			INTEGER  The number of seconds since 1970-01-01 00:00:00 UTC

You can choose to store dates and times in any of these formats and freely convert between formats using the built-in date and time functions.
 * 
 * 
 * */



sqlite3 *db = NULL;
sqlite3 *mdb = NULL;
const char *zErrMsg = 0;
//! \var rc is the global rc from the database functions
int rc;

unsigned int synccounter;



#define DB_VERSION 1
#define INET_SOCKADDR_LENGTH(x) ((x==AF_INET6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in)))

// Block Prepared Statements
sqlite3_stmt *stmt_obtain_block;
sqlite3_stmt *stmt_delete_block;
sqlite3_stmt *stmt_insert_block;
sqlite3_stmt *stmt_update_block;
sqlite3_stmt *stmt_metadt_block;

// Node Prepared Statements
sqlite3_stmt *stmt_insert_target;
sqlite3_stmt *stmt_atempt_target;
sqlite3_stmt *stmt_update_target;
sqlite3_stmt *stmt_obtain_target;
sqlite3_stmt *stmt_select_target;
sqlite3_stmt *stmt_rowcnt_target;
sqlite3_stmt *stmt_workit_target;
sqlite3_stmt *stmt_delete_target;
sqlite3_stmt *stmt_setkey_target;
sqlite3_stmt *stmt_metaup_target;
sqlite3_stmt *stmt_metadt_target;

// Settings Prepared Statements
sqlite3_stmt *stmt_obtain_setting;
sqlite3_stmt *stmt_delete_setting;
sqlite3_stmt *stmt_update_setting;

// Settings Prepared Statements
sqlite3_stmt *stmt_obtain_events;
sqlite3_stmt *stmt_insert_events;

//! \note These are great for understanding the way that this source code 


// Block Statement Strings
const char* stmt_obtain_block_str = "SELECT * FROM blocks WHERE blockid=?1";
const char* stmt_getall_block_str = "SELECT * FROM blocks WHERE synccount>?1";
const char* stmt_delete_block_str = "DELETE FROM blocks WHERE blockid=?1";
const char* stmt_insert_block_str = "INSERT INTO blocks VALUES (?1, ?2, ?3, DATETIME('now'), ?4, ?5)";
const char* stmt_update_block_str = "UPDATE blocks SET serial=?2, data=?3, schange=DATETIME('now'), synccount=?4 WHERE blockid=?1";
const char* stmt_metadt_block_str = "SELECT blockid, serial, data FROM blocks WHERE blockid > ?1 ORDER BY blockid";

// Targets Statement Strings
const char* stmt_insert_target_str = "INSERT INTO targets VALUES (?1, ?2, ?3, DATETIME('now'), \"1960-01-01 00:00:00\", ?4, NULL, 0, ?5, ?6, ?7)";
const char* stmt_atempt_target_str = "UPDATE targets SET lastattempt=DATETIME('now') WHERE address=?1";
const char* stmt_update_target_str = "UPDATE targets SET blockid=?2, lastattempt=DATETIME('now'), lastcontact=DATETIME('now'), state=?3, power=?4, distance=?5 WHERE address=?1";
const char* stmt_obtain_target_str = "SELECT blockid, state, power, sessionkey, serial FROM targets WHERE address=?1";
const char* stmt_select_target_str = "SELECT *, strftime('%s', 'now') - strftime('%s', lastcontact) FROM targets";
const char* stmt_rowcnt_target_str = "SELECT COUNT(*) FROM targets";
const char* stmt_workit_target_str = "SELECT *, strftime('%s', 'now') - strftime('%s', lastcontact) FROM targets WHERE lastattempt < DATETIME('now', '-10 seconds') ORDER BY lastattempt"; // -5 minutes is normal
const char* stmt_delete_target_str = "DELETE FROM targets WHERE address=?1 AND lastcontact < DATETIME('now', '-60 seconds')";
const char* stmt_setkey_target_str = "UPDATE targets SET sessionkey=?2 WHERE blockid=?1";
const char* stmt_metaup_target_str = "UPDATE targets SET nextsync=?2 WHERE blockid=?1";
const char* stmt_metadt_target_str = "SELECT blockid, serial FROM targets WHERE blockid > ?1 GROUP BY blockid ORDER BY blockid";

// Temporary queries
const char* stmt_getserial_str = "SELECT serial FROM blocks WHERE blockid=?1";
const char* stmt_setserial_str = "UPDATE targets SET serial=?2 WHERE blockid=?1";
const char* stmt_getbucket_str = "SELECT distance, count(*) FROM targets WHERE state != 2 GROUP BY distance"; // All nodes that are not in Intel AMT mode (State 2) count against buckets.

// Settings Statement Strings
const char* stmt_obtain_setting_str = "SELECT sdata FROM settings WHERE skey=?1";
const char* stmt_delete_setting_str = "DELETE FROM settings WHERE skey=?1";
const char* stmt_update_setting_str = "REPLACE INTO settings VALUES (?1, ?2)";

// Events Statement Strings
const char* stmt_obtain_event_str = "SELECT * FROM events ORDER BY id DESC";
const char* stmt_insert_event_str = "INSERT INTO events VALUES (NULL, DATETIME('now'), ?1)";

// Database creation Strings
const char* stmt_create_event_str = "INSERT INTO events VALUES (NULL, DATETIME('now'), ?1)";

unsigned int mdb_getsynccounter() 
{
    return synccounter;
}
unsigned int mdb_addsynccounter() 
{
    return ++synccounter;
}
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

//int print_yes(void* a, int b, char**c, char**d)
//{
//	printf("command returned b= %d\n", b);
//}
//sqlite3_callback print_stuff = print_yes;
//! \fn mdb_create start run create commands on the database file
int   mdb_create( char * filename )
{
    ///sqlite3_stmt *stmt;
    sqlite3_stmt *stmt;
    const char *tail;
    char *buf;
    unsigned int i;
    int r = 0;
    char random[64];
    char* szPathPtr = "mesh.db";
    
    
    // specify the database filename if not default.
    if (filename == NULL);
    else  szPathPtr =  filename;
        
    // creates the table in the database
    
    //! \note 
    //SQLITE_API int sqlite3_exec(
	//sqlite3*,                                  /* An open database */
	//const char *sql,                           /* SQL to be evaluated */
	//int (*callback)(void*,int,char**,char**),  /* Callback function */
	//void *,                                    /* 1st argument to callback */
	//char **errmsg                              /* Error msg written here */
	//);
    //rc = sqlite3_exec(db, "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);", NULL, 0, NULL);
    rc = sqlite3_exec(db, "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);", NULL, 0, "Create settings Table Failed \n");
    if (rc == 0)
    {
		// inserts tables into database
        r = 2; // Database requires setup
        rc = sqlite3_exec(db, "CREATE TABLE blocks  (blockid BOOLEAN(32) PRIMARY KEY, serial INTEGER, data BLOB, schange DATE, synccount INTEGER, blocktype INTEGER);", NULL, 0, "Create blocks Table Failed \n");
        rc = sqlite3_exec(db, "CREATE TABLE revoked (blockid BINARY(32) PRIMARY KEY, meshid BINARY(32));", NULL, 0, "Create revoked Table Failed \n");
        rc = sqlite3_exec(db, "CREATE TABLE events  (id INTEGER PRIMARY KEY, time DATE, message TEXT);", NULL, 0, "Create events Table Failed \n"); // This is for debug, but we keep it in release for compatiblity with debug build.
    }    
    // insert some valid yet dummy records to start the database off
    rc = sqlite3_exec(db, "INSERT INTO settings  (skey TEXT PRIMARY KEY, sdata BLOB) USING VALUES ( 'California', 045FFFF );", NULL, 0,  "INSERT INTO settings Failed \n");
    rc = sqlite3_exec(db, "INSERT INTO settings  (skey TEXT PRIMARY KEY, sdata BLOB)  USING VALUES ( 'Texas', 885FFFF);", NULL, 0, "INSERT INTO settings Failed \n");
    rc = sqlite3_exec(db, "INSERT INTO settings  (skey TEXT PRIMARY KEY, sdata BLOB)  USING VALUES ( 'Montana', FFFF777 );", NULL, 0, "INSERT INTO settings Failed \n");
    // insert into blocks nominal values that aren't realistic but recognizable...
    rc = sqlite3_exec(db, "INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype) VALUES ( 0x045FFFF, 1021,  'California', 12/12/1200, 042, 99);", NULL, 0, "INSERT INTO blocks Failed \n");
    // good statement : INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype) VALUES ( 0x045FFFF, 1022,  'California', 12/12/1200, 042, 99);
    rc = sqlite3_exec(db, "INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype)   USING VALUES ( 0x045FFFF, 1022,  'Texas', 12/12/1200, 042, 99 );", NULL, 0, "INSERT INTO blocks Failed \n");
    rc = sqlite3_exec(db, "INSERT INTO blocks  (blockid, serial, data, schange, synccount, blocktype)   USING VALUES (  0x045FFFF, 1023,  'Montana', 12/12/1200, 042, 99 );", NULL, 0, "INSERT INTO blocks Failed \n");
    // revoked blocks
	rc = sqlite3_exec(db, "INSERT INTO revoked (blockid, meshid) USING VALUES ( 0x045FFFF,  042);", NULL, 0, "INSERT INTO revoked Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO revoked (blockid, meshid) USING VALUES ( 0x045FFFF,  042);", NULL, 0, "INSERT INTO revoked Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO revoked (blockid, meshid) USING VALUES ( 0x045FFFF,  042);", NULL, 0, "INSERT INTO revoked Failed \n");    
    // last entry 
	rc = sqlite3_exec(db, "INSERT INTO events (id INTEGER PRIMARY KEY, time DATE, message TEXT) USING VALUES ( 0x045FFFF, 12/12/1200,  'Montana');", NULL, 0, "INSERT INTO events Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO events (id INTEGER PRIMARY KEY, time DATE, message TEXT) USING VALUES ( 0x045FFFF, 12/12/1200,  'California');", NULL, 0, "INSERT INTO events Failed \n");    
	rc = sqlite3_exec(db, "INSERT INTO events (id INTEGER PRIMARY KEY, time DATE, message TEXT) USING VALUES ( 0x045FFFF, 12/12/1200,  'Texas');", NULL, 0, "INSERT INTO events Failed \n");        
    
       
}



//! \fn mdb_open start sql and use local version if var local ==0
int   mdb_open( int local )
{
    sqlite3_stmt *stmt;
    const char *tail;
    char *buf;
    unsigned int i;
    int r = 0;
    char random[64];
    char* szPathPtr = "mesh.db";

    // Fetch the database folder (Windows version)
    // When running as a service, the database will be stored in:
    // C:\Windows\system32\config\systemprofile\AppData\Roaming\MeshAgent\mesh.db
#ifdef WIN32
    char szPath[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, szPath) != S_FALSE)
    {
        size_t len = strlen(szPath);
        if (len + 19 <= MAX_PATH)
        {
            memcpy(szPath + len, "\\MeshAgent\\", 12);
            CreateDirectoryA(szPath, NULL); // We don't care about the error code, path may already exist.
            memcpy(szPath + len + 11, "mesh.db", 8);
            szPathPtr = szPath;
        }
    }
#endif

    // Fetch the database folder (Linux version)
#ifdef _POSIX
    //! the path to 
    char szPath[PATH_MAX];
    char* homepath;
    size_t len;
    if ( !local) // find filesystem mesh database
    {
		homepath = getenv("HOME");
		len = strlen(homepath);

		// We check "/tmp/" so not to use that folder on embedded devices (DD-WRT).
		if (len + 20 <= PATH_MAX && memcmp(homepath, "/tmp/", 5) != 0)
		{
			memcpy(szPath, homepath, len);
			memcpy(szPath + len, "/.meshagent/", 13);
			if (mkdir(szPath, S_IRWXU) == 0 || errno == EEXIST)
			{
				memcpy(szPath + len + 12, "mesh.db", 8);
				szPathPtr = szPath;
			}
		}
	}
	else // select local database
	{
		memcpy(szPath, "mesh.db", strlen("mesh.db"));
		szPathPtr = strlen("mesh.db");		
	}
#endif

    // Setup the on disk database (Used for storing signed blocks)
    if (db != NULL) return 1;
    rc = sqlite3_open_v2(szPathPtr, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (db == NULL) return 1;
    if (rc != 0) 
    {
        mdb_checkerror();
        return 1;
    }

    // Check the database version, this is important for future proofing.
    rc = sqlite3_prepare(db, stmt_obtain_setting_str, (int)strlen(stmt_obtain_setting_str), &stmt_obtain_setting, &tail);
    if (mdb_get_i("dbversion") != DB_VERSION)
    {
        // This database has the wrong signature, delete it.
        sqlite3_finalize(stmt_obtain_setting);
        sqlite3_close(db);
        remove(szPathPtr);
        rc = sqlite3_open_v2(szPathPtr, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        if (db == NULL) return 1;
        if (rc != 0) 
        {
            mdb_checkerror();
            return 1;
        }
    }
    else sqlite3_finalize(stmt_obtain_setting);

    // Lets see if the proper tables are created already
    rc = sqlite3_exec(db, "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);", NULL, 0, NULL);
    if (rc == 0)
    {
        r = 2; // Database requires setup
        rc = sqlite3_exec(db, "CREATE TABLE blocks  (blockid BINARY(32) PRIMARY KEY, serial INTEGER, data BLOB, schange DATE, synccount INTEGER, blocktype INTEGER);", NULL, 0, NULL);
        rc = sqlite3_exec(db, "CREATE TABLE revoked (blockid BINARY(32) PRIMARY KEY, meshid BINARY(32));", NULL, 0, NULL);
        rc = sqlite3_exec(db, "CREATE TABLE events  (id INTEGER PRIMARY KEY, time DATE, message TEXT);", NULL, 0, NULL); // This is for debug, but we keep it in release for compatiblity with debug build.
    }

    // Setup the in-memory database (Used for storing dynamic node information)
#ifdef _DEBUG
    // In debug mode, we store this on disk so we can use debug tools.
    rc = sqlite3_open_v2(":memory:", &mdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    //rc = sqlite3_open_v2("meshm.db", &mdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != 0) 
    {
        sqlite3_close(db);
        mdb_checkerror();
        return 1;
    }
    if (mdb == NULL) 
    {
        sqlite3_close(db);
        return 1;
    }
    rc = sqlite3_exec(mdb, "DROP TABLE nodes;", NULL, 0, NULL);
#else
    rc = sqlite3_open_v2(":memory:", &mdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != 0) 
    {
        mdb_checkerror();
        return 1;
    }
#endif
    rc = sqlite3_exec(mdb, "CREATE TABLE targets (address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastattempt DATE, lastcontact DATE, power INTEGER, sessionkey BINARY(36), iv INTEGER, nextsync BINARY(32), serial INTEGER, distance INTEGER);", NULL, 0, NULL);

    // Prepare block statements
    rc = sqlite3_prepare(db, stmt_obtain_block_str, (int)strlen(stmt_obtain_block_str), &stmt_obtain_block, &tail);
    rc = sqlite3_prepare(db, stmt_delete_block_str, (int)strlen(stmt_delete_block_str), &stmt_delete_block, &tail);
    rc = sqlite3_prepare(db, stmt_insert_block_str, (int)strlen(stmt_insert_block_str), &stmt_insert_block, &tail);
    rc = sqlite3_prepare(db, stmt_update_block_str, (int)strlen(stmt_update_block_str), &stmt_update_block, &tail);
    rc = sqlite3_prepare(db, stmt_metadt_block_str, (int)strlen(stmt_metadt_block_str), &stmt_metadt_block, &tail);

    // Prepare node statements
    rc = sqlite3_prepare(mdb, stmt_insert_target_str, (int)strlen(stmt_insert_target_str), &stmt_insert_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_atempt_target_str, (int)strlen(stmt_atempt_target_str), &stmt_atempt_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_update_target_str, (int)strlen(stmt_update_target_str), &stmt_update_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_obtain_target_str, (int)strlen(stmt_obtain_target_str), &stmt_obtain_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_select_target_str, (int)strlen(stmt_select_target_str), &stmt_select_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_rowcnt_target_str, (int)strlen(stmt_rowcnt_target_str), &stmt_rowcnt_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_workit_target_str, (int)strlen(stmt_workit_target_str), &stmt_workit_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_delete_target_str, (int)strlen(stmt_delete_target_str), &stmt_delete_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_setkey_target_str, (int)strlen(stmt_setkey_target_str), &stmt_setkey_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_metaup_target_str, (int)strlen(stmt_metaup_target_str), &stmt_metaup_target, &tail);
    rc = sqlite3_prepare(mdb, stmt_metadt_target_str, (int)strlen(stmt_metadt_target_str), &stmt_metadt_target, &tail);

    // Prepare settings statements
    rc = sqlite3_prepare(db, stmt_obtain_setting_str, (int)strlen(stmt_obtain_setting_str), &stmt_obtain_setting, &tail);
    rc = sqlite3_prepare(db, stmt_delete_setting_str, (int)strlen(stmt_delete_setting_str), &stmt_delete_setting, &tail);
    rc = sqlite3_prepare(db, stmt_update_setting_str, (int)strlen(stmt_update_setting_str), &stmt_update_setting, &tail);

    // Prepare events statements
    rc = sqlite3_prepare(db, stmt_obtain_event_str, (int)strlen(stmt_obtain_event_str), &stmt_obtain_events, &tail);
    rc = sqlite3_prepare(db, stmt_insert_event_str, (int)strlen(stmt_insert_event_str), &stmt_insert_events, &tail);

    // Setup Sync Counter & Fetch the MAX sync counter
    rc = sqlite3_prepare(db, "SELECT MAX(synccount) FROM blocks;", -1, &stmt, &tail);
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) synccounter = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    i = mdb_get_i("signedblocksynccounter");
    if (i > synccounter) synccounter = i;

    // Add more random seeding and save new random for next time.
    rc = mdb_get("random", &buf);
    if (rc != 0) 
    {
		/// old code
        //RAND_add(buf, rc, rc);
        int j;
        
        /// new code a temporary set in to remove need for OpenSSL
        for (j = 0; j < sizeof(buf) - 1; j++) 
        {
			rc += (unsigned short)buf[j];
        }
        free(buf);
    }
    util_random(64, random);
    mdb_set("random", random, 64);

    // Clear the distance buckets
    memset(g_distancebuckets, 0, 32);

    // Set the database version
    mdb_set_i("dbversion", DB_VERSION);

    return r;
}

void mdb_close()
{
    // Cleanup block prepared statements
    sqlite3_finalize(stmt_obtain_block);
    sqlite3_finalize(stmt_delete_block);
    sqlite3_finalize(stmt_insert_block);
    sqlite3_finalize(stmt_update_block);
    sqlite3_finalize(stmt_metadt_block);

    // Cleanup node prepared statements
    sqlite3_finalize(stmt_insert_target);
    sqlite3_finalize(stmt_atempt_target);
    sqlite3_finalize(stmt_update_target);
    sqlite3_finalize(stmt_obtain_target);
    sqlite3_finalize(stmt_select_target);
    sqlite3_finalize(stmt_rowcnt_target);
    sqlite3_finalize(stmt_workit_target);
    sqlite3_finalize(stmt_delete_target);
    sqlite3_finalize(stmt_setkey_target);
    sqlite3_finalize(stmt_metaup_target);
    sqlite3_finalize(stmt_metadt_target);

    // Cleanup settings prepared statements
    sqlite3_finalize(stmt_obtain_setting);
    sqlite3_finalize(stmt_delete_setting);
    sqlite3_finalize(stmt_update_setting);

    // Cleanup events prepared statements
    sqlite3_finalize(stmt_obtain_events);
    sqlite3_finalize(stmt_insert_events);

    // Close databases
    if (db != NULL) 
    {
        rc = sqlite3_close(db);
        db = NULL;
    }
    if (mdb != NULL) 
    {
        rc = sqlite3_close(mdb);
        mdb = NULL;
    }
}
//! \fn  mdb_commit read state to db
void mdb_begin()
{
    sqlite3_exec(db, "BEGIN;", NULL, 0, NULL);
}
//! \fn  mdb_commit store state to db
void mdb_commit()
{
    sqlite3_exec(db, "COMMIT;", NULL, 0, NULL);
}

void mdb_checkerror()
{
    zErrMsg = sqlite3_errmsg(db);
    zErrMsg = sqlite3_errmsg(mdb);
}

// Set a key and value pair in the settings database
void mdb_set(char* key, char* value, int length)
{
    // "REPLACE INTO settings VALUES (?1, ?2)"
    rc = sqlite3_bind_text(stmt_update_setting, 1, key, (int)strlen(key), SQLITE_STATIC); // Key
    rc = sqlite3_bind_blob(stmt_update_setting, 2, value, length, SQLITE_STATIC); // Value
    rc = sqlite3_step(stmt_update_setting);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_update_setting);
}

// Get a blob value from a key in the settings database
int mdb_get(char* key, char** value)
{
    int len = 0;
    *value = NULL;
    // "SELECT sdata FROM settings WHERE skey=?1";
    rc = sqlite3_bind_text(stmt_obtain_setting, 1, key, (int)strlen(key), SQLITE_STATIC); // Key
    rc = sqlite3_step(stmt_obtain_setting);
    if (rc == SQLITE_ROW && (len = sqlite3_column_bytes(stmt_obtain_setting, 0)) != 0)
    {
        if ((*value = malloc(len+1)) == NULL) ILIBCRITICALEXIT(254);
        (*value)[len] = 0;
        memcpy(*value, sqlite3_column_blob(stmt_obtain_setting, 0), len);
    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_setting);
    return len;
}

// Set an int value to a key in the settings database
void mdb_set_i(char* key, int value)
{
    int len;
    len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), "%d", value);
    mdb_set(key, ILibScratchPad, len);
}

// Get a blob value from a key in the settings database
int mdb_get_i(char* key)
{
    int len;
    char* value;
    int val;
    len = mdb_get(key, &value);
    if (len == 0) return 0;
    val = atoi(value);
    mdb_free(value);
    return val;
}

// Clear a setting from the database
void mdb_remove(char* key)
{
    // "DELETE FROM settings WHERE skey=?1";
    rc = sqlite3_bind_text(stmt_delete_setting, 1, key, (int)strlen(key), SQLITE_STATIC); // Key
    rc = sqlite3_step(stmt_delete_setting);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_delete_setting);
}

// Frees a block of memory returned from this module.
void mdb_free(char* ptr)
{
    free(ptr);
    ptr = NULL;
}

// Checks the existance of a nodeid in the database. Returns 1 if it is present and 0 if not.
int mdb_blockexist(char* blockid)
{
    // "SELECT blockid FROM blocks WHERE nodeid=?1";
    int r = 0;
    rc = sqlite3_bind_blob(stmt_obtain_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_obtain_block);
    if (rc == SQLITE_ROW) r = 1;
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_block);
    return r;
}

// Fetch a block using the block id
int mdb_blockget(char* blockid, char** block)
{
    // "SELECT * FROM blocks WHERE blockid=?1"
    int r = 0;
    *block = NULL;
    rc = sqlite3_bind_blob(stmt_obtain_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_obtain_block);
    if (rc == SQLITE_ROW)
    {
        r = sqlite3_column_bytes(stmt_obtain_block, 2);
        if ((*block = malloc(r)) == NULL) ILIBCRITICALEXIT(254);
        memcpy(*block, sqlite3_column_blob(stmt_obtain_block, 2), r);
    }
    else *block = NULL;
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_block);
    return r;
}

// Removes a node from the database, ignored if the node is not present.
void mdb_blockclear(char* blockid)
{
    // "DELETE FROM blocks WHERE blockid=?1";
    rc = sqlite3_bind_blob(stmt_delete_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_delete_block);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_delete_block);
}

// Removes all nodes and blocks from the databases
void  mdb_clearall()
{
    // "DELETE FROM nodes";
    rc = sqlite3_exec(db, "DELETE FROM nodes;", NULL, 0, NULL);
    // "DELETE FROM blocks";
    rc = sqlite3_exec(db, "DELETE FROM blocks;", NULL, 0, NULL);
}

// Get the current serial number for a given node
unsigned int mdb_getserial(char* nodeid)
{
    // const char* stmt_getserial_str = "SELECT serial FROM blocks WHERE blockid=?1";
    sqlite3_stmt *tmp;
    unsigned int serial = 0;
    rc = sqlite3_prepare(db, stmt_getserial_str, (int)strlen(stmt_getserial_str), &tmp, NULL);
    rc = sqlite3_bind_blob(tmp, 1, nodeid, UTIL_HASHSIZE, SQLITE_STATIC);	// Block ID
    rc = sqlite3_step(tmp);
    if (rc == SQLITE_ROW) 
    {
        serial = sqlite3_column_int(tmp, 0);
    }
    sqlite3_finalize(tmp);
    return serial;
}

// Set a new serial number for a push block in the target table
void mdb_setserial(char* nodeid, unsigned int serial)
{
    // const char* stmt_setserial_str = "UPDATE targets SET serial=?2 WHERE blockid=?1";
    sqlite3_stmt *tmp;
    rc = sqlite3_prepare(mdb, stmt_setserial_str, (int)strlen(stmt_setserial_str), &tmp, NULL);
    rc = sqlite3_bind_blob(tmp, 1, nodeid, UTIL_HASHSIZE, SQLITE_STATIC);	// Block ID
    rc = sqlite3_bind_int(tmp, 2, serial);									// Serial
    rc = sqlite3_step(tmp);
    sqlite3_finalize(tmp);
}

// Updated a node in the database if the information is more recent. Adds the node if it's missing.
int mdb_blockset(char* blockid, int serial, char* node, int nodelen)
{
    // Get the existing node serial number
    int t_serial = 0;
    int t_exists = 0;

    // "SELECT * FROM blocks WHERE blockid=?1";
    rc = sqlite3_bind_blob(stmt_obtain_block, 1, blockid, UTIL_HASHSIZE, SQLITE_STATIC); // Block ID
    rc = sqlite3_step(stmt_obtain_block);
    if (rc == SQLITE_ROW)
    {
        t_serial = sqlite3_column_int(stmt_obtain_block, 1);
        t_exists = 1;
    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_block);

    if (t_exists == 0)
    {
        // "INSERT INTO blocks VALUES (?1, ?2, ?3, DATETIME('now'), ?4, ?5, 0, ?6)";
        rc = sqlite3_bind_blob(stmt_insert_block, 1, blockid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Block ID
        rc = sqlite3_bind_int(stmt_insert_block, 2, serial); // Block Serial
        rc = sqlite3_bind_blob(stmt_insert_block, 3, node, nodelen, SQLITE_TRANSIENT); // Block
        rc = sqlite3_bind_int(stmt_insert_block, 4, ++synccounter); // Sync Counter
        rc = sqlite3_bind_int(stmt_insert_block, 5, ((unsigned short*)node)[0]); // Block Type (first 2 bytes of block)
        rc = sqlite3_step(stmt_insert_block);
        if (rc < SQLITE_ROW) 
        {
            mdb_checkerror();
        }
        rc = sqlite3_reset(stmt_insert_block);
        mdb_setserial(blockid, serial);

        // Send this block as a local event
        //! commented out until network testing...
        /// ctrl_SendSubscriptionEvent(node, nodelen);

        return 1; // Node was added
    }
    else if (t_serial < serial)
    {
        // "UPDATE blocks SET serial=?2, data=?3, schange=DATE('now') WHERE blockid=?1";
        rc = sqlite3_bind_blob(stmt_update_block, 1, blockid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Block ID
        rc = sqlite3_bind_int(stmt_update_block, 2, serial); // Block Serial
        rc = sqlite3_bind_blob(stmt_update_block, 3, node, nodelen, SQLITE_TRANSIENT); // Node Block
        rc = sqlite3_bind_int(stmt_update_block, 4, ++synccounter); // Sync Counter
        rc = sqlite3_step(stmt_update_block);
        if (rc < SQLITE_ROW) 
        {
            mdb_checkerror();
        }
        rc = sqlite3_reset(stmt_update_block);
        mdb_setserial(blockid, serial);

        // Send this block as a local event
      ////  ctrl_SendSubscriptionEvent(node, nodelen);

        return 2; // Node was updated
    }
    return 0; // Node was ignored
}

// Private callback to send all push blocks
void mdb_sendallpushblocksasync_sendok(struct ILibWebServer_Session *sender)
{
    int sendcount = 0;
    unsigned short nodelen;
    char* node;
    int status = 0;
    sqlite3_stmt* query;
    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // If this node is the skip node, skip it
        if (sender->User2 != NULL)
        {
            node = (char*)sqlite3_column_blob(query, 0);
            // Boost speed by comparing first 4 bytes most of the time
            if (((int*)sender->User2)[0] == ((int*)node)[0] && memcmp(sender->User2, node, 32) == 0) continue;
        }

        // Fetch the push block
        nodelen = (unsigned short)sqlite3_column_bytes(query, 2);
        node = (char*)sqlite3_column_blob(query, 2);

        // Send the header & block
        ///status = ILibWebServer_StreamBody(sender, node, nodelen, ILibAsyncSocket_MemoryOwnership_USER,0);
        sendcount++;

        // If the socket is full, break out
        if (status != ILibWebServer_ALL_DATA_SENT) break;
    }
    mdb_commit();

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        if (sender->User2 != NULL) 
        {
            free(sender->User2);
        }
        sqlite3_finalize(query);
        sender->User2 = NULL;
        sender->User3 = NULL;

        // Chain the requests
        mdb_sendasync(sender, sender->User4, NULL, sender->User5);
    }
    else
    {
        //MSG2("Async sent %d nodes...\r\n", sendcount);
    }
}


// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendallpushblocksasync(struct ILibWebServer_Session *sender, unsigned int syncounter, char* skipnode, unsigned int mask)
{
    char* snode = NULL;
    const char *tail;
    sqlite3_stmt* query;

    if (skipnode != NULL)
    {
        if ((snode = malloc(UTIL_HASHSIZE)) == NULL) ILIBCRITICALEXIT(254);
        memcpy(snode, skipnode, UTIL_HASHSIZE);
    }
    rc = sqlite3_prepare(db, stmt_getall_block_str, (int)strlen(stmt_getall_block_str), &query, &tail);
    rc = sqlite3_bind_int(query, 1, syncounter); // Bind the sync counter
    sender->OnSendOK = mdb_sendallpushblocksasync_sendok;
    sender->User2 = (void*)snode;
    sender->User3 = (void*)query;
    sender->User4 = synccounter;
    sender->User5 = mask;
    mdb_sendallpushblocksasync_sendok(sender);
}

// Called when an attempt to connect to a target is made
void mdb_attempttarget(struct sockaddr *addr)
{
    char* addrptr;
    int addrlen = ILibGetAddrBlob(addr, &addrptr);

    // "UPDATE targets SET lastattempt=DATETIME('now') WHERE address=?1";
    sqlite3_bind_blob(stmt_atempt_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);				// Address
    rc = sqlite3_step(stmt_atempt_target);
    sqlite3_reset(stmt_atempt_target);
    return;
}

// Add or update state information about a node
void mdb_updatetarget(char* nodeid, struct sockaddr *addr, unsigned char state, unsigned char power)
{
    unsigned char tstate = -1;
    unsigned char tpower = -1;
    char tempid[UTIL_HASHSIZE];
    char *addrptr;
    int addrlen = ILibGetAddrBlob(addr, &addrptr);
    int distance;

    // If this is an unknown know our own node, delete it.
    if (state == MDB_UNKNOWN || memcmp(nodeid, g_selfid, 32) == 0)
    {
        // "DELETE FROM targets WHERE address=?1"
        sqlite3_bind_blob(stmt_delete_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);			// Address
        rc = sqlite3_step(stmt_delete_target);
        sqlite3_reset(stmt_delete_target);
        if (ctrl_SubscriptionChainCount > 0 && sqlite3_changes(mdb) > 0)
        {
            // Event that this target was removed
            info_event_updatetarget(NULL, addrptr, addrlen, 0, 0);
        }
        return;
    }

    // Fetch the previous state
    tstate = mdb_gettargetstate(addr, tempid, &tpower, NULL, NULL);
    distance = ctrl_Distance(nodeid);

    if (tstate != 0)
    {
        // If we already have an equal or better state with same NodeID, drop this change request
        if (state == MDB_GOTMULTICAST && memcmp(nodeid, tempid, UTIL_HASHSIZE) == 0) return;

        // Lets update the database, we do this even if the entry in the database is missing
        sqlite3_bind_blob(stmt_update_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);			// Address
        sqlite3_bind_blob(stmt_update_target, 2, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT);		// Block ID
        sqlite3_bind_int(stmt_update_target, 3, state);											// State
        sqlite3_bind_int(stmt_update_target, 4, power);											// Power
        sqlite3_bind_int(stmt_update_target, 5, distance);										// XOR Distance
        rc = sqlite3_step(stmt_update_target);
        sqlite3_reset(stmt_update_target);
    }
    else
    {
        mdb_refreshbuckets();																	// TODO: OPTIMIZE: find a way to reduce the number of times this function is called.
        if (g_distancebuckets[distance] >= MESH_MAX_TARGETS_IN_BUCKET) return;

        // We need to insert the node and the bucket is not filled up, lets insert it.
        // "INSERT INTO targets VALUES (?1, ?2, ?3, DATETIME('now'), ?4)";
        sqlite3_bind_blob(stmt_insert_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);			// IP Address
        sqlite3_bind_blob(stmt_insert_target, 2, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT);		// NodeID
        sqlite3_bind_int(stmt_insert_target, 3, state);											// Connectivity state
        sqlite3_bind_int(stmt_insert_target, 4, power);											// Power state
        sqlite3_bind_blob(stmt_insert_target, 5, NullNodeId, 32, SQLITE_TRANSIENT);				// NextSyncID
        sqlite3_bind_int(stmt_insert_target, 6, mdb_getserial(nodeid));							// Push block serial number - TODO: OPTIMIZE THIS
        sqlite3_bind_int(stmt_insert_target, 7, distance);										// XOR Distance
        rc = sqlite3_step(stmt_insert_target);
        sqlite3_reset(stmt_insert_target);
        g_distancebuckets[distance]++;
    }

    if (ctrl_SubscriptionChainCount > 0 && rc != SQLITE_ERROR)// && (tstate != state || tpower != power || memcmp(tempid, nodeid, UTIL_HASHSIZE) != 0))
    {
        // Event that this target was updated
        // TODO: Send this only when there is a real update!
        info_event_updatetarget(nodeid, addrptr, addrlen, state, power);
    }
}


// Add or update state information about a node (NodeID & Key must be pre-allocated or NULL)
unsigned char mdb_gettargetstate(struct sockaddr *addr, char* nodeid, unsigned char* power, char* key, unsigned int* serial)
{
    unsigned char state = 0;
    char* addrptr;
    int addrlen = ILibGetAddrBlob(addr, &addrptr);

    // "SELECT blockid, state, power, sessionkey, serial FROM targets WHERE address=?1";
    sqlite3_bind_blob(stmt_obtain_target, 1, addrptr, addrlen, SQLITE_TRANSIENT);		// Address
    if (sqlite3_step(stmt_obtain_target) == SQLITE_ROW)
    {
        if (nodeid != NULL) memcpy(nodeid, sqlite3_column_blob(stmt_obtain_target, 0), UTIL_HASHSIZE);
        state = (unsigned char)sqlite3_column_int(stmt_obtain_target, 1);
        if (power != NULL) *power = sqlite3_column_int(stmt_obtain_target, 2);
        if (key != NULL && sqlite3_column_bytes(stmt_obtain_target, 3) == 36) memcpy(key, sqlite3_column_blob(stmt_obtain_target, 3), 36);	// Session Key
        if (serial != NULL) *serial = sqlite3_column_int(stmt_obtain_target, 4);
    }

    sqlite3_reset(stmt_obtain_target);
    return state;
}


// Fetch the next target in the rotation that should be sync'ed against (NodeID must be pre-allocated or NULL, address must be freed by user)
void mdb_synctargets()
{
    struct sockaddr_in6 addr;
    char nodeid[32];
    unsigned char power;
    char key[36];
    char* keyptr = NULL;
    char nextsyncblock[36];
    unsigned int lastcontact;
    unsigned int serial;
    int state;
    int len;

    //! \todo make sure int sendresponsekey is the right
    //!  \var sendresponsekey - do we send the response key?
    int sendresponsekey = 1;

    // "SELECT *, strftime('%s', 'now') - strftime('%s', lastcontact) FROM targets WHERE lastattempt < DATETIME('now', '-10 seconds') ORDER BY lastattempt"; // -5 minutes is normal
    // address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastattempt DATE, lastcontact DATE, power INTEGER, sessionkey BINARY(36), iv INTEGER, nextsync BINARY(32), serial INTEGER, distance INTEGER
    while (sqlite3_step(stmt_workit_target) == SQLITE_ROW)
    {
        // Fetch the last contect
        lastcontact = sqlite3_column_int(stmt_workit_target, 11);																			// Seconds since last contact

        // Perform sync if last contact was recent or we have no outstanding
        if (lastcontact < MESH_TLS_FALLBACK_TIMEOUT || g_outstanding_outbound_requests == 0)
        {
            // If this is an Intel AMT computer, wait the full timeout
            state = (unsigned char)sqlite3_column_int(stmt_workit_target, 2);
            if (lastcontact < MESH_TLS_FALLBACK_TIMEOUT && state == MDB_AMTONLY) return;

            // Fetch the IP address
            len = sqlite3_column_bytes(stmt_workit_target, 0);
            memset(&addr, 0, sizeof(struct sockaddr_in6));
            if (len == 4)
            {
                // IPv4 address
                addr.sin6_family = AF_INET;
                ((struct sockaddr_in*)&addr)->sin_port = htons(MESH_AGENT_PORT);
                memcpy(&(((struct sockaddr_in*)&addr)->sin_addr), sqlite3_column_blob(stmt_workit_target, 0), 4);
            }
            else if (len == 16 || len == 20)
            {
                // IPv6 address, or IPv6 + Scope
                memset(&addr, 0, sizeof(struct sockaddr_in6));
                addr.sin6_family = AF_INET6;
                addr.sin6_port = htons(MESH_AGENT_PORT);
                memcpy(&(addr.sin6_addr), sqlite3_column_blob(stmt_workit_target, 0), len);
            }

            // Fetch the rest of the fields
            memcpy(nodeid, sqlite3_column_blob(stmt_workit_target, 1), UTIL_HASHSIZE);															// Node ID
            power = (unsigned char)sqlite3_column_int(stmt_workit_target, 5);																	// Power
            memcpy(nextsyncblock + 4, sqlite3_column_blob(stmt_workit_target, 8), 32);																	// NextSyncID
            serial = sqlite3_column_int(stmt_workit_target, 9);																					// Serial number
            if (sqlite3_column_bytes(stmt_workit_target, 6) == 36)
            {
                memcpy(key, sqlite3_column_blob(stmt_workit_target, 6), 36);					// Session Key
                keyptr = key;
            }

            // Perform the sync
            if (lastcontact < MESH_TLS_FALLBACK_TIMEOUT && keyptr != NULL)
            {
                // Complete building the Sync Start packet
                ((unsigned short*)nextsyncblock)[0] = PB_SYNCSTART;
                ((unsigned short*)nextsyncblock)[1] = 36;

                // Send UDP Syncronization Request
                //SendCryptoUdpToTarget((struct sockaddr*)&addr, nodeid, key, nextsyncblock, 36, sendresponsekey); // Send the SYNCSTART block using UDP
            }
            else
            {
                // Initiate TCP Syncronization Request
                /// commented out until comms fixed
                //ctrl_SyncToNodeTCP((struct sockaddr*)&addr, nodeid, state, keyptr, NULL, lastcontact, serial);
            }
        }
    }

    sqlite3_reset(stmt_workit_target);
}

// Private callback to send all push blocks
void mdb_sendalltargetsasync_sendok(struct ILibWebServer_Session *sender)
{
    int len = 0;
    int status = 0;
    int ptr = 0;
    sqlite3_stmt* query;
    char* packet = ILibScratchPad;

    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    // "SELECT * FROM targets" | address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastattempt DATE, lastcontact DATE, power INTEGER, sessionkey BINARY(36), iv INTEGER, nextsync BINARY(32)
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // This method is optimize to send groups of many targets at once to reduce the number of SSL records sent.
        // The speed up is quite significant for large amounts of small records like this.

        // Fetch the address length
        len = sqlite3_column_bytes(query, 0);

        // Setup the block header
        ((unsigned short*)(packet + ptr))[0] = PB_TARGETSTATUS;
        ((unsigned short*)(packet + ptr))[1] = (unsigned short)(len + 43);

        // Setup BlockID
        memcpy(packet + ptr + 4, (char*)sqlite3_column_blob(query, 1), UTIL_HASHSIZE);

        // Setup state & power
        packet[36 + ptr] = (char)sqlite3_column_int(query, 2);
        packet[37 + ptr] = (char)sqlite3_column_int(query, 5);

        // Setup seconds since last contact. This is an SQL query computation of the number of seconds since the last contact.
        // Since no two clocks in the mesh are assumed to be set correctly, time since now is the only way to go.
        ((unsigned int*)(packet + 38 + ptr))[0] = htonl(sqlite3_column_int(query, 11));

        // Setup the address length
        packet[42 + ptr] = (char)len;

        // Setup the IP address
        memcpy(packet + 43 + ptr, (char*)sqlite3_column_blob(query, 0), len);

        // Add to the pointer
        ptr += len + 43;

        // If we filled 4k worth of data, go ahead and send it out
        if (ptr > 4000)
        {
            // Send the data
            if (ptr > 4096) ILIBCRITICALEXIT(253);
            ///status = ILibWebServer_StreamBody(sender, packet, ptr, ILibAsyncSocket_MemoryOwnership_USER, 0);
            ptr = 0;

            // If the socket is full, break out
            if (status != ILibWebServer_ALL_DATA_SENT) break;
        }
    }
    mdb_commit();

    // If we have something left, this is almost always the case, send it out.
    if (ptr > 0)
    {
        // Send the data
        ///status = ILibWebServer_StreamBody(sender, packet, ptr, ILibAsyncSocket_MemoryOwnership_USER, 0);
    }

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        sqlite3_finalize(query);
        sender->User3 = NULL;

        // Chain the requests
        mdb_sendasync(sender, sender->User4, NULL, sender->User5);
    }
}

// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendalltargetsasync(struct ILibWebServer_Session *sender, unsigned int syncounter, unsigned int mask)
{
    const char *tail;
    sqlite3_stmt* query;

    rc = sqlite3_prepare(mdb, stmt_select_target_str, (int)strlen(stmt_select_target_str), &query, &tail);
    sender->OnSendOK = mdb_sendalltargetsasync_sendok;
    sender->User3 = (void*)query;
    sender->User4 = syncounter;
    sender->User5 = mask;
    mdb_sendalltargetsasync_sendok(sender);
}

// Send a set of async enumerations, the mask indicates what information to send out
void mdb_sendasync(struct ILibWebServer_Session *sender, unsigned int syncounter, char* skipnode, unsigned int mask)
{
    // If mask is empty, close the HTTP session
    if (mask == 0) ;///ILibWebServer_StreamBody(sender, NULL, 0, ILibAsyncSocket_MemoryOwnership_STATIC, 1);
    else if (mask & MDB_SELFNODE)
    {
        // Send self push block
        int l;
        char* str;
        //l = ctrl_GetCurrentSignedNodeInfoBlock(&str);
        ///ILibWebServer_StreamBody(sender, str, l, ILibAsyncSocket_MemoryOwnership_USER, 0);
        mdb_sendasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_SELFNODE));
    }
    else if (mask & MDB_AGENTID)
    {
        // Send self agent information
        char str[10];
        ((unsigned short*)str)[0] = PB_AGENTID;
        ((unsigned short*)str)[1] = 10;
        ((unsigned int*)str)[1] = htonl(MESH_AGENT_VERSION);
        ((unsigned short*)str)[4] = htons(g_agentid);
        //ILibWebServer_StreamBody(sender, str, 10, ILibAsyncSocket_MemoryOwnership_USER, 0);
        mdb_sendasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_AGENTID));
    }
    else if (mask & MDB_SESSIONKEY)
    {
        // Send private session key, used for UDP
        if (sender->CertificateHashPtr != NULL)
        {
            // Compute private session key for this target node, add session key header
            char key[40];
            /// commented out for now.
            ///util_nodesessionkey(sender->CertificateHashPtr, key + 4);
            ((unsigned short*)key)[0] = PB_SESSIONKEY;
            ((unsigned short*)key)[1] = 40;
            ///ILibWebServer_StreamBody(sender, key, 40, ILibAsyncSocket_MemoryOwnership_USER, 0);
        }
        mdb_sendasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_SESSIONKEY));
    }
    else if (mask & MDB_PUSHBLOCKS)
    {
        mdb_sendallpushblocksasync(sender, syncounter, skipnode, mask & ~((unsigned int)MDB_PUSHBLOCKS));	// Send push blocks
    }
    else if (mask & MDB_TARGETS) mdb_sendalltargetsasync(sender, syncounter, mask & ~((unsigned int)MDB_TARGETS));						// Send target information
}

// Save the session key to the target database
void  mdb_setsessionkey(char* nodeid, char* key)
{
    // "UPDATE targets SET sessionkey=?2 WHERE blockid=?1";
    rc = sqlite3_bind_blob(stmt_setkey_target, 1, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Node ID
    rc = sqlite3_bind_blob(stmt_setkey_target, 2, key, 4 + UTIL_HASHSIZE, SQLITE_TRANSIENT); // Key Identifier + Session Key
    rc = sqlite3_step(stmt_setkey_target);
    if (rc < SQLITE_ROW) {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_setkey_target);
}

// Runs thru the node block database and generates a metadata block of a given length.
// The block starts with the standard header, then the startnodeid followed by an
// long set of nodeid/serial. If we get to the end of the database, we terminate with
// a nodeid/serial of all zeros.
int mdb_getmetadatablock(char* startnodeid, int maxsize, char** result, char* skipnodeid)
{
    int ptr = 40;

    // Allocate the block
    if (maxsize < 512) {
        *result = NULL;
        return 0;
    }
    if ((*result = malloc(maxsize)) == NULL) ILIBCRITICALEXIT(254);

    // Run thru the database, ordered by NodeID starting at but excluding startnodeid
    // "SELECT blockid, serial FROM targets WHERE blockid > ?1 GROUP BY blockid ORDER BY blockid"
    //! SQLITE_API int sqlite3_blob_read(sqlite3_blob *, void *Z, int N, int iOffset);
    rc = sqlite3_bind_blob(stmt_metadt_target, 1, startnodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Start Node ID
    while (ptr + 36 < maxsize)
    {
        // If this is the last record, make the end and exit.
        //if ((rc = sqlite3_step(stmt_metadt_target)) != SQLITE_ROW) { memset(*result + ptr, 0, 36); ptr += 36; break; }
        if ((rc = sqlite3_step(stmt_metadt_target)) != SQLITE_ROW) 
        {
            memset(*result + ptr, 0, 1);
            ptr += 1;
            break;
        }

        // If this is the skipped node, skip it.
        if (skipnodeid != NULL && memcmp(skipnodeid, sqlite3_column_blob(stmt_metadt_target, 0), UTIL_HASHSIZE) == 0) continue;

        // Copy the nodeid & serial.
        memcpy((*result) + ptr, sqlite3_column_blob(stmt_metadt_target, 0), UTIL_HASHSIZE);
        ((unsigned int*)((*result) + ptr))[8] = htonl(sqlite3_column_int(stmt_metadt_target, 1));
        ptr += 36;
    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_metadt_target);

    // Add the header and startnodeid
    ((unsigned short*)(*result))[0] = PB_SYNCMETADATA;
    ((unsigned short*)(*result))[1] = ptr;
    memcpy(*result + 4, startnodeid, 32);				// The start NodeID, same as the one requested.
    ((unsigned int*)(*result))[9] = htonl(g_serial);	// Our own current serial number

    return ptr;
}

// This is the tricky task of comparing our own data against a metadata block sent by a peer.
// We got to do this really efficiently and send back UDP packets as we detect differences.
// We will accumulate the push block requests so to minimize the number of UDP packets going out.
void mdb_performsync(char* meta, int metalen, char* nodeid, struct sockaddr *addr, char* key, unsigned int nodeidserial)
{
    int ptr = 0;
    char *snode = NullNodeId;
    char *rnode = NullNodeId;
    unsigned int sserial = 0;
    unsigned int rserial = 0;
    int delta;
    int moveforward = 0;
    int done_local = 0;
    int done_remote = 0;
    char *requests = ILibScratchPad; // Used to hold a block size of node requests
    int requestsPtr = 4;

    //! \todo make sure int sendresponsekey is the right
    //!  \var sendresponsekey - do we send the response key?
    int sendresponsekey = 1;

    // First, lets extract the current serial number of the remote node
    rserial = ntohl(((unsigned int*)meta)[8]);
    if (nodeidserial < rserial)
    {
        // If it's higher than the block we currently have, add it to the request.
        memcpy(requests + requestsPtr, nodeid, UTIL_HASHSIZE);
        requestsPtr += UTIL_HASHSIZE;
    }
    rserial = 0;

    // Run thru the database, ordered by NodeID starting at but excluding startnodeid
    rc = sqlite3_bind_blob(stmt_metadt_block, 1, meta, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Start Node ID
    moveforward = 3;
    goto startpoint;

    while (1)
    {
        // Compare both nodes
        delta = memcmp(snode, rnode, UTIL_HASHSIZE);
        if (delta < 0)
        {
            // SNode < RNode. We conclude that the remote peer does not have SNode, just skip it.
            moveforward = 1;
        }
        else if (delta > 0)
        {
            // SNode > RNode. We conclude that we don't have RNode, we have to request it.
            memcpy(requests + requestsPtr, rnode, UTIL_HASHSIZE);
            requestsPtr += UTIL_HASHSIZE;
            moveforward = 2;
        }
        else if (delta == 0)
        {
            // SNode == RNode. We both have this node, check the serial numbers
            rserial = ntohl(((unsigned int*)(meta + ptr))[8]);
            sserial = sqlite3_column_int(stmt_metadt_block, 1);
            if (sserial < rserial)
            {
                // Request RNode
                memcpy(requests + requestsPtr, rnode, UTIL_HASHSIZE);
                requestsPtr += UTIL_HASHSIZE;
            }
            moveforward = 3;
        }

startpoint:

        // Move the nodes forward
        if (moveforward & 1)
        {
            // Move to the next SNode
            if ((rc = sqlite3_step(stmt_metadt_block)) != SQLITE_ROW) 
            {
                done_local = 1;
            }
            else {
                snode = (char*)sqlite3_column_blob(stmt_metadt_block, 0);
            }
        }
        if (moveforward & 2)
        {
            // Move to the next RNode
            if (ptr + 72 > metalen) 
            {
                done_remote = 1;
            }
            else
            {
                ptr += 36;
                rnode = meta + ptr;
            }
        }

        // If the requests have filled up, send them out
        if (requestsPtr + 32 >= 1024)
        {
            ((unsigned short*)requests)[0] = PB_SYNCREQUEST;
            ((unsigned short*)requests)[1] = requestsPtr;
            //! \note added sendresponsekey
            //SendCryptoUdpToTarget(addr, nodeid, key, requests, requestsPtr, sendresponsekey);
            requestsPtr = 4;
        }

        // Local or remote is done, let exit the loop
        if ( done_local != 0 || done_remote != 0) break;
    }

    if (done_local == 1 && done_remote == 0)
    {
        // We only have remote nodes to request
        while (1)
        {
            // Request RNode
            memcpy(requests + requestsPtr, rnode, UTIL_HASHSIZE);
            requestsPtr += UTIL_HASHSIZE;

            // If the requests have filled up, send them out
            if (requestsPtr + 32 >= 1024)
            {
                ((unsigned short*)requests)[0] = PB_SYNCREQUEST;
                ((unsigned short*)requests)[1] = requestsPtr;
                //! \note added sendresponsekey
                //SendCryptoUdpToTarget(addr, nodeid, key, requests, requestsPtr, sendresponsekey);
                requestsPtr = 4;
            }

            // Move to the next RNode
            if (ptr + 72 > metalen) break;
            ptr += 36;
            rnode = meta + ptr;
        }
    }

    // Clean up the Sql query
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_metadt_block);

    // If the metadata has an end marker, we got all of the metadata of the remote node and we have to restart at NodeID null for the next request.
    if (metalen == ptr + 37 && meta[ptr + 36] == 0) {
        rnode = NullNodeId;
    }

    // Save the last metadata index
    rc = sqlite3_bind_blob(stmt_metaup_target, 1, nodeid, UTIL_HASHSIZE, SQLITE_TRANSIENT); // Node ID
    rc = sqlite3_bind_blob(stmt_metaup_target, 2, rnode, UTIL_HASHSIZE, SQLITE_TRANSIENT);  // Next Sync Node ID
    rc = sqlite3_step(stmt_metaup_target);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_metaup_target);

    // If there are any requests, send them out
    if (requestsPtr > 4)
    {
        ((unsigned short*)requests)[0] = PB_SYNCREQUEST;
        ((unsigned short*)requests)[1] = requestsPtr;
        //! \note added sendresponsekey
        //! commented out for now
        //SendCryptoUdpToTarget(addr, nodeid, key, requests, requestsPtr, sendresponsekey);
        requestsPtr = 4;
    }
}

// Recomputes the latest counts in each bucket.
void mdb_refreshbuckets()
{
    sqlite3_stmt *tmp;
    unsigned char newbuckets[32];
    unsigned int distance;

    memset(newbuckets, 0, 32);
    rc = sqlite3_prepare(mdb, stmt_getbucket_str, (int)strlen(stmt_getbucket_str), &tmp, NULL);
    while (sqlite3_step(tmp) == SQLITE_ROW)
    {
        distance = (unsigned int)sqlite3_column_int(tmp, 0);
        if (distance < 32) newbuckets[distance] = (unsigned char)sqlite3_column_int(tmp, 1);
    }
    sqlite3_finalize(tmp);
    memcpy(g_distancebuckets, newbuckets, 32);
}

// If added is 0, removes a node from the distance(nodeid) bucket, otherwise, add the node to the bucket.
void mdb_changebuckets(char* nodeid, int added)
{
    int d = ctrl_Distance(nodeid);
    if (added) g_distancebuckets[d]++;
    else if (g_distancebuckets[d] != 0) g_distancebuckets[d]--;
}

#ifdef _DEBUG

// Add an event to the event log
void mdb_addevent(char* msg, int msglen)
{
    UNREFERENCED_PARAMETER( msg );
    UNREFERENCED_PARAMETER( msglen );
    /*
    if (db == NULL) return;
    rc = sqlite3_bind_text(stmt_insert_events, 1, msg, msglen, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt_insert_events);
    if (rc < SQLITE_ROW) {mdb_checkerror();}
    rc = sqlite3_reset(stmt_insert_events);
    */
}

// Delete all events from the event log
void mdb_deleteevents()
{
    rc = sqlite3_exec(db, "DELETE FROM events;", NULL, 0, NULL);
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
}

// Send all event in text format to the HTTP session
void mdb_sendevents(struct ILibWebServer_Session *sender)
{
    int len, v;
    char* msg1;
    char* msg2;

    while ((rc = sqlite3_step(stmt_obtain_events)) == SQLITE_ROW)
    {
        // Send event counter
        v = sqlite3_column_int(stmt_obtain_events, 0);
        //len = snprintf(spareBuffer, spareBufferLen, "%d - ", v);
        //ILibWebServer_StreamBody(sender, spareBuffer, len, ILibAsyncSocket_MemoryOwnership_USER,0);

        // Send event date & time
        //len = sqlite3_column_bytes(stmt_obtain_events, 1);
        msg1 = (char*)sqlite3_column_text(stmt_obtain_events, 1);
        //ILibWebServer_StreamBody(sender, msg, len, ILibAsyncSocket_MemoryOwnership_USER,0);

        // Send spacer
        //ILibWebServer_StreamBody(sender, " - ", 3, ILibAsyncSocket_MemoryOwnership_STATIC,0);

        // Send event log message
        //len = sqlite3_column_bytes(stmt_obtain_events, 2);
        msg2 = (char*)sqlite3_column_text(stmt_obtain_events, 2);
        //ILibWebServer_StreamBody(sender, msg, len, ILibAsyncSocket_MemoryOwnership_USER,0);

        // Send end of line
        //ILibWebServer_StreamBody(sender, "<br>", 4, ILibAsyncSocket_MemoryOwnership_STATIC,0);

        len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), "%d - %s - %s<br>", v, msg1, msg2);
        ///ILibWebServer_StreamBody(sender, ILibScratchPad, len, ILibAsyncSocket_MemoryOwnership_USER, 0);

    }
    if (rc < SQLITE_ROW) 
    {
        mdb_checkerror();
    }
    rc = sqlite3_reset(stmt_obtain_events);
}

// blockid BINARY(32) PRIMARY KEY, serial INTEGER, data BLOB, schange DATE, synccount INTEGER, syncnode INTEGER, blocktype INTEGER
char* DEBUG_BLOCK_TABLE_HEADER = "<table border=\"1\"><tr><th>blockid</th><th>serial</th><th>data</th><th>schange</th><th>synccount</th><th>blocktype</th></tr>";
char* DEBUG_BLOCK_TABLE_ITEMBK = "<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";
char* DEBUG_BLOCK_TABLE_FOOTER = "</table><br><br>";

// address TEXT PRIMARY KEY, blockid BINARY(32), state INTEGER, lastcontact DATE, power INTEGER
char* DEBUG_TARGET_TABLE_HEADER = "<table border=\"1\"><tr><th>address</th><th>blockid</th><th>state</th><th>lastAttempt</th><th>lastContact</th><th>power</th><th>SK</th><th>IV</th><th>NextSync</th><th>Serial</th><th>Dist</th></tr>";
char* DEBUG_TARGET_TABLE_ITEMBK1 = "<tr><td><a href=\"https://%s:16990/db\">%s</a></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";
char* DEBUG_TARGET_TABLE_ITEMBK2 = "<tr><td><a href=\"https://[%s]:16990/db\">%s</a></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";
char* DEBUG_TARGET_TABLE_ITEMBK3 = "<tr><td><a href=\"https://[%s]:16990/db\">%s%%%d</a></td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>";

// Private callback to send all push blocks
void mdb_sendallblocksdebugasync_sendok(struct ILibWebServer_Session *sender)
{
    int len;
    int status = 0;
    sqlite3_stmt* query;
    int sendcount = 0;
    char nodeIdStr[18];

    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // Send the data
        util_tohex((char*)sqlite3_column_blob(query, 0), 8, nodeIdStr);
        len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), DEBUG_BLOCK_TABLE_ITEMBK, nodeIdStr, sqlite3_column_int(query, 1), sqlite3_column_bytes(query, 2), sqlite3_column_text(query, 3), sqlite3_column_int(query, 4), sqlite3_column_int(query, 5), sqlite3_column_int(query, 6));
        ///status = ILibWebServer_StreamBody(sender, ILibScratchPad, len, ILibAsyncSocket_MemoryOwnership_USER, 0);
        sendcount++;

        // If the socket is full, break out
        if (status != ILibWebServer_ALL_DATA_SENT) break;
    }
    mdb_commit();

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        sqlite3_finalize(query);
        sender->User3 = NULL;
        ///ILibWebServer_StreamBody(sender, DEBUG_BLOCK_TABLE_FOOTER, (int)strlen(DEBUG_BLOCK_TABLE_FOOTER), ILibAsyncSocket_MemoryOwnership_STATIC, 1);
    }
}

// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendallblocksdebugasync(struct ILibWebServer_Session *sender)
{
    const char *tail;
    sqlite3_stmt* query;

    rc = sqlite3_prepare(db, stmt_getall_block_str, (int)strlen(stmt_getall_block_str), &query, &tail);
    rc = sqlite3_bind_int(query, 1, 0); // Bind the sync counter
    sender->OnSendOK = mdb_sendallblocksdebugasync_sendok;
    sender->User3 = (void*)query;
    ///ILibWebServer_StreamBody(sender, DEBUG_BLOCK_TABLE_HEADER, (int)strlen(DEBUG_BLOCK_TABLE_HEADER), ILibAsyncSocket_MemoryOwnership_STATIC, 0);
    mdb_sendallblocksdebugasync_sendok(sender);
}

// Private callback to send all push blocks
void mdb_sendalltargetsdebugasync_sendok(struct ILibWebServer_Session *sender)
{
    int len = 0;
    int status = 0;
    int scope;
    sqlite3_stmt* query;
    int sendcount = 0;
    char addrstr[200];
    char nodeIdStr[18];
    char nextsync[18];

    query = (sqlite3_stmt*)sender->User3;
    if (query == NULL) return;

    mdb_begin();
    while ((rc = sqlite3_step(query)) == SQLITE_ROW)
    {
        // Fetch BlockID
        util_tohex((char*)sqlite3_column_blob(query, 1), 8, nodeIdStr);

        // Fetch NextSyncNodeID
        util_tohex((char*)sqlite3_column_blob(query, 8), 8, nextsync);

        // Fetch the address
        if (sqlite3_column_bytes(query, 0) == 4)
        {
            // IPv4 Address
            ILibInet_ntop(AF_INET, (char*)sqlite3_column_blob(query, 0), addrstr, 200);
            len = snprintf(ILibScratchPad, sizeof(ILibScratchPad),  DEBUG_TARGET_TABLE_ITEMBK1, addrstr, addrstr, nodeIdStr, sqlite3_column_int(query, 2), sqlite3_column_text(query, 3), sqlite3_column_text(query, 4), sqlite3_column_int(query, 5), sqlite3_column_bytes(query, 6), sqlite3_column_int(query, 7), nextsync, sqlite3_column_int(query, 9), sqlite3_column_int(query, 10));
        }
        else if (sqlite3_column_bytes(query, 0) == 16)
        {
            // IPv6 Address
            ILibInet_ntop(AF_INET6, (char*)sqlite3_column_blob(query, 0), addrstr, 200);
            len = snprintf(ILibScratchPad, sizeof(ILibScratchPad),  DEBUG_TARGET_TABLE_ITEMBK2, addrstr, addrstr, nodeIdStr, sqlite3_column_int(query, 2), sqlite3_column_text(query, 3), sqlite3_column_text(query, 4), sqlite3_column_int(query, 5), sqlite3_column_bytes(query, 6), sqlite3_column_int(query, 7), nextsync, sqlite3_column_int(query, 9), sqlite3_column_int(query, 10));
        }
        else if (sqlite3_column_bytes(query, 0) == 20)
        {
            // IPv6 Address + Scope
            ILibInet_ntop(AF_INET6, (char*)sqlite3_column_blob(query, 0), addrstr, 200);
            scope = ((int*)sqlite3_column_blob(query, 0))[4];
            len = snprintf(ILibScratchPad, sizeof(ILibScratchPad), DEBUG_TARGET_TABLE_ITEMBK3, addrstr, addrstr, scope, nodeIdStr, sqlite3_column_int(query, 2), sqlite3_column_text(query, 3), sqlite3_column_text(query, 4), sqlite3_column_int(query, 5), sqlite3_column_bytes(query, 6), sqlite3_column_int(query, 7), nextsync, sqlite3_column_int(query, 9), sqlite3_column_int(query, 10));
        }

        if (len > 0 && len < sizeof(ILibScratchPad))
        {
            // Format & send the string
            ///status = ILibWebServer_StreamBody(sender, ILibScratchPad, len, ILibAsyncSocket_MemoryOwnership_USER, 0);
            sendcount++;

            // If the socket is full, break out
            if (status != ILibWebServer_ALL_DATA_SENT) break;
        }
    }
    mdb_commit();

    if (rc != SQLITE_ROW || status < 0)
    {
        // We are done, clean up and close the session.
        sqlite3_finalize(query);
        sender->User3 = NULL;

        ///ILibWebServer_StreamBody(sender, DEBUG_BLOCK_TABLE_FOOTER, (int)strlen(DEBUG_BLOCK_TABLE_FOOTER), ILibAsyncSocket_MemoryOwnership_STATIC, 0);
        mdb_sendallblocksdebugasync(sender);
    }
}

// Send all event in text format to the HTTP session. Skip node will be de-allocated by this method.
void mdb_sendalltargetsdebugasync(struct ILibWebServer_Session *sender)
{
    const char *tail;
    sqlite3_stmt* query;

    rc = sqlite3_prepare(mdb, stmt_select_target_str, (int)strlen(stmt_select_target_str), &query, &tail);
    sender->OnSendOK = mdb_sendalltargetsdebugasync_sendok;
    sender->User3 = (void*)query;
    /// \note all ILibWebServer_StreamBody commented out until fixed
    ///ILibWebServer_StreamBody(sender, DEBUG_TARGET_TABLE_HEADER, (int)strlen(DEBUG_TARGET_TABLE_HEADER), ILibAsyncSocket_MemoryOwnership_STATIC, 0);
    mdb_sendalltargetsdebugasync_sendok(sender);
}

#endif

