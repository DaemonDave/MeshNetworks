/*
 *  An Introduction To The SQLite C/C++ Interface 
 * 
 * The following two objects and eight methods comprise the essential elements of the SQLite interface:

    sqlite3 → The database connection object. Created by sqlite3_open() and destroyed by sqlite3_close().

    sqlite3_stmt → The prepared statement object. Created by sqlite3_prepare() and destroyed by sqlite3_finalize().

    sqlite3_open() → Open a connection to a new or existing SQLite database. The constructor for sqlite3.
    * This routine opens a connection to an SQLite database file and returns a database connection object. 
    * This is often the first SQLite API call that an application makes and is a prerequisite for most other SQLite APIs. 
    * Many SQLite interfaces require a pointer to the database connection object as their first parameter and can be 
    * thought of as methods on the database connection object. This routine is the constructor for the database connection object. 

    sqlite3_prepare() → Compile SQL text into byte-code that will do the work of querying or updating the database. The constructor for sqlite3_stmt.
    * This routine converts SQL text into a prepared statement object and returns a pointer to that object. 
    * This interface requires a database connection pointer created by a prior call to sqlite3_open() and a text string 
    * containing the SQL statement to be prepared. This API does not actually evaluate the SQL statement. It merely prepares the SQL statement for evaluation.
    * Think of each SQL statement as a small computer program. The purpose of sqlite3_prepare() is to compile that program into object code. The prepared 
    * statement is the object code. The sqlite3_step() interface then runs the object code to get a result.
    * New applications should always invoke sqlite3_prepare_v2() instead of sqlite3_prepare(). The older sqlite3_prepare() is retained 
    * for backwards compatibility. But sqlite3_prepare_v2() provides a much better interface.
    
    sqlite3_bind() → Store application data into parameters of the original SQL.

    sqlite3_step() → Advance an sqlite3_stmt to the next result row or to completion.
    * This routine is used to evaluate a prepared statement that has been previously created by the sqlite3_prepare() interface. 
    * The statement is evaluated up to the point where the first row of results are available. To advance to the second row of results, 
    * invoke sqlite3_step() again. Continue invoking sqlite3_step() until the statement is complete. Statements that do not return 
    * results (ex: INSERT, UPDATE, or DELETE statements) run to completion on a single call to sqlite3_step(). 

    sqlite3_column() → Column values in the current result row for an sqlite3_stmt.
    *  This routine returns a single column from the current row of a result set for a prepared statement that is being evaluated by sqlite3_step(). 
    *  Each time sqlite3_step() stops with a new result set row, this routine can be called multiple times to find the values of all columns in that row.
    *  As noted above, there really is no such thing as a "sqlite3_column()" function in the SQLite API. Instead, what we here call "sqlite3_column()" is a 
    *  place-holder for an entire family of functions that return a value from the result set in various data types. There are also routines in this family 
    *  that return the size of the result (if it is a string or BLOB) and the number of columns in the result set. 

    sqlite3_finalize() → Destructor for sqlite3_stmt.
    *  This routine destroys a prepared statement created by a prior call to sqlite3_prepare(). 
    * Every prepared statement must be destroyed using a call to this routine in order to avoid memory leaks. 

    sqlite3_close() → Destructor for sqlite3.
    * This routine closes a database connection previously opened by a call to sqlite3_open(). All prepared statements associated with the 
    * connection should be finalized prior to closing the connection. 

    sqlite3_exec() → A wrapper function that does sqlite3_prepare(), sqlite3_step(), sqlite3_column(), and sqlite3_finalize() for a string of one or more SQL statements. 
 * 
 * */
 /**
 * https://www.sqlitetutorial.net/sqlite-data-types/
 * 
 * 
Introduction to SQLite data types
* If you come from other database systems such as MySQL and PostgreSQL, you notice that they use static typing. 
* It means when you declare a column with a specific data type, that column can store only data of the declared data type.
* Different from other database systems, SQLite uses dynamic type system. In other words, a value stored in a column 
* determines its data type, not the column’s data type.
* In addition, you don’t have to declare a specific data type for a column when you create a table. 
* In case you declare a column with the integer data type, you can store any kind of data types such as text 
* and BLOB, SQLite will not complain about this.
* SQLite provides five primitive data types which are referred to as storage classes. 
* 
* Storage classes describe the formats that SQLite uses to store data on disk. 
* A storage class is more general than a data type e.g., 
* INTEGER storage class includes 6 different types of integers. 
* In most cases, you can use storage classes and data types interchangeably.

The following table illustrates 5 storage classes in SQLite:
Storage Class	Meaning
NULL	NULL values mean missing information or unknown.
INTEGER	Integer values are whole numbers (either positive or negative). An integer can have variable sizes such as 1, 2,3, 4, or 8 bytes.
REAL	Real values are real numbers with decimal values that use 8-byte floats.
TEXT	TEXT is used to store character data. The maximum length of TEXT is unlimited. SQLite supports various character encodings.
BLOB	BLOB stands for a binary large object that can store any kind of data. The maximum size of BLOB is, theoretically, unlimited.

SQLite determines the data type of a value based on its data type according to the following rules:

    If a literal has no enclosing quotes and decimal point or exponent, SQLite assigns the INTEGER storage class.
    If a literal is enclosed by single or double quotes, SQLite assigns the TEXT storage class.
    If a literal does not have quote nor decimal point nor exponent, SQLite assigns REAL storage class.
    If a literal is NULL without quotes, it assigned NULL storage class.
    If a literal has the X’ABCD’ or x ‘abcd’, SQLite assigned BLOB storage class.

SQLite does not support built-in date and time storage classes. However, you can use the TEXT, INT, or REAL to store date and time values. For the detailed information on how to handle date and time values, check it out the SQLite date and time tutorial.

 Typical Usage Of Core Routines And Objects  (from: https://www.sqlite.org/cintro.html)

An application will typically use sqlite3_open() to create a single database connection during initialization. Note that sqlite3_open() can be used to either open existing database files or to create and open new database files. While many applications use only a single database connection, there is no reason why an application cannot call sqlite3_open() multiple times in order to open multiple database connections - either to the same database or to different databases. Sometimes a multi-threaded application will create separate database connections for each thread. Note that a single database connection can access two or more databases using the ATTACH SQL command, so it is not necessary to have a separate database connection for each database file.

Many applications destroy their database connections using calls to sqlite3_close() at shutdown. Or, for example, an application that uses SQLite as its application file format might open database connections in response to a File/Open menu action and then destroy the corresponding database connection in response to the File/Close menu.

To run an SQL statement, the application follows these steps:

    Create a prepared statement using sqlite3_prepare().
    Evaluate the prepared statement by calling sqlite3_step() one or more times.
    For queries, extract results by calling sqlite3_column() in between two calls to sqlite3_step().
    Destroy the prepared statement using sqlite3_finalize().

The foregoing is all one really needs to know in order to use SQLite effectively. All the rest is optimization and detail. 


 * 
 * */
 
/**
 *  \file test-sqlite3.c 
 * 
 *  is the file from the SQLITE3 website page: 
 * 
 * 	https://www.sqlite.org/quickstart.html
 * 
 * It is the simplest way to operate the SQLITE3 CAPI without any code overlaps. 
 * 
 * You simply compile this and use it as the endpoint for strings of SQLITE3 commands.
 * 
 * Usage: %s DATABASE SQL-STATEMENT
 * 
 * example:
 * 
 * ./t-sqlite3 pem.db "select Data from pem Where Id =1;"
 * 
 * then the callback prints out the response from the sqlite3 server response. 
 * 
 * */

#include <stdio.h>
#include <sqlite3.h>
 
static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
	int i;
	for(i=0; i<argc; i++)
	{
		printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
    printf("\n");
    return 0;
}
  
int main(int argc, char **argv)
{
 sqlite3 *db;
 char *zErrMsg = 0;
 int rc;
 
	if( argc!=3 )
	{
		fprintf(stderr, "Usage: %s DATABASE SQL-STATEMENT\n", argv[0]);
		return(1);
	}
	rc = sqlite3_open(argv[1], &db);
	if( rc )
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return(1);
	}
	rc = sqlite3_exec(db, argv[2], callback, 0, &zErrMsg);
	if( rc!=SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	sqlite3_close(db);
	return 0;
}
