/*!
 *   test-databasessl ports over the latest version of 
 * 
 * 
 * */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include <openssl/ssl.h>
#include <openssl/err.h>


#include <sqlite3.h> 

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
  * It looks to me like the easiest way to interface is to avoid OpenSSL calls and just read and write files as BLOBS inside the database.
  * 
  * It's great that field data types are dynamic, that will help for real time and data interchange...
  * 
  * */


// a working C callback function
static int callback(void *data, int argc, char **argv, char **azColName){
   int i;
   fprintf(stderr, "%s: ", (const char*)data);
   
   for(i = 0; i<argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   
   printf("\n");
   return 0;
}

//! \def file char maximum
#define FILEMAX	4096

/// This one tests out the create table queries needed to setup a database for meshdb
int main(int argc, char* argv[]) 
{
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;
   const char * primarykey = "'Maine'";
   const char* stmt_insert_target_str =  "INSERT INTO certificates  (certkey, certdata)  VALUES (";
   const char* data = "Callback function called";
   size_t file_size;   
   //! \var cert holds the pem file contents verbatim
   char cert[FILEMAX];
   //! \var encased_cert with a few extra chars
   char encased_cert[FILEMAX+6];
   char sqlite_insert_encased_cert[2*FILEMAX];
   //! \var fp the file descriptor to a prestored copy of the certificate file
   FILE * fp;

//  Basic Algorithm


// file side
// Open the cert.pem file
// Load the cert.pem from file into a memory char array.
// Copy the cert.pem inside fp into char buffer.
// Format the string into the SQLITE FORMATTED BLOB DATA
// close the file

// THEN 

// database side
// Create a certificate file database
// update the entry with the contents of the file *** USING SQLITE FORMATTED BLOB DATA ***
   
// Then 

// make specific functions from the three needs - reading from, writing to, and adding to the database.

// Then make a dual for the server side private key .pem file...
  
  // certificate loading half algorithm
  
  
  // the file open
  fp = fopen("cert.pem", "r" );
  
  /**
   * size_t fread(void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream);
   * 
   * elements_read = fread(buf, sizeof(buf), 1, fp);
   * 
   * */
   file_size = fread(cert, sizeof(cert), 1, fp);
   printf("file_size = %d  \n", file_size);
   printf( " certificate : \n %s", cert );
   printf( "cert: %d\n", strlen(cert) );      


	// remove newlines and carriage returns 
    char *src, *dst;
    for (src = dst = cert; *src != '\0'; src++) 
    {
        *dst = *src;
        // eliminate two chars
        if (*dst != '\r' || *dst != '\n' ) dst++;
        
    }
    *dst = '\0';
    
   printf( "processed certificate : \n %s", cert );    
   printf( "processed certificate : %d \n", strlen(cert) );      


   //! \note setup start of the encased cert buffer
   strncpy(encased_cert, " X'", strlen(" X'"));   
   strncat(encased_cert, cert, strlen(cert));
   strncat(encased_cert, "'", 1);
   printf( "encased_cert: %d \n", strlen(encased_cert) );  
      
   printf( "encased certificate : \n %s\n", encased_cert );   
   
   //! \note concatenate sql insert statement
   strncpy(sqlite_insert_encased_cert, stmt_insert_target_str, strlen(stmt_insert_target_str));
   strncat(sqlite_insert_encased_cert, primarykey, strlen(primarykey));
   strncat(sqlite_insert_encased_cert, encased_cert, strlen(encased_cert));
   strncat(sqlite_insert_encased_cert, " );", 3);   
   
   printf( "stmt_insert_target_str: %d \n", strlen(stmt_insert_target_str) );      
   printf( "primarykey: %d \n", strlen(primarykey) );      
   printf( "encased_cert: %d \n", strlen(encased_cert) );      
   printf( "sqlite_insert_encased_cert:  %d \n %s", strlen(sqlite_insert_encased_cert), sqlite_insert_encased_cert );      
      
   fclose(fp);   
   
   

   ///	    Open database 
   rc = sqlite3_open("cert.db", &db);
   
   if( rc ) 
   {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
   } 
   else 
   {
      fprintf(stderr, "Opened database successfully\n");
   }

	/// a correct SQLITE3 query: sqlite> select * from COMPANY; proven here.
   // Create SQL statement 
   //sql =  "CREATE TABLE certificates (certkey TEXT PRIMARY KEY, certdata BLOB);"\
   //		"INSERT INTO certificates  (certkey, certdata)  VALUES ( 'California', X'123456' );";
   
   // aim sql at the 
   sql = sqlite_insert_encased_cert;
   // Execute SQL statement 
   rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
   
   if( rc != SQLITE_OK ) 
   {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }
   else
   {
      fprintf(stdout, "Operation done successfully\n");
   }
   sqlite3_close(db);


   return 0;
}
