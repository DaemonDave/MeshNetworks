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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include <openssl/ssl.h>
#include <openssl/err.h>


#include <sqlite3.h> 


// a working C callback function
static int callback(void *data, int argc, char **argv, char **azColName){
   int i;
   fprintf(stderr, "%s: ", (const char*)data);
   
   for(i = 0; i<argc; i++)
   {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   
   printf("\n");
   return 0;
}



int main(void) 
{
    sqlite3_stmt *pStmt;	
	size_t bytes = 0;    
    
    // The output write from a database lookup
    FILE *fp = fopen("backup-key.pem", "wb");
    
    if (fp == NULL) {
        
        fprintf(stderr, "Cannot open image file\n");    
        
        return 1;
    }    
    
    sqlite3 *db;
    char *err_msg = 0;
    
    int rc = sqlite3_open("key.db", &db);
    
    if (rc != SQLITE_OK) 
    {
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }
    
    char *sql = "SELECT Data FROM key WHERE Id = 1";
        

    rc = sqlite3_prepare_v2(db, sql, -1, &pStmt, 0);
    
    if (rc != SQLITE_OK ) 
    {
        
        fprintf(stderr, "Failed to prepare statement\n");
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        
        sqlite3_close(db);
        
        return 1;
    } 
    // The SQL command execute Step
    rc = sqlite3_step(pStmt);
    // if the return was a row?   
    if (rc == SQLITE_ROW) 
    {
        bytes = sqlite3_column_bytes(pStmt, 0);
    }
    printf( "sqlite3_column_bytes() bytes returned: %d \n", bytes);
    printf( "sqlite3_column_count: %d \n", sqlite3_column_count(pStmt));
    printf( "sqlite3_column_type: %d \n", sqlite3_column_type(pStmt,0));
    // fwrite the data into the open file
    /// sqlite3_column_blob returns a pointer to the data 
    fwrite(sqlite3_column_blob(pStmt, 0), bytes, 1, fp);

	// show off the data to the programmer in human form:
   printf( "processed certificate : \n %s", sqlite3_column_blob(pStmt, 0) );    
   printf( "processed certificate : %d \n", strlen(sqlite3_column_blob(pStmt, 0)) );  	

    if (ferror(fp)) 
    {                   
        fprintf(stderr, "fwrite() failed\n");
        return 1;      
    }  
    
    int r = fclose(fp);

//    if (r == EOF) 
//    {
//        fprintf(stderr, "Cannot close file handler\n");
//    }       
    
    rc = sqlite3_finalize(pStmt);   

    sqlite3_close(db);
    
    return 0;
}    

