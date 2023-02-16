#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 
/** \fn callback is the database return acceptance function
 * The callback names make a hell of a lot of sense over the sqlite3.h 
 * 
 * However: I understand why they are phasing out exec functions 
 * because they use strings that take time and code to create on the
 * fly for a binary 
 * 
 * \var data is the string sent to the sqlite3 database
 * \var argc - argument count is the number of arguments in this iteration of the callback
 *    iterator i is all values under argc from 0
 * \var argv is the array of the array 
 * 
 * \var azColName is the array of strings of the data table column strings
 * 
 * 
 * */
static int callback(void *data, int argc, char **argv, char **azColName){
   int i;
   fprintf(stderr, "%s: ", (const char*)data);
   
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

int main(int argc, char* argv[]) {
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;
   const char* data = "Callback function called";

   /* Open database */
   rc = sqlite3_open("test.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
   } else {
      fprintf(stderr, "Opened database successfully\n");
   }

   /* Create merged SQL statement */
   sql = "UPDATE COMPANY set SALARY = 25000.00 where ID=1; " \
         "SELECT * from COMPANY";

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
   
   if( rc != SQLITE_OK ) {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   } else {
      fprintf(stdout, "Operation done successfully\n");
   }
   sqlite3_close(db);
   return 0;
}
