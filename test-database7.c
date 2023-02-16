#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 

// This is the first update to the sqlite3 functions in meshdb which creates a 

static int callback(void *NotUsed, int argc, char **argv, char **azColName) 
{
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

int main(int argc, char* argv[]) 
{
   sqlite3 *db;
   char error1[30] = "Create settings Table Failed \n";
   char error2[30] = "INSERT INTO settings Failed \n";
   char *zErrMsg = error1;
   int rc;
   char *sql;

   /* Open database */
   rc = sqlite3_open("test1.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
   } else {
      fprintf(stdout, "Opened database successfully\n");
   }

   // create and insert into tables by sequence
   
   /* Create SQL statement */
   sql = "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);";

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
   zErrMsg = error2;
   /* Create SQL statement */
   sql = "INSERT INTO settings  (skey, sdata) VALUES ( 'California', 045FFFF );";  
   /* Execute SQL statement */    
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg); 
   sql = "INSERT INTO settings  (skey, sdata) VALUES ( 'Texas', 885FFFF);";   
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg); 
   sql = "INSERT INTO settings  (skey, sdata) VALUES ( 'Montana', FFFF777 );";   
   rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg); 


   
   if( rc != SQLITE_OK )
   {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }
   else 
   {
      fprintf(stdout, "Table created successfully\n");
   }
   sqlite3_close(db);
   return 0;
}
