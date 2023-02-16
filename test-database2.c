#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 
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


/// This one tests out the create table queries needed to setup a database for meshdb
int main(int argc, char* argv[]) 
{
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;
   const char* data = "Callback function called";

   /* Open database */
   rc = sqlite3_open("mesh.db", &db);
   
   if( rc ) {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return(0);
   } else {
      fprintf(stderr, "Opened database successfully\n");
   }

	/// a correct SQLITE3 query: sqlite> select * from COMPANY; proven here.
   /* Create SQL statement */
   sql =  "CREATE TABLE settings (skey TEXT PRIMARY KEY, sdata BLOB);"\
			"INSERT INTO settings  (skey , sdata )  VALUES ( 'California', X'123456' );"\
			"INSERT INTO settings  (skey , sdata )  VALUES ( 'Texas',  X'123456' );"\
			"INSERT INTO settings  (skey , sdata )  VALUES ( 'Montana', X'123456' );"\
			"CREATE TABLE revoked (blockid BINARY(32) PRIMARY KEY, meshid BINARY(32));"\
			"INSERT INTO revoked (blockid, meshid) VALUES ( 0x045FFFF,  042);"\
			"INSERT INTO revoked (blockid, meshid) VALUES ( 0x045FAFF,  043);"\
			"INSERT INTO revoked (blockid, meshid) VALUES ( 0x045FDFF,  044);"\
			"CREATE TABLE events  (id INTEGER PRIMARY KEY, time TEXT, message TEXT);"\
			"INSERT INTO events (id, time, message) VALUES ( 0x045FFFF, '12/12/1200',  'Montana');"\
			"INSERT INTO events (id, time, message) VALUES ( 0x045FFFD, '12/12/1200',  'California');"\
			"INSERT INTO events (id, time, message) VALUES ( 0x045FFFE, '12/12/1200',  'Texas');"\
			"CREATE TABLE blocks  (blockid BOOLEAN(32) PRIMARY KEY, serial INTEGER, data BLOB, schange TEXT, synccount INTEGER, blocktype INTEGER);"\
			"INSERT INTO blocks (blockid, serial, data, schange, synccount, blocktype) VALUES ( 0x045FFFF, 1021,  X'111111', '1999-12-31', 042, 99);"\
			"INSERT INTO blocks (blockid, serial, data, schange, synccount, blocktype) VALUES ( 0x045FFFD, 1022,  X'222222', '1999-12-31', 042, 99 );"\
			"INSERT INTO blocks (blockid, serial, data, schange, synccount, blocktype) VALUES (  0x045FFFE, 1023,  X'333333', '1999-12-31', 042, 99 );";

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
