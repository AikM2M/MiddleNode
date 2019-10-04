static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   if (argv[2] == rn)      aei = argv[0];
   return 0;
}

static int retrive_ae(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   if(argv[0] == From)
   {
      aei = argv[0];
      api = argv[1];
      rn = argv[2];
      rr = argv[3];
   }
   printf(" \n");
   return 0;
}

static int retrive_cont(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
      if (i == 0) rn = argv[i];
      if (i == 1) _to = argv[i];
      if (i == 2) rqi = argv[i];
   }
   printf(" \n");
   return 0;
}

static int retrive_sub(void *NotUsed, int argc, char **argv, char **azColName) {
   int i;
   for(i = 0; i<argc; i++) {
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
      
   }
   if(argv[5] == _to)
   {
      printf("In retrive");
      rn = argv[0];
      rqi = argv[1];
      nu = argv[2];
      net = std::stoi(argv[3]);
      nct = std::stoi(argv[4]);
      _to = argv[5];
      printf("\n rn = %s, rqi = %s, nu = %s, net = %d, nct = %d, _to = %s\n", rn.c_str(), rqi.c_str(), nu.c_str(), net, nct, _to);
   }
   printf(" \n");
   return 0;
}

void CreateTables(sqlite3 *db)
{
	int rc;
    char *zErrMsg = 0;
    char *sql;
    
    // Drop if Exits
    sql = "DROP TABLE Registration";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "Registration Table Dropped successfully\n");
    sql = "DROP TABLE Container";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "Container Table Dropped successfully\n");
    sql = "DROP TABLE ContentInstance";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "ContentInstance Table Dropped successfully\n");
    sql = "DROP TABLE Subscription";
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "Subscription Table Dropped successfully\n");
    
    //Create Registration Table
    
    sql = "CREATE TABLE Registration("  \
      "aei TEXT PRIMARY KEY     NOT NULL," \
      "api           TEXT    NOT NULL," \
      "rn            TEXT     NOT NULL UNIQUE," \
      "rr            BOOLEAN     NOT NULL," \
      "ct            TEXT     NOT NULL," \
      "lt        TEXT NOT NULL);";
      
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "Registration Table created successfully\n");


	//Create Container Table

	sql = "CREATE TABLE Container("  \
      "rn		TEXT	PRIMARY KEY	NOT NULL," \
      "_to	TEXT     NOT NULL," \
      "rqi        TEXT	NOT NULL,"\
      "ct            TEXT     NOT NULL," \
      "lt            TEXT     NOT NULL," \
       "FOREIGN KEY (_to) REFERENCES Registration(aei) ON DELETE CASCADE);";
      
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "Container Table created successfully\n");
    
    //Create Content Instance Table
    
    sql = "CREATE TABLE ContentInstance("  \
      "rqi	TEXT	PRIMARY KEY	NOT NULL," \
      "con            TEXT     NOT NULL," \
      "cnf TEXT     NOT NULL," \
      "_to        TEXT		NOT NULL,"\
      "ct            TEXT     NOT NULL," \
      "lt            TEXT     NOT NULL," \
       "FOREIGN KEY (_to) REFERENCES Container(rn) ON DELETE CASCADE);";
      
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "ContentInstance Table created successfully\n");
    
    //Create Subscription Table
    
    sql = "CREATE TABLE Subscription("  \
      "rn	TEXT	PRIMARY KEY	NOT NULL," \
      "rqi            TEXT     NOT NULL," \
      "nu TEXT     NOT NULL," \
      "net INT     NOT NULL," \
      "nct INT     NOT NULL," \
      "_to        TEXT		NOT NULL,"\
      "ct            TEXT     NOT NULL," \
      "lt            TEXT     NOT NULL," \
       "FOREIGN KEY (_to) REFERENCES Container(rn) ON DELETE CASCADE);";
      
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
   
    if( rc != SQLITE_OK ){
       fprintf(stderr, "SQL error: %s\n", zErrMsg);
       sqlite3_free(zErrMsg);
    } 
    else        fprintf(stdout, "Subscription Table created successfully\n");
	
	sql = "PRAGMA foreign_keys = ON;";
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
	
	if( rc != SQLITE_OK ){
	   fprintf(stderr, "SQL error: %s\n", zErrMsg);
	   sqlite3_free(zErrMsg);
	} 
	else        fprintf(stdout, "Successfully invoked Foreign Keys Pragma\n");       
	
    return;
}
