# Doctor :

## 1 Network map :
### 1.1 Ports identification :
#### 1.1.1 TCP :
Run :
````bash
nmap -sS 10.10.10.209

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown
````

All TCP ports :
````bash
nmap -sS -p1-65535 10.10.10.209
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown
````

All TCP handshake :
````bash
nmap -sT -p1-65535 10.10.10.209
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown
````

---

#### 1.1.2 UDP :
Run :
````bash
nmap -sU 10.10.10.209
PORT   STATE  SERVICE
22/udp closed ssh
80/udp closed http
````

---

### 1.2 Banner Grabbing :
#### 1.2.1 Manual :
Run :
````bash
nc 10.10.10.209 22
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1

nc 10.10.10.209 80
Apache/2.4.41

nc 10.10.10.209 8089
# None
````

---

#### 1.2.2 Automatic :
Run :
````bash
nmap -sV -sS 10.10.10.209
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
8089/tcp open  ssl/http Splunkd httpd

httprint -h 10.10.10.209 -s /usr/share/httprint/signatures.txt
Banner Reported: Apache/2.4.41 (Ubuntu)
Banner Deduced: Apache/2.0.x

httprint -h 10.10.10.209:8089 -s /usr/share/httprint/signatures.txt
# None
````

---

### 1.3 OS identification :
#### 1.3.1 Automatic :
Run :
````bash
nmap -O 10.10.10.209
Not shown: 997 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (91%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Infomir MAG-250 set-top box (86%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (86%)
````

---

#### 1.3.2 Manual :
Run :
````bash
p0f

nc 10.10.10.209 80
.-[ 10.10.14.175/47198 -> 10.10.10.209/80 (syn+ack) ]-
|
| server   = 10.10.10.209/80
| os       = ???
| dist     = 1
| params   = none
| raw_sig  = 4:63+1:0:1357:mss*45,7:mss,sok,ts,nop,ws:df:0
|
`----
````

---

### 1.4 Conclude :

Network :

* IP : 10.10.10.209 
* MAC : ?
* DNS : ?
* Same subnet : NO

Ports :

* 22 	; SSH 	; OpenSSH 8.2p1 Ubuntu 4ubuntu0.1	; TCP
* 80	; HTTP 	; Apache httpd 2.4.41 				; TCP/UDP
* 8089	; HTTP 	; Splunk build: 8.0.5				; TCP/UDP

OS :

* OS : Ubuntu Linux 2.6.32
* Kernel : 2.6.32 (91%)

---

## 2 Vulnerability :
### 2.1 Searcploit :
Run :
````bash
searchsploit OpenSSH 8.2
# None 

searchsploit Apache 2.4.41 
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                           
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                         
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                                       
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                      
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal                                                       
Apache Tomcat < 5.5.17 - Remote Directory Listing                                                                         
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                                       
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                                 
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)              
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)              
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                              
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution

searchsploit Splunk 8.0.5
# None 
````

---

### 2.1 NSE scan :
Run :
````bash
nmap -sV -p22,80,8089 10.10.10.209 --script=exploit,vuln,auth,default -oX /tmp/Doctor.xml
xsltproc /tmp/Doctor.xml -o /var/www/html/Doctor.html
````

### 2.2 Port scan :
#### 2.2.1 Port 22 :
Run :
````bash

````

---
#### 2.2.2 Port 80 :
Run :
````bash
nikto -h http://10.10.10.209/
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 4d88, size: 5afad8bea6589, mtime: gzip
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.

dirb http://10.10.10.209/
==> DIRECTORY: http://10.10.10.209/css/
==> DIRECTORY: http://10.10.10.209/fonts/
==> DIRECTORY: http://10.10.10.209/images/
+ http://10.10.10.209/index.html (CODE:200|SIZE:19848)
==> DIRECTORY: http://10.10.10.209/js/
+ http://10.10.10.209/server-status (CODE:403|SIZE:277)

wapiti -u http://10.10.10.209/
Injection SQL	0
Injection SQL en aveugle	0
Divulgation de fichier	0
Cross Site Scripting	0
Injection CRLF	0
Exécution de commandes	0
Contournement de htaccess	0
Copie de sauvegarde	0
Fichier potentiellement dangereux	0
Server Side Request Forgery	0
Open Redirect	0
XXE	0
Erreur interne au serveur	0
Consommation anormale de ressource	0

whatweb -a 4 http://10.10.10.209/
http://10.10.10.209/ [200 OK] Apache[2.4.41], Bootstrap[4.3.1], Country[RESERVED][ZZ], Email[info@doctors.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.209], JQuery[3.3.1], Script, Title[Doctor]
````

---

#### 2.2.2 Port 8089 :
````bash
nikto -h https://10.10.10.209:8089/

dirb https://10.10.10.209:8089/
+ https://10.10.10.209:8089/robots.txt (CODE:200|SIZE:26)
+ https://10.10.10.209:8089/services (CODE:401|SIZE:130)
+ https://10.10.10.209:8089/v1 (CODE:200|SIZE:2178)
+ https://10.10.10.209:8089/v2 (CODE:200|SIZE:2178)
+ https://10.10.10.209:8089/v3 (CODE:200|SIZE:2178)
+ https://10.10.10.209:8089/v4 (CODE:200|SIZE:2178)


wapiti -u https://10.10.10.209:8089/
Injection SQL	0
Injection SQL en aveugle	0
Divulgation de fichier	0
Cross Site Scripting	0
Injection CRLF	0
Exécution de commandes	0
Contournement de htaccess	0
Copie de sauvegarde	0
Fichier potentiellement dangereux	0
Server Side Request Forgery	0
Open Redirect	0
XXE	0
Erreur interne au serveur	0
Consommation anormale de ressource	0

whatweb -a 4 https://10.10.10.209:8089/
https://10.10.10.209:8089/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Splunkd], IP[10.10.10.209], Title[splunkd], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN]
````
