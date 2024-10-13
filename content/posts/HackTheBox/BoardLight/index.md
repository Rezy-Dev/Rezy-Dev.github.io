---
title: "BoardLight Writeup - HackTheBox"
date: 2024-10-10
draft: false
Tags:
- HackTheBox
- Linux
- Easy
---

| Link: | [https://app.hackthebox.com/machines/BoardLight](https://app.hackthebox.com/machines/BoardLight) |
| --- | --- |
| Difficulty | Easy |
| Machine | Linux |

---

## Enumeration

I ran the Nmap command to find all available open ports on this system using the command: `nmap 10.10.11.11 -T4 -vv`.

```html
**PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack**
```

Again, I ran an aggressive scan using the command: **`sudo nmap 10.10.11.11 -T4 -p22,80 -A -sC -sV -O -vv`**. While it ran, I was looking at port 80 and enumerating the web server.

```html
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH0dV4gtJNo8ixEEBDxhUId6Pc/8iNLX16+zpUCIgmxxl5TivDMLg2JvXorp4F2r8ci44CESUlnMHRSYNtlLttiIZHpTML7ktFHbNexvOAJqE1lIlQlGjWBU1hWq6Y6n1tuUANOd5U+Yc0/h53gKu5nXTQTy1c9CLbQfaYvFjnzrR3NQ6Hw7ih5u3mEjJngP+Sq+dpzUcnFe1BekvBPrxdAJwN6w+MSpGFyQSAkUthrOE4JRnpa6jSsTjXODDjioNkp2NLkKa73Yc2DHk3evNUXfa+P8oWFBk8ZXSHFyeOoNkcqkPCrkevB71NdFtn3Fd/Ar07co0ygw90Vb2q34cu1Jo/1oPV1UFsvcwaKJuxBKozH+VA0F9hyriPKjsvTRCbkFjweLxCib5phagHu6K5KEYC+VmWbCUnWyvYZauJ1/t5xQqqi9UWssRjbE1mI0Krq2Zb97qnONhzcclAPVpvEVdCCcl0rYZjQt6VI1PzHha56JepZCFCNvX3FVxYzEk=
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK7G5PgPkbp1awVqM5uOpMJ/xVrNirmwIT21bMG/+jihUY8rOXxSbidRfC9KgvSDC4flMsPZUrWziSuBDJAra5g=
|   256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHj/lr3X40pR3k9+uYJk4oSjdULCK0DlOxbiL66ZRWg
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=5/26%OT=22%CT=%CU=35758%PV=Y%DS=2%DC=T%G=N%TM=6652CBFE%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 29.321 days (since Fri Apr 26 18:00:39 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   95.49 ms 10.10.14.1
2   91.74 ms 10.10.11.11
```

This is what the website looks like.

![Untitled](BoardLight%20ef1d86f4c0bc4c468c1bec1f95968b7d/Untitled.png)

I checked the newsletter form, contact form, and looked around the website. It doesn’t seem to work at all, so the injection point is probably not in this asset. We can try subdomain brute forcing and directory brute forcing now.

I will first conduct directory brute forcing using Gobuster:

```html
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://board.htb/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 90
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://board.htb/
[+] Method:                  GET
[+] Threads:                 90
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 307] [--> http://board.htb/images/]
/css                  (Status: 301) [Size: 304] [--> http://board.htb/css/]
/js                   (Status: 301) [Size: 303] [--> http://board.htb/js/]
/server-status        (Status: 403) [Size: 274]
```

Nothing interesting with the directories. We might check the JS and source codes, but they don’t seem promising at the moment. Before checking the source code, we can try subdomain brute forcing using Gobuster again:

```html
┌──(kali㉿kali)-[~]
└─$ gobuster vhost -u http://board.htb/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 90 --append-domain --exclude-length 301
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:              http://board.htb/
[+] Method:           GET
[+] Threads:          90
[+] Wordlist:         /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] User Agent:       gobuster/3.6
[+] Timeout:          10s
[+] Append Domain:    true
[+] Exclude Length:   301
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: crm.board.htb Status: 200 [Size: 6360]
Found: CRM.board.htb Status: 200 [Size: 6360]
```

I added the newly found subdomain to my `/etc/hosts` file to gain access to it.

```html
┌──(root㉿kali)-[/home/kali]
└─# cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

10.10.11.11 board.htb crm.board.htb
```

Accessing the web page, we see it’s Dolibarr 17.0.0. Dolibarr ERP & CRM is modular business management software that adapts to the size of the company (SMEs, large companies, freelancers, or associations).

![Untitled](BoardLight%20ef1d86f4c0bc4c468c1bec1f95968b7d/Untitled%201.png)

After doing a few research on this version of Dolibarr, I found a CVE associated with it: [https://www.swascan.com/security-advisory-dolibarr-17-0-0/](https://www.swascan.com/security-advisory-dolibarr-17-0-0/)

## User Flag

This CVE allows us to execute Authenticated PHP Code Injection. So we need to be authenticated before we can inject PHP code. Trying the default username and password **`admin:admin`** worked perfectly as expected.

I followed the Proof of Concept (PoC) from the above URL by creating a web page from the “Websites” tab, then changing the HTML source to add our PHP reverse shell payload and get a reverse shell.

![Untitled](BoardLight%20ef1d86f4c0bc4c468c1bec1f95968b7d/Untitled%202.png)

The PHP code is flagged as disabled; however, it’s still possible to inject PHP code as the Test user by typing **`<?PHP code…?>`** instead of **`<?php code..?>`**.

![Untitled](BoardLight%20ef1d86f4c0bc4c468c1bec1f95968b7d/Untitled%203.png)

Before injecting, I have netcat actively listening on port 6969. (nc -nvlp 6969)

Once the injected payload is executed and we visit the site, I can see the shell popped up in my netcat session. I will quickly stabilize the shell with a Python TTY shell. With the shell as www-data, I will run LinPEAS to see if we have a vector to laterally move to the user Larissa.

After enumerating on my own without using LinPEAS, I found interesting stuff in **`/var/www/html/crm.board.htb/htdocs/conf/conf.php`**.

```html
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';
```

Here in this config file, I found the database username and password. I will use the MySQL command like this to log in to the database:

```bash
mysql -u dolibarrowner -p
```

(and password as: **`serverfun2$2023!!`**)

I can see the database names with **`SHOW DATABASES;`** too, but we already know the database name from the above config. I will select this database using **`use dolibarr;`** and try to see the available tables using **`SHOW TABLES;`**. I then executed:

```sql
SELECT * FROM llx_user;
```

I selected the interesting stuff from MySQL.

```html
mysql> select admin, pass_crypted, api_key, firstname, lastname from llx_user;
+-------+--------------------------------------------------------------+--------------+-----------+------------+
| admin | pass_crypted                                                 | api_key      | firstname | lastname   |
+-------+--------------------------------------------------------------+--------------+-----------+------------+
|     1 | $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm | NULL         |           | SuperAdmin |
|     0 | $2y$10$gIEKOl7VZnr5KLbBDzGbL.YuJxwz5Sdl5ji3SEuiUSlULgAhhjH96 | yr6V3pXd9QEI |           | admin      |
+-------+--------------------------------------------------------------+--------------+-----------+------------+
2 rows in set (0.00 sec)
```

I attempted to crack the first hash, which unfortunately remained uncracked. However, after a bit of frustration, I realized that the user password and the database password are the same. So, I SSHed to the user account with:

```bash
ssh larissa@board.htb
```

and used the password (**`serverfun2$2023!!`**) obtained from the **`conf.php`** file. And there we go, we have the user flag now.

## Root Flag

I quickly transferred LinPEAS to the target machine and ran it to see if there is any privilege escalation vector.

However, what I noticed is that this box had desktop, document, and picture files in the **`/home/larissa`** directory, which is not normal for a typical Linux server. This anomaly is likely due to the desktop environment installed on this box. So, I quickly tried to enumerate what desktop environment this box uses. It turns out this box uses version 0.23.1 of the Enlightenment desktop environment.

![Untitled](BoardLight%20ef1d86f4c0bc4c468c1bec1f95968b7d/Untitled%204.png)

After conducting some research, I found a working privilege escalation CVE associated with this desktop environment. The Proof of Concept (PoC) of the CVE can be found at: [https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit).

The Enlightenment Version: 0.25.3 is indeed vulnerable to local privilege escalation. The vulnerability lies in **`Enlightenment_sys`** before version 0.25.3, which allows local users to gain privileges because it is setuid root. The issue arises from the mishandling of pathnames that begin with a **`/dev/..`** substring. If an attacker has local access to a machine on which Enlightenment is installed, they can exploit this vulnerability to execute potentially dangerous actions.

I created an **`exploit.sh`** script in the **`/tmp`** directory and granted it execute permissions with **`chmod +x exploit.sh`**. Then, I executed the bash script downloaded from the GitHub link of the PoC, and, boom, we obtained a root shell.

## Conclusion

Thanks for following my write-up. Keep learning and happy hacking! 🙂
