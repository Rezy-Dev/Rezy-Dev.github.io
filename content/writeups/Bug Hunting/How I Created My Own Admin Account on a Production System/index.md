---
title: How I Created My Own Admin Account on a Production System
date: 2025-11-30
description: A severe authorization flaw allowed the creation of a full-privilege admin account on a major Fortune 50 company’s live platform. This resulted in unrestricted access to sensitive financial data, internal files, and the ability to delete users and organizations.
summary: A severe authorization flaw allowed the creation of a full-privilege admin account on a major Fortune 50 company’s live platform. This resulted in unrestricted access to sensitive financial data, internal files, and the ability to delete users and organizations.
draft: false
tags:
  - Broken Access Control
  - Information Disclosure
  - Privilege Escalation
cover:
  image: "feature.jpg"
---

Hello everyone! My name is **Raunak Neupane**, better known as **“rezydev”**. I’m a security researcher who enjoys uncovering vulnerabilities that help organizations strengthen their defense.

In this write‑up, I’m going to share how I was able to **create my own administrative account** on a production platform belonging to a company recognized in the **Fortune 50 Best Companies to Work For® List (2025)**. With no prior permissions, this flaw allowed me to **delete any user**, **remove entire organizations**, and gain unrestricted access to highly sensitive financial‑related records. I was also able to access and download internal files, including confidential PDFs and company submission documents, clearly demonstrating a **critical security failure** that required immediate remediation.

Below is the CVSS v3.1 severity score assigned to this vulnerability:
![](assets/Pasted%20image%2020251127104343.png)

To demonstrate how this issue was exploited, let’s start from the very beginning, **how I found the application in the first place**.

# Reconnaissance
Since the program scope mentioned that **any application owned by “NCA Finance”** was in‑scope, I began my reconnaissance phase focused on discovering external assets tied to the organization. To avoid interacting with the primary public domain directly, I started with **Google Dorking** to uncover additional infrastructure that may not be well‑known or linked publicly.

I crafted a simple but effective dork targeting the company’s footer signature:
```bash
"© 2025 NCA Finance, Pvt. Ltd."
```

To filter out noise from the company’s primary domain, I excluded it using the minus operator:
```bash
"© 2025 NCA Finance, Pvt. Ltd." -ncafinance.com
```

This allowed me to surface **additional domains** associated with NCA Finance that were not tied to the main website. One of those stood out as potentially interesting and worth deeper inspection.

## Subdomain Enumeration
Next, I ran **Subfinder (by ProjectDiscovery)** on the newly identified domain to enumerate all associated subdomains:
```bash
❯ subfinder -d anotherncafinance.com

               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/

		projectdiscovery.io

[INF] Current subfinder version v2.7.1 (outdated)
[INF] Loading provider config from /home/rezy/.config/subfinder/provider-config.yaml
[INF] Enumerating subdomains for anotherncafinance.com
ns2.anotherncafinance.com
ns1.anotherncafinance.com
www.anotherncafinance.com
.anotherncafinance.com
finance.anotherncafinance.com
[INF] Found 7 subdomains for anotherncafinance.com in 14 seconds 269 milliseconds
```

Among these, the subdomain:

> **finance.anotherncafinance.com**

was particularly interesting, it hosted a production application that eventually turned out to be **critically vulnerable**.

This marked the beginning of my journey into discovering multiple access control flaws that would later lead to **full administrative takeover**.

# Exploitation
Before walking through the actual exploitation steps, I want you to **follow along interactively**, because _doing_ is always better than just _reading_. To help you understand this vulnerability in action, I created a **fictional** CTF challenge that closely mimics the real‑world issue I reported.

You can participate here:

> **[https://ctf.ncateam.xyz/](https://ctf.ncateam.xyz/)**

### How to Join the Simulation
1. Register a new account
2. Verify your email (*make sure to check SPAM*)
3. Log in
4. Join the game using the invite code:
```bash
NCAxBBReportsCTF2025
```

> ⚠ **Note**: You must be part of a team to join the game.  
> If needed, you can simply **create your own team**.

Once you’re inside, you’ll gain access to the CTF challenge environment, designed to replicate the **broken access control flaw** I discovered in production.

![](assets/Pasted%20image%2020251127110448.png)

The challenge is called **“NCA Finance.”** You can create a container and start hacking the application right away.

When we first visit the application, we are presented with a standard login page. Nothing unusual at a glance, just a typical form requiring valid credentials to access the system.
![](assets/Pasted%20image%2020251127110632.png)

However, appearances can be deceiving.

Since the login page didn’t provide any visible option to create a new account, I decided to **inspect the page source** to see if there were any hidden or disabled features left behind by the developers.

And that’s when I noticed something interesting:
![](assets/Pasted%20image%2020251127110813.png)

Even though the registration button was not displayed on the UI, the code for it was still present and the endpoint remained fully active. This meant the developers likely **intended** to restrict user registration, but only did so visually, without disabling the route itself.

This is a common security oversight:

> _Removing the interface does not remove the functionality._

Curious to see if the endpoint still worked, I manually visited:
![](assets/Pasted%20image%2020251127110902.png)

With the registration endpoint confirmed as publicly accessible, the next logical step was to test whether I could successfully create a new user account. I filled out the required fields and submitted the form, and it worked flawlessly.
![](assets/Pasted%20image%2020251127111017.png)

There were **no restrictions**, **no invite requirements**, and **no approval workflow**. Any external visitor could simply register and gain access to the internal system.

After completing the registration process, I logged in using the newly created credentials through the main login page. At this point, I was authenticated as a **normal user**, someone who should only be able to access basic and restricted functionality.
![](assets/Pasted%20image%2020251127111057.png)

After logging in with the newly created standard user account, I initially hit a **dead end**. The interface was minimal, not a single feature seemed available for exploration. At first glance, it looked like this account had **no meaningful access** at all.

But in security research, we **never stop at what’s visible**. Hidden functionality often lurks behind endpoints that are not linked in the UI.

To uncover these, I began **fuzzing directories and endpoints**. The goal was to identify any routes that the authenticated user could reachm, even ones that were meant to be restricted to admins or internal staff.

```bash
❯ dirsearch -u http://challenge.ncateam.xyz:33138/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460


Target: http://challenge.ncateam.xyz:33138/

[10:40:28] Starting: 
..SNIP..
[10:40:48] 200 -   1KB - /account/login
[10:40:48] 200 -   1KB - /account/register
..SNIP..
..SNIP..
..SNIP..
[10:42:09] 200 -   53KB - /users
```

I identified a particularly interesting endpoint that responded with **HTTP 200 OK**:
```bash
[10:42:09] 200 -   53KB - /users
```

Visiting this page immediately exposed a **full list of all registered users**, including:
- Usernames
- Email addresses
- Roles
![](assets/Pasted%20image%2020251127112231.png)

Even worse, the page included **functional controls** such as:
- **Edit User**
- **Delete User**
- **Create New User**

> *Please note that I did not include Edit User, Delete User functionality in this fictional CTF.*

This is a textbook example of **Broken Access Control**:
> The system failed to restrict administrative functionality to admin‑only accounts.

Meaning:  
A non‑privileged user (like the one I created) was suddenly able to manage and manipulate user accounts, including those with administrative roles.

At this moment, the severity of the issue became clear:  
If a standard user can edit roles or delete critical accounts, then the platform is essentially open for **complete takeover**.

This discovery paved the way for full administrative privilege escalation, and things were about to get even more impactful.

Once I confirmed that the `/Users` endpoint exposed sensitive administrative functionality, the next logical step was to test whether I could **modify roles** or **create privileged users**.

![](assets/Pasted%20image%2020251127112353.png)

To my surprise, the “Create New” button allowed me to create a user with **Admin** role directly from the interface, with **no verification**, **no authorization checks**, and **no restrictions**.

So, I generated a brand‑new account with the **Administrator** role:
![](assets/Pasted%20image%2020251127112523.png)

Interestingly, when creating the new admin account, the application briefly displayed an error message stating that I **did not have permission** to create a new user. 
![](assets/Pasted%20image%2020251127112533.png)

However, despite the error, the backend logic **still processed and saved the request**, successfully creating a new account with **administrative privileges**.
![](assets/Pasted%20image%2020251127112854.png)

This revealed a **logical flaw in the code**:
> The frontend attempted to block the action, but the backend lacked proper authorization checks, meaning the front‑end “error” had no real effect on security.

Once logged in as the newly created admin, I had **unrestricted access** to a wide variety of sensitive internal records and client data.
![](assets/Pasted%20image%2020251127113018.png)

Among the exposed information were:
- **Client submission forms** containing detailed personal and financial information
- **Confidential PDF documents** related to capital allowances, tax filings, and other sensitive financial operations
- **Internal company records** detailing user accounts, organizational structures, and operational data

These files were **directly downloadable** from the admin dashboard without any further checks.

The impact of this is critical:
> An attacker could exfiltrate confidential business and client data, potentially resulting in **regulatory violations**, **data privacy breaches**, and severe **reputational damage**.

And since I approached this writeup like a CTF, the “flag” was represented as a confidential PDF belonging to a fictional partner company named **Flag Pvt. Ltd.**. By navigating through the admin interface, I was able to locate and download the PDF file to retrieve the flag, demonstrating full unauthorized access to sensitive documents.
![](assets/Pasted%20image%2020251127113229.png)

# Conclusion
This vulnerability showed how a single missing access control check can quickly escalate from a harmless-looking login page to **complete system compromise**. By chaining together small weaknesses, an exposed registration page, hidden admin endpoints, and flawed authorization logic, an attacker could gain full admin control and access highly confidential financial data.

Since this was part of a **VDP (Vulnerability Disclosure Program)**, I did **not receive any monetary reward** for this finding. However, I am genuinely happy to have helped **secure the organization** and protect their clients’ sensitive information.

I sincerely appreciate the quick and professional response from the security team after reporting this issue. It’s always rewarding when responsible disclosure leads to real security improvements. This finding highlights just how important strong access controls truly are.

Thanks for reading! ✌️

---

Follow: [@rezydev](https://x.com/RezyDev) on Twitter! 