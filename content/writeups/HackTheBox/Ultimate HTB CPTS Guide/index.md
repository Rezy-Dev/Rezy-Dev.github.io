![](assets/HTB%20Certified%20Penetration%20Testing%20Specialist.png)

# Introduction
Hello everyone, welcome to my **Ultimate HTB CPTS Guide**. Don’t worry—this won’t be just another CPTS blog. I wanted to write something different, because the **HTB CPTS environment was recently updated** and I couldn’t really find any **fresh exam experiences, tips, or tricks** online.

Back when I was grinding HackTheBox Season 5, I saw a few of my friends preparing for CPTS. At the time, I only knew about certifications like **PNPT, OSCP, CRTO, CRTP**, and CPTS felt completely foreign to me. I was still new to HTB seasonal boxes and mainly lived on **TryHackMe and PortSwigger Academy** before.

But the more I looked into it, the more CPTS stood out as **different**. Everyone kept calling it a **beast-level exam**, harder than OSCP in many ways, and the **10-day exam window** sounded terrifying and exciting at the same time. That challenge is what really hooked me—I wanted something that pushed me out of my comfort zone.

# My Mindset Going Into CPTS
After finishing the **CBBH path** (currently `CWES`), I felt extremely confident in **web exploitation**. That path doesn’t just show you vulnerabilities — it trains you to **break intended features** of web applications, an approach that massively improved my problem-solving mindset. I found it better than PortSwigger Academy at explaining vulnerabilities; if you read the contents properly, **word for word**, there’s a lot of deep material hidden in the lessons — **must read**.

When I compared that to CPTS, I thought: _If CBBH is already this solid, CPTS must be an absolute beast._ And that’s exactly what motivated me to commit.

I also had exposure to **TCM Security’s PNPT content** (though I didn’t take their exam) and TryHackMe Pathways (Jr Penetration Testing & Offensive Security Pathway). That gave me a good base already, but I kept hearing how CPTS was a **different level of difficulty**, especially with its **Active Directory and pivot-heavy labs**.

So I went in with this mindset:
- I wanted to tackle something **harder than OSCP**.
- I wanted to prove to myself I could survive a **10-day real-world exam simulation**.
- And I wanted to build a skillset that wasn’t just about passing an exam, but about becoming a stronger pentester.

# My HTB Academy Modules Journey
I began my HTB Academy journey by diving straight into the **CBBH** path (now renamed **CWES**) and then progressed through the **CPTS** (Certified Penetration Testing Specialist) track. Starting with the web-focused content gave me strong fundamentals in web exploitation and reconnaissance; by the time I completed the CPTS path I felt confident performing real-world web assessments.

Below I present a module-by-module account of what I studied, what I found valuable, gaps I encountered, and practical advice for anyone preparing for HTB CPTS or improving their bug-bounty/web-assessment skills.

## Web-Focused Modules (CBBH / CWES)

### Information Gathering — Web Edition

A highly practical module focused on reconnaissance. The module teaches both active and passive techniques to enumerate and map a target’s web footprint and technology stack. If you plan to do bug bounty work, this module’s recon coverage is directly applicable — the methodology taught here mirrors real-world recon workflows. Key takeaways:
- Learn to combine passive and active methods to build complete asset maps.
- Focus on technology fingerprinting and service discovery — these reduce chase time later in testing.
- Take meticulous notes: domain-ownership clues, subdomain patterns, and tech stack versions are often entry points.

### Using Web Proxies
Covers Burp Suite and OWASP ZAP. I personally used Burp for everything and skimmed ZAP, but the module is useful for exam completion and for understanding different proxy workflows. Practical advice:
- Master Burp’s essential features: repeater, intruder (or extenders for newer Burp releases), proxy history, and session handling.
- Learn how to script or extend your proxy workflow (Burp extensions), which pays off when dealing with unusual request flows.

### Fuzzing (ffuf → Web Fuzzing)
Originally the ffuf module, HTB updated this into a broader “Web Fuzzing” module. The ffuf module was excellent at teaching directory and resource fuzzing specifics; the new module expands tool coverage and strategy. Key lessons:
- Understand wordlist design (context-specific lists beat generic ones).
- Learn recursive fuzzing patterns and how to interpret responses (status, size, timing).
- The new module teaches tool-agnostic fuzzing mindsets — valuable for not becoming tool-dependent.

### Login Brute Forcing
This module felt narrow by itself and could have been merged with fuzzing, but the content is solid. Recent updates added **Medusa** alongside **Hydra**, and the module gives good coverage of:
- Account enumeration vs. credential stuffing approaches.
- Custom wordlist creation and contextual bruteforce strategies.
- Rate-limiting, lockout handling, and how to detect account lockout behaviors without causing damage.

### SQL Injection & sqlmap
I found the SQLi theoretical module to be accurate but lighter than expected. My recommendation: treat HTB’s SQLi theory as a starting point and supplement heavily with PortSwigger’s SQLi material for depth. The separate **sqlmap** module compensates by showing automation techniques for advanced exploitation scenarios. Notes:
- Learn manual exploitation first (union-based, error-based, boolean/time-based).
- Use sqlmap for escalation/automation only after understanding how payloads work and how to verify them manually.

### Cross-Site Scripting (XSS)
Short, well-focused, and practical. The module clearly explains the different XSS types and practical exploitation (reflected, stored, DOM). It also includes relevant scenarios like phishing and defacement — practical from both a real-world and a risk-assessment perspective.

### File Inclusion
A strong module with a lot of techniques (local file inclusion, remote file inclusion, php filter tricks, log poisoning). If you’re already familiar with PayloadsAllTheThings, much will feel familiar — but HTB adds context and structured learning. Tip: supplement with real-world payload repositories and note techniques like using filter wrappers and session poisoning to get RCE.

### File Upload Attacks
Covers bypasses for client-side and server-side checks and practical chaining techniques. Realistic lab coverage on how to bypass sanitizers and content-type checks — a high-value module for real assessments.

### Command Injection
One of the most comprehensive modules. This exceeded PortSwigger’s coverage in my view, especially regarding creative command chaining, environment manipulation, and escaping strategies. This is a module to _study and build a cheatsheet for_ — it’s dense with practical techniques.

### Web Attacks (Verb Tampering, IDOR, XXE)
This module bundles several important topics:
- HTTP verb tampering and non-standard verb behavior.
- IDORs: practical exploitation and real-world impact analysis — one of the most realistic-feeling sections.
- XXE: a bit more theoretical but covers advanced payloads and out-of-band exploitation vectors.  I recommend pairing the XXE section with PortSwigger labs for hands-on practice.

## CPTS / Network and Enterprise Path
### Penetration Testing Process
This module is a strong theoretical foundation: the stages of a pen test, pre-engagement criteria, reporting expectations, and how a professional engagement should be structured. Essential for anyone wanting to work in an industry environment. Take good notes here — it sets expectations for client communication and test boundaries.

### Getting Started (Practical Intro)
A gentle introduction using a sample HTB box (“nibbles”) that shows how a test progresses in practice. Great for consolidating early workflow patterns.

### Nmap & Footprinting
Realistic, practical scanning techniques and fingerprinting. Learn how to filter noise, prioritize results, and pivot from open ports to probable attack surfaces. HackTricks is an excellent complement when you encounter unfamiliar ports or services.

### Vulnerability Assessment (Nessus / OpenVAS)
The module is useful for job-oriented skill sets: understanding how vulnerability scanners complement manual testing. It’s realistic — on the job you’ll often produce scans and then prioritize results for manual verification.

### File Transfer
A deep, essential module. It covers multiple robust ways to exfiltrate and transfer files (sockets, web-based uploads, outbound connections, etc.). This was one of the most valuable modules I studied — file transfer techniques are used in nearly every real engagement. Take detailed notes for each technique and scenario.

### Shells & Payloads
Solid coverage of payload selection, how to identify the right shell type, and how to maintain footholds on Windows and Linux. The module frames payloads in attacker mindset context — not just “run this command” but “why this payload fits this network situation.”

### Metasploit
Quick and pragmatic. If you’re comfortable with Metasploit, you can skim; if not, the module gives a good practical introduction to the framework and common exploit workflows.

### Password Attacks
Historically slow due to long fuzzing/wait times, but updated lately to make practice faster. You’ll learn password cracking, brute-forcing, and credential harvesting techniques for both Linux and Windows. The skill assessments were simplified recently and felt easier; however, the underlying techniques and learning value remain high.

### Attacking Common Services
A long and somewhat repetitive module covering exploitation concepts for services found during footprinting (RDP, FTP, SSH, etc.). While I think this content could be consolidated (the same “attack concept” is repeated for each service), the module’s conceptual sections are valuable.

### Pivoting, Tunneling & Port Forwarding
This module is crucial. It teaches how to move laterally and maintain access across segmented networks. Practical advice:
- Diagram everything (I recommend Excalidraw or draw.io). Visualizing hosts, subnets, and pivot hops clarifies the pivoting strategy.
- Learn tools like ligolo-ng for advanced, stealthy pivots (the module doesn’t cover every tool in depth — external videos are useful).
- Practice chaining simple pivots before trying sophisticated DNS/ICMP tunneling.

### Active Directory Enumeration & Attacks
If you’ve practiced with internal domain setups (e.g., I did from PNPT labs), this module will feel familiar but still contains vast amount of valuable attack vectors, especially cross-forest attacks — a complex topic that HTB explains well. Make sure to take note of each and every section.

### Attacking Common Applications
A long, comprehensive set of labs on CMSes, common application stacks, and attack patterns. Some parts felt out of place (thick client content, which HTB may soon remove), but overall the module is thorough for web-app-related enterprise targets.

### Linux & Windows Privilege Escalation
Solid, practical material. If you’ve already trained with PNPT or similar labs, much will be familiar; however, Windows priv-esc includes several less-common techniques worth noting.

### Documentation & Reporting
A surprisingly important module. HTB’s documentation guidelines are industry-aligned: how to structure findings, impact statements, remediation guidance, and how to present evidence. The skill assessment here seemed unnecessary, but the module content is essential for producing professional reports.

### CrackMapExec / NetExec (Tool Module)
This is a tool-specific module that costs in-curriculum “cubes.” It’s useful for skill assessment practice, but the official documentation for CrackMapExec/NetExec is more up-to-date. Do the module's Skill Assessment for the exam practice; use the official docs for current feature sets and advanced usage.

### Attacking Enterprise Network (AEN) Lab
The capstone lab that ties everything together. It’s a realistic environment to practice a full-scope penetration test and produce a report. I used SysReptor to draft my AEN report and recommend a similar structured reporting tool. A useful practice is to attempt the lab twice: once once blind, and with hints— the second run improves retention and problem-solving under exam conditions.

# From Academy to Real-World Practice
After finishing the CPTS curriculum I purchased HTB ProLabs to consolidate skills under realistic, time-boxed pressure. Below is a polished, professional account of that stage — 
what I practiced, how it helped, and recommendations for other candidates.

## ProLabs: Dante, Zephyr, and Mini-ProLabs

### Dante
I started with **Dante**, a ProLab containing 14 machines. Dante is an excellent beginner-level environment that strongly emphasizes **pivoting**. The lab’s network design forces multiple pivot hops and realistic lateral movement, which is exactly the type of practice you need to internalize pivoting concepts, post-exploitation persistence, and multi-host attack chains. Dante’s progressive difficulty and number of hosts made it a high-value time investment — you’ll repeatedly revisit pivot strategies and tooling, and by the end you’ll have far more confidence chaining exploits across segmented networks.

### Zephyr (intermediate)
Next I attempted **Zephyr**, another intermediate ProLab with significant **Active Directory (AD)** content and very challenging pivoting scenarios. Zephyr felt substantially harder than Dante: AD attack paths were deeper, and lateral movement required more careful planning and technique chaining. It pushed me to apply cross-module knowledge (AD enumeration, credential harvesting, pivoting, persistence, and privilege escalation) in a single cohesive exercise. Despite the difficulty, I completed the entire environment — Zephyr rewarded persistence and methodical documentation of each step.

### P.O.O. (mini-ProLab)
I also completed a smaller, focused ProLab (P.O.O.). This mini-ProLab was simpler than expected and served as a confidence booster and a quick skills refresher. Mini-ProLabs like this are useful for warming up before larger sessions or when you want to practice a specific technique without committing many hours.


# Note Taking
Throughout my CPTS journey and ProLab practice, I used **Obsidian** for note-taking. It turned out to be one of the best decisions I made. I documented everything — from enumeration commands and exploitation steps to post-exploitation tricks — directly inside Obsidian, organizing them in a structured, searchable format.

To keep my data safe and accessible across devices, I **pushed the entire Obsidian vault to a private GitHub repository**, which gave me both version control and backup peace of mind.

My note-taking style followed the same approach used in **HackTricks** and **PayloadAllTheThings** — concise, categorized, and example-driven. Every note had short explanations, payloads, and ready-to-use snippets. This format made it extremely easy to **search and reference** during labs or while troubleshooting.

If you’re starting your own journey, I highly recommend building your notes **in a similar style** — treat your vault like a personal HackTricks. Well-structured notes not only help you retain knowledge but also make last-minute review before exam significantly easier.

# My CPTS Exam Experience
The CPTS exam was a completely different experience than I expected, even after doing AEN, ProLabs, and other Hack The Box environments. Everything about the setup — from network segmentation to privilege escalation paths — felt like attacking a real company. It’s designed to test your ability to think methodically, not just exploit vulnerabilities. The exam truly forces you to apply every concept from the course in a simulated real-world environment where nothing is handed to you. That realism was both intimidating and exciting, and it made me appreciate how well the CPTS path prepared me for practical penetration testing.

In the beginning, I approached the exam calmly. I didn’t rush to burn energy on the first day; instead, I focused on recon and took proper breaks to keep my focus sharp. Once I got into the rhythm, the flags started coming steadily, and I gained confidence after the first few footholds. Things were going smoothly until I hit Flag 8 — that one absolutely tested my patience and endurance. It took me an entire day of enumeration, trial, and lateral thinking before finally breaking through. That single flag taught me more about persistence, pivoting, and creativity under pressure than any lab I had done before. It was the point where I realized how mentally demanding the CPTS exam really is.

After that long battle, the rest of the environment felt much smoother. I continued to collect flags at a consistent pace, but I also made sure not to push myself into burnout. I kept a balanced routine — taking rest, attending my classes, and spending time refining my documentation as I went. When I eventually crossed the passing threshold, I focused entirely on polishing the report instead of rushing for the remaining flags. That decision paid off: I managed to create a clean, thorough submission that clearly communicated my findings, impact, and methodology.

Once the report was complete, I trimmed it down from nearly 280 pages to around 230 to make it more concise without losing technical depth. Interestingly, the exam portal went under maintenance for about an hour during my attempt, and HTB support generously added two extra days to my timer. I didn’t even need to use that extension since I had already finished early and finalized my report. When I finally submitted it, I was nervous — expecting a long wait — but to my surprise, the results came in within just 38 hours. The entire experience, from start to finish, taught me how critical consistency, note-taking discipline, and calm problem-solving are under time pressure. 

I also like how HackTheBox provides you feedback even if you pass the exam. Here is the feedback I received:
![](assets/Pasted%20image%2020251029205342.png)


# My **Top 10 CPTS Tips**
1. **Don’t rush Academy — build a strong base**  
    Take your time going through the HTB Academy modules. Every concept there will show up in some way during the exam. Understanding _why_ something works is more important than just knowing _how_ it works.
    
2. **Treat ProLabs like mini real-world jobs**  
    When you’re in a ProLab, act like you’re doing an actual company assessment. Take notes, document everything, and plan your attacks methodically. The more professional your workflow here, the smoother your exam experience will be.
    
3. **Active Directory skills are the make-or-break**  
    AD environments dominate both the labs and the exam. Learn enumeration techniques, privilege escalation paths, and cross-domain attacks thoroughly — these will separate a passing candidate from an exceptional one.
    
4. **Automate recon, but never skip manual checks**  
    Tools are great for speed, but they miss nuances that a human eye catches. Always verify tool results manually and look for patterns or misconfigurations automation might overlook.
    
5. **Keep your notes simple, structured, and reusable**  
    Write notes like you’re building your own HackTricks — clean, categorized, and searchable. This will save you countless hours during the exam and even in future engagements.
    
6. **Practice reporting before the exam — don’t leave it last minute**  
    Reporting is a major part of CPTS. Don’t wait until the final day to figure out how to structure or format your report. Create a template early and practice writing short sample reports as you finish modules or labs.
    
7. **Manage your health during the exam (sleep/food/breaks)**  
    The exam is long, mentally draining, and can easily push you into burnout. Take proper breaks, stay hydrated, and rest — a clear mind will solve problems faster than an exhausted one.
    
8. **Don’t get stuck too long — pivot to another box**  
    It’s easy to lose track of time on a single machine. If you’re completely stuck, switch focus, take a short break, or pivot to another system. Fresh eyes often spot what you missed earlier.
    
9. **Track your progress & celebrate small wins**  
    Whether it’s getting a new foothold, escalating privileges, or finding an interesting vector — celebrate it. It keeps motivation high and reminds you how far you’ve come.
    
10. **Remember: CPTS is not just about passing, it’s about becoming a better pentester**
    The real goal isn’t just the certification — it’s mastering the mindset of a penetration tester. Focus on learning, documenting, and understanding. The pass will naturally follow.

# Conclusion
The **CPTS journey** is more than a certification path — it’s a transformation. It takes you from simply _knowing vulnerabilities_ to actually _thinking like a professional penetration tester_. Every module, lab, and exam challenge builds a deeper sense of how real-world networks, systems, and organizations operate. It’s not an easy path, but every hour you invest gives you tangible skills that directly translate into practical hacking and security assessment capabilities.

CPTS isn’t just a cert you add to your résumé — it’s a **mindset shift**. It teaches discipline, documentation, and patience. It forces you to approach problems strategically rather than relying on guesswork or tool automation. The blend of theory, hands-on labs, and the final exam mirrors the pressure and thrill of real-world red teaming. When you finally reach the end, you don’t just earn a title — you walk away more confident, analytical, and methodical.

For anyone starting this journey, my biggest advice is: **don’t rush it**. Enjoy the process. Take detailed notes, build your foundation through the Academy modules, and learn to think like an attacker and a defender. The more effort you put into understanding the “why” behind every exploit, the more rewarding your experience will be.

The CPTS journey may challenge your patience, sleep, and determination, but it will shape you into a more complete hacker — one who not only knows how to exploit but also understands the value of professionalism, structure, and continuous learning. If you’re just getting started, keep going — every small win adds up. The certification is just the milestone; the **real reward is who you become through it.**