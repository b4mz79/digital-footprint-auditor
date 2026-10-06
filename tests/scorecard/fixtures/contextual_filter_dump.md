BEFORE
```json
{
  "schema_version": "contextual-filter-dump-v2",
  "filter": "security_publication_context_v2",
  "generated_at": "2026-10-05T17:27:27.489409+00:00",
  "records": [
    {
      "domain": "ashbyhq.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://careers.microsoft.com/v2/global/en/locations/sao-paulo.html",
      "title": "Jobs in São Paulo - Microsoft Careers",
      "summary": "Completes required security and data management training while complying with security and data management procedures/policies with guidance from other ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/asus-com-compromised-link-to-ani-exploit/30317/",
      "title": "asus.com compromised: link to ANI exploit - Securelist",
      "summary": "We've just confirmed multiple reports about asus.com, a very well known hardware manufacturer, being compromised.",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/operation-shadowhammer/89992/",
      "title": "Operation ShadowHammer | Securelist",
      "summary": "Earlier today, Motherboard published a story by Kim Zetter on Operation ShadowHammer, a newly discovered supply chain attack that leveraged ASUS Live Update software. In January 2019, we discovered a sophisticated supply chain attack involving the ASUS Live Update Utility . We have contacted ASUS and informed them about the attack on Jan 31, 2019, supporting their investigation with IOCs and descriptions of the malware. IOCs Kaspersky Lab verdicts for the malware used in this and related attacks: - asushotfix[.]com - Vulnerabilities and exploits - ASUS 3. Any idea if ASUS wireless routers were affected by this as well? I noticed in that same time frame that several of these that I manage required multiple reboots to resolve wireless connectivity issues (wireless signal dropping unexpectedly, unexplained slow internet speeds, etc) when previously these were behaving perfectly. Reply 2. Im wondering the same thing. Luckily ALL 5 of my ASUS motherboard PCs arent infected, as well as my ASUS laptop. But ironically I had bought a brand new ASUS router last year (RT-N66u) and it happened to be one of the very few routers that were one of the models to get their Firmware infected with malware (possibly even having the malware on the router when I bought it brand new from newegg.com ) Definitely not neweggs fault , but kinda scary knowing that other people and possibly mine as well were shipped brand new with the infected firmware that could be dormant for an indefinite amount of time and then enabled remotely one day to start relaying data to Russia etc. AKa using peoples bandwidth to turn their network into a botnet to give them access to a very large amount of routers to use at their disposal for DDoS attacks etc. Reply 1. This was an exploit to the Asus Live Update software for their Laptops. If this program was uninstalled or not updated after the hack occurred you wouldn’t be affected. Reply 9. Is it possible that the certificate was left on a server, and then used to",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/category/incidents/page/25/",
      "title": "Category: Incidents | Page 25 | Securelist",
      "summary": "Recent website hacks, malware epidemies, data leaks and other information security incidents ... asus.com compromised: link to ANI exploit · Roel Schouwenberg ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "navigation_page",
      "signals": {
        "page_type": "navigation",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "navigation_page"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/author/roel/page/7/",
      "title": "Author: Roel Schouwenberg | Page 7 | Securelist",
      "summary": "asus.com compromised: link to ANI exploit · Events · The more things change ... Kaspersky researchers reveal previously undocumented malware attributed to ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "navigation_page",
      "signals": {
        "page_type": "navigation",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "navigation_page"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/browsing-malicious-websites/36273/",
      "title": "Browsing malicious websites - Securelist",
      "summary": "2 asus.com compromised: link to ANI exploit; 3 Active anti-reverse techniques in Javascript; 4 'Gumblar' attacks spreading quickly; 5 Asprox ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "reference_page",
      "signals": {
        "page_type": "reference",
        "target": "summary_domain",
        "target_strength": "medium",
        "security": true,
        "reason": "reference_page"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2019/05/14/plead-malware-mitm-asus-webstorage/",
      "title": "Plead malware distributed via MitM attacks at router level, misusing ...",
      "summary": "Plead malware distributed via MitM attacks at router level, misusing ASUS WebStorage ESET researchers have discovered that the attackers have been distributing the Plead malware via compromised routers and man-in-the-middle attacks against the legitimate ASUS WebStorage software Anton Cherepanov Anton Cherepanov 14 May 2019 • , 6 min. read Plead malware distributed via MitM attacks at router level, misusing ASUS WebStorage In July 2018 we discovered that the Plead backdoor was digitally signed by a code-signing certificate that was issued to D-Link Corporation. Recently we detected a new activity involving the same malware and a connection to legitimate software developed by ASUS Cloud Corporation. The Plead malware is a backdoor which, according to Trend Micro, is used by the BlackTech group in targeted attacks. What has happened? At the end of April 2019, ESET researchers utilizing ESET telemetry observed multiple attempts to deploy Plead malware in an unusual way. Specifically, the Plead backdoor was created and executed by a legitimate process named AsusWSPanel.exe. As seen in Figure 1, the executable file is digitally signed by ASUS Cloud Corporation. Figure 1. The AsusWSPanel.exe code-signing certificate Figure 2. Plead backdoor - %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\slui.exe - %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ctfmon.exe - %TEMP%\\DEV[4 random chars].TMP Conclusion ESET researchers notified ASUS Cloud Corporation prior to this publication. Indicators of Compromise (IoCs) | ESET detection names | |-| | Win32/Plead.AP trojan | | Win32/Plead.AC trojan | | C&C servers | |-| | update.asuswebstorage.com.ssmailer[.]com | | [www.google.com.dns-report\\[.\\]com](http://www.google.com.dns-report\\[.\\]com) | MITRE ATT&CK techniques | Tactic | ID | Name | Description | |-|-|-|-| | Execution | T1203 | Exploitation for Client Execution | BlackTech group exploits a vulnerable update mechanism in ASUS WebStorage software in order to deplo",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2019/05/17/week-security-tony-anscombe-23/",
      "title": "Week in security with Tony Anscombe - WeLiveSecurity",
      "summary": "ESET researchers detail how ASUS's cloud service has been abused to distribute the Plead malware; in other news, ESET's telemetry shows that the use of the ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2020/07/09/popular-home-routers-plagued-critical-security-flaws/",
      "title": "Popular home routers plagued by critical security flaws - WeLiveSecurity",
      "summary": "A recent study of 127 home routers from seven, mostly large vendors has found that nearly all tested routers are affected by scores of ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2020/02/26/krook-serious-vulnerability-affected-encryption-billion-wifi-devices/",
      "title": "KrØØk: Serious vulnerability affected encryption of billion+ Wi-Fi devices",
      "summary": "ESET researchers uncovered a security flaw affecting Wi-Fi chips that are commonly used in devices such as smartphones, tablets, laptops, ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2019/10/08/needles-haystack-unwanted-uefi-components/",
      "title": "Needles in a haystack: Picking unwanted UEFI components out of ...",
      "summary": "UEFI (Unified Extensible Firmware Interface) security has been a hot topic for the past few years, but, due to various limitations, ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/answers/questions/2733690/my-brand-new-asus-laptop-came-with-pre-installed-m",
      "title": "My brand new Asus laptop came with pre-installed malware.",
      "summary": "You can submit a sample of any detected threat(s) to the Microsoft Malware ... asus.com/us/support/. Regards… Was this answer helpful? Yes No. 2 ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "non_article_page",
      "signals": {
        "page_type": "non_article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "non_article_page"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/answers/questions/2738380/asus-laptop-running-windows-8",
      "title": "asus laptop running windows 8 - Microsoft Q&A",
      "summary": "This is how to use the Asus Recovery process. http://www.asus.com/support/FAQ/[REDACTED]/. \"What to do if you forget your Windows 8/8.1 password ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "non_article_page",
      "signals": {
        "page_type": "non_article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "non_article_page"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-nz/answers/questions/acf887e5-5cb8-4618-9ae6-c577a7fd7644/asus-laptop-not-charging?forum=windows-all&referrer=answers",
      "title": "ASUS laptop not charging - Microsoft Q&A",
      "summary": "... email them via their website. Choose your region: https://www.asus.com/entry.htm. Was this answer helpful? Yes No. 0 comments No comments.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "non_article_page",
      "signals": {
        "page_type": "non_article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "non_article_page"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://apps.microsoft.com/detail/9p8v2wqtd7mb?hl=ug-CN&gl=FR",
      "title": "ASUS Expert Site Manager - Windows دا ھەقسىز چۈشۈرۈش ۋە قاچىلاش",
      "summary": "... security and multi-network management in business scenarios. ASUS Expert ... تارقاتقۇچىنىڭ ئۇچۇرى. نام. ASUSTeK COMPUTER INC. تورخەت. asc su***@a***.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "security_context_missing",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": false,
        "reason": "security_context_missing"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/answers/questions/3232741/bsod-possible-connection-to-asus-easy-update",
      "title": "BSOD possible connection to asus easy update - Microsoft Q&A",
      "summary": "More methods to check for malware in my next message though this case may not be malware related. ... http://vip.asus.com/forum/default.aspx?",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "non_article_page",
      "signals": {
        "page_type": "non_article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "non_article_page"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/realtek-sdk-vulnerability/",
      "title": "Realtek SDK Vulnerability Attacks Highlight IoT Supply Chain Threats",
      "summary": "Realtek SDK Vulnerability Attacks Highlight IoT Supply Chain Threats Executive Summary As of December 2022, we’ve observed 134 million exploit attempts in total leveraging this vulnerability, and about 97% of these attacks occurred after the start of August 2022. Vulnerability Overview - A script executes a shell command on the targeted server. This script actively connects to a malicious IP address, and automatically downloads and executes malware (shown in Figure 1). These threats were mostly from the Mirai malware family. Malware Analysis The second wave of the RedGoBot campaign was observed in November 2022, when the threat actor switched its malware host to [REDACTED][.] In this campaign, the shell script utilizes wget and curl to download the following botnet clients to accommodate different processor architectures: Attack Origin Analysis This could mean that the attacker is changing the proxy while continuing to exploit this vulnerability. From this data, we can see that when launching a campaign, attackers could host the malware on multiple sites.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/microsoft-cve-2025-59287/",
      "title": "Microsoft WSUS Remote Code Execution (CVE-[REDACTED] ...",
      "summary": "- Vulnerabilities",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/volt-typhoon-threat-brief/",
      "title": "Threat Brief: Attacks on Critical Infrastructure Attributed to Insidious ...",
      "summary": "Threat Brief: Attacks on Critical Infrastructure Attributed to Insidious Taurus (Volt Typhoon) Executive Summary These techniques include performing extensive pre-compromise reconnaissance, the exploitation of known or zero-day vulnerabilities in public-facing network appliances to gain initial access, and a focus on gaining administrator credentials within a victim environment. The vast majority of the devices included in the botnet were routers that were vulnerable because they were no longer supported through their manufacturer’s security patches or other software updates.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/iot-supply-chain/",
      "title": "Risks in IoT Supply Chain - Palo Alto Networks Unit 42",
      "summary": "Risks in IoT Supply Chain Examples of IoT Supply Chain Attacks Firmware – OpenWrt Devices In March 2020, a vulnerability found in OpenWrt allowed attackers to impersonate downloads from downloads.openwrt.org and make the devices download malicious updates. Types of Motivation for Attacks on the IoT Supply Chain Cyberespionage Perspective In 2018, Operation ShadowHammer revealed that legitimate ASUS security certificates (such as “ASUSTeK Computer Inc.”) were abused by attackers and signed trojanized softwares, which misled targeted victims to install backdoors in their system and download additional malicious payloads onto their machines. Conclusion Identified devices vulnerable to CVE-2019-[REDACTED]. Identified devices vulnerable to CVE-[REDACTED].",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/new-mirai-variant-adds-8-new-exploits-targets-additional-iot-devices/",
      "title": "New Mirai Variant Adds 8 New Exploits, Targets Additional IoT ...",
      "summary": "- Malware Malware",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/mata-multi-platform-targeted-malware-framework/97746/",
      "title": "MATA: Multi-platform targeted malware framework - Securelist",
      "summary": "- Threats - Vulnerabilities and exploits Recently, we reported to our Threat Intelligence Portal customers a similar malware framework that internally we called MATA. Victims After deploying MATA malware and its plugins, the actor attempted to find the victim’s databases and execute several database queries to acquire customer lists. In addition, MATA was used to distribute VHD ransomware to one victim, something that will be described in detail in an upcoming blog post. Conclusion In addition, the actor behind this advanced malware framework utilized it for a type of cybercrime attack that steals customer databases and distributes ransomware.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/it-threat-evolution-in-q3-2021-pc-statistics/104982/",
      "title": "IT threat evolution in Q3 2021. PC statistics - Securelist",
      "summary": "PC threat statistics for Q3 2021 contain data on miners, encrypting ransomware, financial malware, and threats to Windows, macOS and IoT.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/trusted-relationship-attack/112731/",
      "title": "Trusted relationship attacks | Securelist",
      "summary": "- Threats - Vulnerabilities and exploits Attack development | | | | |-|-|-| | No. | Event | Description | | 1 | Gaining access to service providers | In most cases, the hack started by exploiting vulnerabilities in software accessible from the internet ( Initial Access, Exploit Public-Facing Application, T1190). | | 3 | Actions after compromising credentials for connecting to target organizations | Group A, having discovered credentials for connecting to the service provider’s clients’ VPN tunnel, penetrated their infrastructure on the same day: the attackers connected to systems allocated to the contractor via the RDP protocol using accounts allocated for the contractor’s employees ( Initial Access, Valid Accounts: Domain Accounts, T[REDACTED]), established persistence using the Ngrok utility (probably in case of losing access to the VPN), and returned to the new victims’ infrastructure after several months. Up to three months could have passed between initial access to the target organization and attack discovery. | | 7 | Fulfilling attack objectives | In most cases, the attackers launched ransomware in the target organization’s infrastructure ( Impact Data, Encrypted for Impact, T1486). It’s worth noting that group policies or remote creation of Windows services were often used to distribute ransomware files in the infrastructure. Less frequently, distribution and execution were carried out manually. | Key MITRE ATT&CK tactics and techniques used in trusted relationship attacks Reports - Vulnerabilities and exploits",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2015/02/03/hipchat-hack-password/",
      "title": "HipChat hack leads to precautionary password reset - WeLiveSecurity",
      "summary": "Australian enterprise software firm Atlassian has told customers that it recently suffered a security breach that saw hackers access names, usernames, email ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2018/01/05/meltdown-spectre-cpu-vulnerabilities/",
      "title": "Meltdown and Spectre CPU Vulnerabilities - WeLiveSecurity",
      "summary": "Critical flaws in the CPU that affects almost every device has been exploited by Meltdown and Spectre exposing nearly any data the computer ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/deutsch/2018/01/05/meltdown-und-spectre-cpu-sicherheitsluecken/",
      "title": "Meltdown und Spectre Sicherheitslücken: Was ... - We Live Security",
      "summary": "Kritische Fehler in der CPU-Prozessorarchitektur können von Meltdown und Spectre ausgenutzt werden, um Daten abzufangen und auszuspähen.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/es/ransomware/ransomhub-crece-america-latina-nivel-global/",
      "title": "RansomHub: un grupo de ransomware que crece en América ...",
      "summary": "RansomHub es un grupo de ransomware que comenzó a operar en inicios a 2024, tras el desmantelamiento del grupo ALPHV/BlackCat.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/la-es/2021/07/30/vulnerabilidades-explotadas-mayor-frecuencia-cibercriminales-2020/",
      "title": "Las vulnerabilidades explotadas con mayor frecuencia por ...",
      "summary": "Las vulnerabilidades explotadas con mayor frecuencia por cibercriminales en 2020 ; Microsoft, CVE-[REDACTED], RCE ; Atlassian, CVE-[REDACTED], RCE.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "security_context_missing",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": false,
        "reason": "security_context_missing"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/defender-cloud-apps/protect-atlassian",
      "title": "How Defender for Cloud Apps helps protect your Atlassian environment",
      "summary": "Refresh the Atlassian API key every 6 months to avoid expiration-related issues. To revoke and replace the key: Navigate to admin.atlassian.com ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "security_context_missing",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": false,
        "reason": "security_context_missing"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/microsoft-365-app-certification/teams/atlassiancom-jira-data-center",
      "title": "Jira Data Center - Microsoft 365 App Certification",
      "summary": "https://www.atlassian.com. App's Terms of Use, https://www.atlassian.com ... Do you have a formal security incident response process documented and established?",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "product_metadata_page",
      "signals": {
        "page_type": "product_metadata",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "product_metadata_page"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/microsoft-365-app-certification/teams/atlassiancom-jira-cloud",
      "title": "Jira Cloud - Microsoft 365 App Certification",
      "summary": "General information ; ID, WA[REDACTED] ; Office 365 clients supported, Microsoft Teams ; Partner company name, Atlassian.com ; Company's website ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "product_metadata_page",
      "signals": {
        "page_type": "product_metadata",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "product_metadata_page"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/microsoft-365-app-certification/teams/atlassiancom-atlassian-chatops",
      "title": "Atlassian ChatOps - Microsoft 365 App Certification",
      "summary": "This information has been provided by Atlassian.com about how this app collects and stores organizational data and the control that your ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "product_metadata_page",
      "signals": {
        "page_type": "product_metadata",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "product_metadata_page"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/microsoft-365-app-certification/outlook/atlassiancom-jira-cloud-for-outlook-official",
      "title": "Application Information for Jira Cloud for Outlook (Official) by Atlassian.com",
      "summary": "https://www.atlassian.com. App's Terms of Use, https://www.atlassian ... Do you have a formal security incident response process documented and ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "product_metadata_page",
      "signals": {
        "page_type": "product_metadata",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "product_metadata_page"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/cve-2022-26134-atlassian-code-execution-vulnerability/",
      "title": "CVE-[REDACTED] Threat Brief: Atlassian Confluence RCE ...",
      "summary": "Based on the security advisory issued by Atlassian, it appears that the exploit is indeed an unauthenticated, remote code execution ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/cve-2021-26084/",
      "title": "Threat Brief: CVE-[REDACTED] - Palo Alto Networks Unit 42",
      "summary": "On Aug. 25, 2021, Atlassian released a security advisory for an injection vulnerability in Confluence Server and Data Center, CVE-[REDACTED] ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/",
      "title": "The Shadow Campaigns: Uncovering Global Espionage",
      "summary": "The Shadow Campaigns: Uncovering Global Espionage Executive Summary Here we describe the technical sophistication of the actors, including the phishing and exploitation techniques, tooling and infrastructure used by the group. Phishing In February 2025, Unit 42 investigated a cluster of malicious phishing campaigns targeting European governments. Example phishing email (translated). We assess that an Estonian government entity identified the campaign and uploaded one such ZIP archive to a public malware repository. In this case, the Estonian filename was: Politsei- ja Piirivalveameti organisatsiooni struktuuri muudatused.zip",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/ja/cve-2022-26134-atlassian-code-execution-vulnerability/",
      "title": "Atlassian Confluenceのリモートコード実行脆弱性(CVE-[REDACTED])",
      "summary": "パロアルトネットワークスの攻撃対象領域管理ソリューションCortex XpanseはこのCVEの影響を受ける可能性のある Confluence Serverを19,707インスタンス ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "security_context_missing",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": false,
        "reason": "security_context_missing"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/ja/cve-2021-26084/",
      "title": "脅威に関する情報: CVE-[REDACTED] Atlassian Confluence Serverおよび ...",
      "summary": "2021年8月25日、AtlassianはConfluence ServerおよびData Centerに存在するインジェクション脆弱性（CVE-[REDACTED]）に関するセキュリティアドバイザリを公開しました ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "security_context_missing",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": false,
        "reason": "security_context_missing"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2016/04/07/mumblehard-takedown-ends-army-of-linux-servers-from-spamming/",
      "title": "Mumblehard takedown ends army of Linux servers from spamming",
      "summary": "The malware authors apparently responded by removing the unnecessary domains and IP addresses from the list of C&C servers included in the ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/en/privacy/osint-playbook-find-weak-spots-attackers-do/",
      "title": "The OSINT playbook: Find your weak spots before attackers do",
      "summary": "Here's how open-source intelligence helps uncover your digital footprint and weak points, plus a few essential tools to connect the dots.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/pt/privacidade/a-inteligencia-artificial-e-os-limites-da-privacidade/",
      "title": "A inteligência artificial e os limites da privacidade - WeLiveSecurity",
      "summary": "Analisamos as políticas de privacidade de empresas que utilizam inteligência artificial, como a Microsoft (com o Windows Recall) e a Adobe, ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/pt/recursos-e-ferramentas/osint-do-zero-como-comecar/",
      "title": "OSINT do zero: como começar? - WeLiveSecurity",
      "summary": "Os benefícios para a segurança são claros: o OSINT automatiza a detecção de dados sensíveis, como credenciais vazadas, metadados em imagens e ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/la-es/2015/07/24/falsos-activadores-windows-consecuencias-sistema/",
      "title": "Falsos activadores de Windows y sus consecuencias en el sistema",
      "summary": "Análisis de un activador no licenciado de Windows que dice ser gratuito pero que no es tal, instalando aplicaciones no deseadas para el usuario.",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://learn.microsoft.com/en-us/answers/questions/4110965/behance-videos-not-loading-due-to-firewall-or-anti",
      "title": "Behance Videos Not Loading Due to Firewall or Antivirus Blockage",
      "summary": "I am encountering a persistent issue with Behance where some videos are not loading, and I receive the error message \"Firewall or antivirus ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "non_article_page",
      "signals": {
        "page_type": "non_article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "non_article_page"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://news.microsoft.com/en-in/features/design-pro-surface-pro/",
      "title": "A Design Pro and her Surface Pro - Microsoft Stories India",
      "summary": "While working, I also ensure that I get feedback from my peers, share my work on platforms such as Behance and Instagram, and build on my ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "security_context_missing",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": false,
        "reason": "security_context_missing"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://microsoftedge.microsoft.com/addons/detail/lnhjehahjbmmcgddjcmfdhbbgcijhdad?hl=en",
      "title": "Comment Bot for Behance - Microsoft Edge Add-ons",
      "summary": "Automates comments and appreciates on Behance to increase your engagement!",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "security_context_missing",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": false,
        "reason": "security_context_missing"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-security-exposure-management",
      "title": "Microsoft Security Exposure Management",
      "summary": "Discover Microsoft Security Exposure Management, a threat exposure solution that limits risk, enhances visibility, and strengthens attack surface ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": true,
        "reason": "target_not_subject"
      }
    },
    {
      "domain": "behance.com",
      "publisher": "Microsoft Security",
      "publisher_domain": "microsoft.com",
      "url": "https://www.microsoft.com/applied-sciences/people/antonio-gomes",
      "title": "Antonio Gomes | Applied Sciences | Microsoft",
      "summary": "Antonio Gomes is a 2014 research intern with the Applied Sciences Group (ASG). His interests include hardware development, actuated interfaces, ...",
      "published_at": null,
      "decision": "reject",
      "decision_reason": "target_not_subject",
      "signals": {
        "page_type": "article",
        "target": "none",
        "target_strength": "none",
        "security": false,
        "reason": "target_not_subject"
      }
    }
  ]
}
```
---
AFTER
```json
{
  "schema_version": "contextual-filter-dump-v2",
  "filter": "security_publication_context_v2",
  "generated_at": "2026-10-05T17:27:27.489409+00:00",
  "records": [
    {
      "domain": "asus.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/asus-com-compromised-link-to-ani-exploit/30317/",
      "title": "asus.com compromised: link to ANI exploit - Securelist",
      "summary": "We've just confirmed multiple reports about asus.com, a very well known hardware manufacturer, being compromised.",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Kaspersky Securelist",
      "publisher_domain": "securelist.com",
      "url": "https://securelist.com/operation-shadowhammer/89992/",
      "title": "Operation ShadowHammer | Securelist",
      "summary": "Earlier today, Motherboard published a story by Kim Zetter on Operation ShadowHammer, a newly discovered supply chain attack that leveraged ASUS Live Update software. In January 2019, we discovered a sophisticated supply chain attack involving the ASUS Live Update Utility . We have contacted ASUS and informed them about the attack on Jan 31, 2019, supporting their investigation with IOCs and descriptions of the malware. IOCs Kaspersky Lab verdicts for the malware used in this and related attacks: - asushotfix[.]com - Vulnerabilities and exploits - ASUS 3. Any idea if ASUS wireless routers were affected by this as well? I noticed in that same time frame that several of these that I manage required multiple reboots to resolve wireless connectivity issues (wireless signal dropping unexpectedly, unexplained slow internet speeds, etc) when previously these were behaving perfectly. Reply 2. Im wondering the same thing. Luckily ALL 5 of my ASUS motherboard PCs arent infected, as well as my ASUS laptop. But ironically I had bought a brand new ASUS router last year (RT-N66u) and it happened to be one of the very few routers that were one of the models to get their Firmware infected with malware (possibly even having the malware on the router when I bought it brand new from newegg.com ) Definitely not neweggs fault , but kinda scary knowing that other people and possibly mine as well were shipped brand new with the infected firmware that could be dormant for an indefinite amount of time and then enabled remotely one day to start relaying data to Russia etc. AKa using peoples bandwidth to turn their network into a botnet to give them access to a very large amount of routers to use at their disposal for DDoS attacks etc. Reply 1. This was an exploit to the Asus Live Update software for their Laptops. If this program was uninstalled or not updated after the hack occurred you wouldn’t be affected. Reply 9. Is it possible that the certificate was left on a server, and then used to",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2019/05/14/plead-malware-mitm-asus-webstorage/",
      "title": "Plead malware distributed via MitM attacks at router level, misusing ...",
      "summary": "Plead malware distributed via MitM attacks at router level, misusing ASUS WebStorage ESET researchers have discovered that the attackers have been distributing the Plead malware via compromised routers and man-in-the-middle attacks against the legitimate ASUS WebStorage software Anton Cherepanov Anton Cherepanov 14 May 2019 • , 6 min. read Plead malware distributed via MitM attacks at router level, misusing ASUS WebStorage In July 2018 we discovered that the Plead backdoor was digitally signed by a code-signing certificate that was issued to D-Link Corporation. Recently we detected a new activity involving the same malware and a connection to legitimate software developed by ASUS Cloud Corporation. The Plead malware is a backdoor which, according to Trend Micro, is used by the BlackTech group in targeted attacks. What has happened? At the end of April 2019, ESET researchers utilizing ESET telemetry observed multiple attempts to deploy Plead malware in an unusual way. Specifically, the Plead backdoor was created and executed by a legitimate process named AsusWSPanel.exe. As seen in Figure 1, the executable file is digitally signed by ASUS Cloud Corporation. Figure 1. The AsusWSPanel.exe code-signing certificate Figure 2. Plead backdoor - %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\slui.exe - %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ctfmon.exe - %TEMP%\\DEV[4 random chars].TMP Conclusion ESET researchers notified ASUS Cloud Corporation prior to this publication. Indicators of Compromise (IoCs) | ESET detection names | |-| | Win32/Plead.AP trojan | | Win32/Plead.AC trojan | | C&C servers | |-| | update.asuswebstorage.com.ssmailer[.]com | | [www.google.com.dns-report\\[.\\]com](http://www.google.com.dns-report\\[.\\]com) | MITRE ATT&CK techniques | Tactic | ID | Name | Description | |-|-|-|-| | Execution | T1203 | Exploitation for Client Execution | BlackTech group exploits a vulnerable update mechanism in ASUS WebStorage software in order to deplo",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2019/05/17/week-security-tony-anscombe-23/",
      "title": "Week in security with Tony Anscombe - WeLiveSecurity",
      "summary": "ESET researchers detail how ASUS's cloud service has been abused to distribute the Plead malware; in other news, ESET's telemetry shows that the use of the ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "asus.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/iot-supply-chain/",
      "title": "Risks in IoT Supply Chain - Palo Alto Networks Unit 42",
      "summary": "Risks in IoT Supply Chain Examples of IoT Supply Chain Attacks Firmware – OpenWrt Devices In March 2020, a vulnerability found in OpenWrt allowed attackers to impersonate downloads from downloads.openwrt.org and make the devices download malicious updates. Types of Motivation for Attacks on the IoT Supply Chain Cyberespionage Perspective In 2018, Operation ShadowHammer revealed that legitimate ASUS security certificates (such as “ASUSTeK Computer Inc.”) were abused by attackers and signed trojanized softwares, which misled targeted victims to install backdoors in their system and download additional malicious payloads onto their machines. Conclusion Identified devices vulnerable to CVE-2019-[REDACTED]. Identified devices vulnerable to CVE-[REDACTED].",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "ESET Research",
      "publisher_domain": "welivesecurity.com",
      "url": "https://www.welivesecurity.com/2015/02/03/hipchat-hack-password/",
      "title": "HipChat hack leads to precautionary password reset - WeLiveSecurity",
      "summary": "Australian enterprise software firm Atlassian has told customers that it recently suffered a security breach that saw hackers access names, usernames, email ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/cve-2022-26134-atlassian-code-execution-vulnerability/",
      "title": "CVE-[REDACTED] Threat Brief: Atlassian Confluence RCE ...",
      "summary": "Based on the security advisory issued by Atlassian, it appears that the exploit is indeed an unauthenticated, remote code execution ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "title_alias",
        "target_strength": "strong",
        "security": true,
        "reason": "target_subject_security_context"
      }
    },
    {
      "domain": "atlassian.com",
      "publisher": "Palo Alto Networks Unit 42",
      "publisher_domain": "unit42.paloaltonetworks.com",
      "url": "https://unit42.paloaltonetworks.com/cve-2021-26084/",
      "title": "Threat Brief: CVE-[REDACTED] - Palo Alto Networks Unit 42",
      "summary": "On Aug. 25, 2021, Atlassian released a security advisory for an injection vulnerability in Confluence Server and Data Center, CVE-[REDACTED] ...",
      "published_at": null,
      "decision": "accept",
      "decision_reason": "target_subject_security_context",
      "signals": {
        "page_type": "article",
        "target": "summary_alias",
        "target_strength": "weak",
        "security": true,
        "reason": "target_subject_security_context"
      }
    }
  ]
}
```
