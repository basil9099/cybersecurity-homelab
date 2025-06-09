#  John the Ripper - Offline Password Crack (DVWA)

##  Objective

To extract and crack an MD5 hashed password for the default DVWA `admin` user by leveraging offline password cracking techniques using **John the Ripper**.

---

##  Target Overview

- **Platform**: Metasploitable 2
- **Web App**: DVWA (Damn Vulnerable Web Application)
- **Service**: HTTP (DVWA exposed via port 80)
- **User Account Targeted**: `admin`
- **Hash Algorithm**: MD5

---

##  Tools Used

| Tool | Purpose |
|------|---------|
| `sqlmap` or `mysqldump` | Extract password hash from DVWA database |
| `John the Ripper` | Crack the MD5 hash |
| `rockyou.txt` | Common password wordlist |
| `nano`, `grep`, `cut`, `cat` | Linux CLI tools for file parsing |

---

##  Exploit Process

### 1️⃣ Dumping the DVWA `admin` hash

We accessed the DVWA backend and dumped the user password hash from the MySQL database.

```sql
SELECT user, password FROM users;

---

##  Result

admin | 5f4dcc3b5aa765d61d8327deb882cf99


 Screenshot: `metasploit_mysql_dump.png`

---

## 2️⃣ Preparing the Hash File

Extracted only the hash:

```bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" > md5.txt

 Stored as md5.txt in the same directory as our wordlist and John.

---

## 3️⃣ Cracking with John the Ripper

Forced format to avoid misdetection:

```bash

john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt md5.txt
Output:5f4dcc3b5aa765d61d8327deb882cf99:password
 Screenshot: john_crack_output.png

---

## 4️⃣ Verifying the Password via Web Login

Used credentials:

```pgsql

Username: admin
Password: password
Login successful on DVWA main login panel.

 Screenshot: john_dvwa_login.png

---

##  Outcome

Hash successfully cracked.

Credentials verified by logging into DVWA admin panel.

Demonstrated ability to extract, prepare, and crack hashes using CLI and custom tooling.

## Lessons Learned

john --show won’t recognize hash if improperly formatted (e.g., admin:hash)

Forcing the format using --format=raw-md5 was critical

VM environments often lack GPU support for Hashcat — fallback tools like John are essential

Always sanitize and simplify input files before passing to cracking tools

## Screenshots

Filename	                Description

	
metasploit_mysql_dump.png       Shows extracted hash from DVWA
john_crack_output.png	        John the Ripper terminal output showing cracked password
john_dvwa_login.png	        Successful login to DVWA using cracked credentials

---

### Once written, save the file:

```bash
nano exploits/john_dvwa_crack.md

