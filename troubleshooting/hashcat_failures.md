#  Troubleshooting: Hashcat and John Cracking Errors

This document captures the issues encountered while attempting to use **Hashcat** and **John the Ripper** for offline password cracking in a virtualized lab environment (Kali Linux and DVWA).

---

##  Issue 1: Hashcat Memory Error

###  Command Used:
```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
---

##  Issue 2: No OpenCL Platform Found

###  Error: ATTENTION! No OpenCL, HIP or CUDA compatible platform found.


###  Root Cause:
- Your VM does not have GPU passthrough enabled or supported.
- Kali was missing the required OpenCL runtime to allow Hashcat to function on CPU.

###  Solution:
Install OpenCL CPU runtime and re-test:
```bash
sudo apt install -y ocl-icd-libopencl1 clinfo
clinfo | grep -i device

If no device is listed, use John the Ripper as a fallback cracking tool:

john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt md5.txt

---

##  Issue 3: John Misinterpreting Hash Format

###  Symptom:
```bash
john --show hash.txt
0 password hashes cracked, 2 left

The hash was saved in username:hash format (admin:hash), which John tried to interpret using the wrong format (e.g., LM hash).

--show couldn’t recognize the cracked password due to mismatched formatting.

###  Solution:

1. Recreate the hash file using **only** the raw MD5 hash, without usernames or formatting:
```bash
   echo "5f4dcc3b5aa765d61d8327deb882cf99" > md5.txt
2. Run John the Ripper with an explicitly defined format to avoid misclassification
```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt md5.txt
3. After cracking completes, verify the result:
```bash
john --show md5.txt

You should see output like: 
```makefile
5f4dcc3b5aa765d61d8327deb882cf99:password

---

## 📌 Final Notes

These troubleshooting steps highlight key red team insights:

-  **Correct hash formatting is critical** — many cracking tools will silently fail or misclassify data if the format is not exact.

-  **Tool flexibility matters** — knowing how to switch between Hashcat and John lets you continue progressing even in restrictive environments like virtual machines.

-  **Environmental constraints (VM, no GPU)** are real limitations in home labs, and learning to work within them is an essential penetration testing skill.

-  **Documenting failures is just as important as successes** — it shows practical understanding and resilience.

Each of these issues contributed to a deeper understanding of password cracking techniques and tool-specific behavior, making this homelab experience more realistic and resume-worthy.

---

