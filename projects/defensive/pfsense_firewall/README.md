# pfSense Firewall — Installation &# pfSense CE 2.7.2 – VMware Workstation Lab

## 1 · Lab “Hardware”
| Component | Details |
|-----------|---------|
| **Hypervisor** | VMware Workstation 17.x (Windows 10 host) |
| **Guest OS** | pfSense CE 2.7.2-RELEASE (`pfSense-CE-2.7.2-RELEASE-amd64.iso`) |
| **vCPUs / RAM** | 2 vCPU • 2 GiB RAM |
| **Disk** | 20 GB thin-provisioned, single `.vmdk` |
| **NIC 1 (WAN)** | Bridged → `vmnet0` (maps to home router) |
| **NIC 2 (LAN)** | Host-Only → `vmnet2` (10.10.10.0/24) |
| **(optional) NIC 3 (MGMT)** | Host-Only → `vmnet3` (10.10.20.0/24) |
| **NIC type** | **VMXNET 3** ( *VM ▸ Settings ▸ Advanced…* ) |

---

## 2 · Installation Media
* **Download ISO:** <https://www.pfsense.org/download/> → **DVD Installer ▸ AMD64**  
* No USB needed — attach the ISO to the VM’s **CD/DVD drive** and tick **Connected at power-on**.

---

## 3 · pfSense Text Installer (inside the VM)
| Prompt | Choice |
|--------|--------|
| Keymap | Default / US |
| Install mode | Guided – **UFS (GPT/UEFI Hybrid)** |
| Target disk | `da0` 20 GB *VMware Virtual S* |
| RAM warning | **Proceed anyway** (2 GiB OK) |
| Root password | `your-lab-password` |
| Post-install reboot | ✔️ (Eject ISO first) |

---

## 4 · Console Interface Assignment
| Role | NIC name | VMware switch | IP after wizard |
|------|----------|---------------|-----------------|
| **WAN** | `em0` (or `vmx0`) | `vmnet0` – Bridged | via DHCP (home router) |
| **LAN** | `em1` (or `vmx1`) | `vmnet2` – Host-Only | 10.10.10.1/24 |
| **OPT1** | *skip for now* | (`vmnet3`) | — |

**Set LAN IP & DHCP scope (console menu 2):**
```text
IPv4 address : 10.10.10.1 /24
DHCP range   : 10.10.10.100 – 10.10.10.200
 Baseline Configuration

> Part of the **Defensive Security** track of my homelab.

## 1. Lab Hardware

| Component | Details |
|-----------|---------|
| Appliance | VMware Virtual Machine |
| CPU / RAM | AMD Ryzen 5 3600 6-Core Processor 2 x CPUs |
| NICs      | 4 × Intel i210 |
| pfSense   | **ce-2.7.2-RELEASE** (installed `2025-07-15`) |

## 2. Preparing Installation Media

1. Download image: <https://www.pfsense.org/download/>  (choose *USB Memstick Installer > AMD64*). :contentReference[oaicite:0]{index=0}  
2. Verify SHA-256 checksum from Netgate docs. :contentReference[oaicite:1]{index=1}  
3. Flash to USB with **balenaEtcher** (`sudo balena-etcher-electron`). :contentReference[oaicite:2]{index=2}  

## 3. BIOS tweaks

* Disable Secure Boot.  
* Set USB as first boot device.  
* Enable all NICs (some OEM BIOSes ship NICs disabled).

## 4. pfSense Text Installer Steps

| Step | Selection |
|------|-----------|
| Console Keymap | Default/US |
| Partition Scheme | Guided — ZFS (RAID-Z1 on 16 GB SSD) |
| Password | **REDACTED** |
| Reboot | Remove USB, login as `admin/pfsense` |

## 5. Initial WebGUI Configuration

```text
https://10.10.10.1/
  • Change default password
  • Set hostname: pfsense.lab.local
  • Configure WAN (PPPoE) and LAN (192.168.10.1/24)
  • Enable SSH + key-based auth
