# WiFi Pineapple Clone (GL.iNet MT300N v2)

This directory documents my DIY WiFi Pineapple project, based on a GL.iNet Mango router and custom firmware. Inspired by the following resources:  
- [DIY WiFi Pineapple | Hak5 Clone](https://www.youtube.com/watch?v=udnxagkSzoA)  
- [wifi-pineapple-cloner GitHub Repository](https://github.com/xchwarze/wifi-pineapple-cloner)

## 📌 Overview

The WiFi Pineapple is a device used for wireless network auditing and penetration testing.  
I built this device using the GL.iNet MT300N v2 (Mango) router flashed with a Pineapple clone image based on OpenWRT.

**Features:**
- Rogue access point creation
- Packet sniffing and logging
- Credential harvesting
- Modular payloads via web interface

> ⚠️ **For educational purposes only.** Use responsibly on networks you own or have explicit permission to test.

## 🛠️ Hardware

- GL.iNet MT300N v2 (Mango)
- USB power source or battery pack
- Ethernet cable for initial configuration

## 🧰 Software & Firmware

- **OpenWRT Version:** v21.02.0-rc2  
  [Download Firmware](https://firmware-selector.openwrt.org/)
- **Pineapple Clone Image:**  
  [wifi-pineapple-cloner GitHub](https://github.com/xchwarze/wifi-pineapple-cloner)

## 🗒️ Setup Instructions (Summary)

1. Download the custom Pineapple firmware image:
    (https://github.com/xchwarze/wifi-pineapple-cloner.git)

2. Flash OpenWRT v21.02.0-rc2 to the GL.iNet MT300N v2 using the GL.iNet web UI.

3. Upload the Pineapple clone firmware via OpenWRT's sysupgrade.

4. Connect to the Mango router over Ethernet.

5. Access the web interface (default IP: 192.168.1.1) and configure:

	- SSID for rogue AP

	- DHCP/DNS settings

	- Payload modules

6. Launch wireless attacks as needed.

  Refer to the Pineapple Cloner repository for detailed instructions.


### References

- https://www.youtube.com/watch?v=udnxagkSzoA

- https://github.com/xchwarze/wifi-pineapple-cloner

- https://firmware-selector.openwrt.org/

- https://www.gl-inet.com/products/gl-mt300n-v2/

### 🛡️ Disclaimer

This project is for educational and authorized security testing only.
