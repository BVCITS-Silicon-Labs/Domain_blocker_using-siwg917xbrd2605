# Domain Blocker using Silicon Labs SiWx917 (SiWG917X-BRD2605)

[![Hardware](https://img.shields.io/badge/Hardware-SiWG917X--BRD2605-005596.svg)](https://www.silabs.com/)
[![SDK](https://img.shields.io/badge/Gecko%20SDK%20%2F%20WiseConnect-v3.x-green.svg)](https://github.com/SiliconLabs)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An embedded, hardware-level domain filtering and network blocking application implemented on the **Silicon Labs SiWx917 Wi-Fi & Bluetooth Wireless Co-Processor / SoC Radio Board (BRD2605A)**.

This project monitors network traffic and prevents connected devices or local applications from resolving and establishing connections to specified blacklisted domains.

---

# SiWG917 Embedded IP & Domain Blocker (BRD2605A)

An embedded network-level domain filtering firewall and DNS sinkhole built for the **Silicon Labs SiWG917** Wi-Fi SoC running on the **BRD2605A** radio board.

---

## 🚀 Key Features

- **Concurrent Dual-Service Architecture (FreeRTOS):**
  - **DNS Server (`UDP/53`):** Intercepts client DNS lookups, inspects query names (QNAME), blocks configured domains with `NXDOMAIN` (RFC 1035), and forwards legitimate traffic to upstream recursive resolvers (`1.1.1.1` and `8.8.8.8`).
  - **Embedded Web Management Portal (`TCP/80`):** Responsive dashboard providing real-time blocked domain viewing, dynamic rule addition (`/api/add`), and rule removal (`/api/remove`).
- **Resilient Upstream Forwarding:** Employs socket-level timeout enforcement (`SL_SI91X_SO_RCVTIME` / `SO_RCVTIMEO`) and automatic fallback to secondary resolvers or `SERVFAIL` (RCODE 2).
- **Concurrency & Memory Safety:** Uses CMSIS-RTOS2 mutexes (`domain_mutex`) to synchronize blocklist access across the HTTP and DNS threads, maintaining safe high-water mark margins on FreeRTOS Heap 4.

---

## 🛠️ Hardware & SDK Requirements

- **Development Hardware:** Silicon Labs BRD2605A (SiWG917M111MGTBA)
- **Simplicity SDK:** `2025.12.3`
- **WiSeConnect 3 SDK:** `4.0.2`
- **RTOS:** FreeRTOS (Heap 4) with CMSIS-RTOS2 abstraction layer

---

## 📂 Project Structure

## 📌 Overview

Traditional network filters rely on heavy desktop software or dedicated router appliances. This project demonstrates an ultra-low-power, MCU-based domain filtering firewall leveraging the dual-core architecture and high-performance Wi-Fi stack of the SiWx917.

### Key Features
- **Network-Level Interception**: Inspects outgoing network transactions (DNS / Hostname requests) at the device layer.
- **Configurable Blacklist**: Blocks user-defined domains (e.g., ad networks, tracking endpoints, restricted domains).
- **Ultra-Low Power Operations**: Optimized for battery-operated or standalone low-power network accessories.
- **Serial Debugging Output**: Real-time inspection logs via USART/UART VCOM interface.

---

## 🛠️ Hardware & Software Requirements

### Hardware
* **Board**: Silicon Labs **SiWG917X-BRD2605A** (SiWx917 Wi-Fi + Bluetooth Radio Board)
* **Mainboard**: Wireless Starter Kit Mainboard (BRD4001A / BRD4002A) or direct USB-C On-Board J-Link Connection
* **Micro-USB / USB-C Cable**

### Software
* **IDE**: [Simplicity Studio v5](https://www.silabs.com/developers/simplicity-studio)
* **SDK**: Silicon Labs WiseConnect 3 SDK / Gecko SDK (GSDK)
* **Toolchain**: GNU ARM Embedded Toolchain (`arm-none-eabi-gcc`)
* **Serial Terminal**: PuTTY, Tera Term, or Serial Monitor (115200 Baud Rate)


## 📂 Project Structure

├── app.c                     # Core application logic (HTTP server & DNS sinkhole threads)
├── app.h                     # Public API prototypes and shared declarations
├── main.c                    # Firmware bootstrap and task scheduler dispatch
├── siwg917_ip_blocker.slcp   # Simplicity Studio project configuration
├── siwg917_ip_blocker.slpb   # Post-build pipeline descriptor (.rps, .hex, .bin)
└── siwg917_ip_blocker.slps   # Toolchain and board descriptor

---

## ⚙️ How It Works

1. **Station Connection:** Connects as a Wi-Fi client interface and acquires an IP via DHCP.
2. **DNS Sinkholing:** 
   - Receives standard UDP queries on port 53.
   - Extracts and normalizes QNAME labels.
   - If the query matches the blocklist, immediately crafts and transmits an RFC 1035 `NXDOMAIN` response (`0x8403`).
   - If allowed, forwards the query to Cloudflare (`1.1.1.1`) or Google (`8.8.8.8`) over UDP source port `40053`.
3. **Web Interface:** Direct a browser to `http://<Device_IP>` to add or remove domains on the fly.

---

## 🧪 Client Validation (Windows PowerShell)

Set your DNS server to the SiWG917 board's IP address:
```powershell
Resolve-DnsName -Name youtube.com -Server 192.168.137.45 -DnsOnly
Resolve-DnsName -Name x.com -Server 192.168.137.45 -DnsOnly

