# Domain Blocker using Silicon Labs SiWx917 (SiWG917X-BRD2605)

[![Hardware](https://img.shields.io/badge/Hardware-SiWG917X--BRD2605-005596.svg)](https://www.silabs.com/)
[![SDK](https://img.shields.io/badge/Gecko%20SDK%20%2F%20WiseConnect-v3.x-green.svg)](https://github.com/SiliconLabs)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An embedded, hardware-level domain filtering and network blocking application implemented on the **Silicon Labs SiWx917 Wi-Fi & Bluetooth Wireless Co-Processor / SoC Radio Board (BRD2605A)**.

This project monitors network traffic and prevents connected devices or local applications from resolving and establishing connections to specified blacklisted domains.

---

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


