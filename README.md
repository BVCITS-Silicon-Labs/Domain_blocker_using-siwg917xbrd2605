# SiWG917 Embedded IP & Domain Blocker (BRD2605A)

An embedded hardware-level domain filtering firewall and DNS sinkhole running on the Silicon Labs SiWG917 SoC Radio Board (BRD2605A).

The firmware intercepts inbound DNS queries on UDP port 53, evaluates requested hostnames against an in-memory blocklist using thread-safe CMSIS-RTOS2 primitives, and responds with an RFC 1035 NXDOMAIN (RCODE 3) packet for blocked hosts. Allowed queries are proxied to upstream recursive resolvers (1.1.1.1 and 8.8.8.8) with socket timeouts. The device simultaneously runs an embedded HTTP server on TCP port 80 that provides a web-based dashboard and REST-like endpoints to add, remove, and list blocked domains in real time.

---

## Table of Contents
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Hardware & Software Prerequisites](#-hardware--software-prerequisites)
- [Repository Structure](#-repository-structure)
- [Source Code Deep-Dive](#-source-code-deep-dive)
  - [Memory Allocation & Thread Budgets](#memory-allocation--thread-budgets)
  - [Domain Normalization & Boundary Matching](#domain-normalization--boundary-matching)
  - [DNS Packet Parsing & RFC 1035 NXDOMAIN Construction](#dns-packet-parsing--rfc-1035-nxdomain-construction)
  - [Upstream Forwarding & Failover State Machine](#upstream-forwarding--failover-state-machine)
  - [Embedded Web Server & REST API](#embedded-web-server--rest-api)
- [Setup & Build Instructions](#-setup--build-instructions)
- [UART Console Logs](#-uart-console-logs)
- [Client-Side Verification](#-client-side-verification)
- [License](#-license)

---

## 📌 Key Features
- **Dual-Thread FreeRTOS Architecture**: Separates high-frequency UDP packet processing from client HTTP requests into two dedicated tasks (DNS stack: 6144 B; HTTP stack: 8192 B).
- **RFC 1035 Standards-Compliant DNS Sinkhole**: Intercepts queries on UDP port 53, extracts domain labels, matches them with dot-boundary checks, and crafts authoritative NXDOMAIN responses (Header Flags: 0x8403).
- **Dual Upstream Recursive Forwarding**: Forwards permitted domain queries to Cloudflare (1.1.1.1) and fails over to Google (8.8.8.8), with socket receive timeouts (`SL_SI91X_SO_RCVTIME` / `SO_RCVTIMEO`) and fallback to SERVFAIL (RCODE 2).
- **Zero-Dependency Web Portal**: Embedded HTTP/1.0 micro-server provides an in-browser management UI and JSON endpoints (`/api/add`, `/api/remove`, `/api/domains`).
- **Thread-Safe Shared State**: Protects concurrent access to the blocklist across the HTTP and DNS threads via CMSIS-RTOS2 mutex primitives (`osMutexAcquire`/`osMutexRelease`).
- **Low-Level Memory Monitoring**: High-water mark checks via `uxTaskGetStackHighWaterMark()` and heap monitoring via `xPortGetFreeHeapSize()` maintain stack margins on FreeRTOS Heap 4.

---

## ⚙️ System Architecture

```text
                               +-------------------------------------------------------------+
                               |                 Silicon Labs SiWG917 (BRD2605A)             |
                               |                                                             |
   +-----------------------+   |   +-----------------------------------------------------+   |
   |   Client Machine      |   |   |                   FreeRTOS Kernel                   |   |
   |   (PC / Smartphone)   |   |   +-----------------------------------------------------+   |
   +-----------------------+   |                              |                              |
      |                 |      |          +-------------------+-------------------+          |
      | UDP/53 (DNS)    |      |          |                                       |          |
      |                 |      |          v                                       v          |
      |                 |      |   +--------------------------+       +----------------------+   |
      |                 +--------->|  DNS Server Task (UDP:53)|       | HTTP Server (TCP:80) |   |
      |                        |   |  - Label parser (QNAME)  |       | - Dashboard (/)      |   |
      |                        |   |  - Check blocklist mutex |       | - /api/add           |   |
      |                        |   +--------------------------+       | - /api/remove        |   |
      |                        |          |           |               | - /api/domains       |   |
      |                        |   Match  |           | No Match      +----------------------+   |
      |                        |          v           v                          ^           |
      |<--- NXDOMAIN (0x8403) -+----------+       +-------------------+          |           |
      |                                           | Forward to 1.1.1.1|          |           |
      |                                           | Failover: 8.8.8.8 |          |           |
      |                                           +-------------------+          |           |
      |                                                     |                    |           |
      | HTTP/80 (Browser Management)                        | Upstream Reply     |           |
      +-----------------------------------------------------+--------------------+-----------+|

---

##🛠️ Hardware & Software Prerequisites
'''Hardware
Radio Board: Silicon Labs SiWx917 Wi-Fi SoC Radio Board (BRD2605A / SiWG917M111MGTBA).

Mainboard / Carrier: Direct USB-C connection to onboard Segger J-Link debugger and Virtual COM port.

Host Network: 2.4 GHz 802.11 b/g/n Wi-Fi Access Point with DHCP enabled.

'''Software & SDK
IDE: Simplicity Studio v5 or VS Code with Silicon Labs Simplicity extension.

SDK Suite: Simplicity SDK 2025.12.3 with WiSeConnect 3 SDK extension 4.0.2.

Toolchain: GNU Arm Embedded Toolchain (arm-none-eabi-gcc) with -u _printf_float -Wall -Werror.

Serial Terminal: 115200 Baud, 8 Data Bits, 1 Stop Bit, No Parity (8-N-1).
