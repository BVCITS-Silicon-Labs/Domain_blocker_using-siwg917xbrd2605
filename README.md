# SiWG917 Embedded IP & Domain Blocker (BRD2605A)

An embedded hardware-level domain filtering firewall and DNS sinkhole running on the **Silicon Labs SiWG917 SoC Radio Board (BRD2605A)**.

The firmware intercepts inbound DNS queries on **UDP port 53**, evaluates requested hostnames against an in-memory blocklist using thread-safe **CMSIS-RTOS2** primitives, and responds with an **RFC 1035 NXDOMAIN (RCODE 3)** packet for blocked hosts. Allowed queries are proxied to upstream recursive resolvers (**1.1.1.1** and **8.8.8.8**) with socket timeouts.

The device simultaneously runs an embedded **HTTP server on TCP port 80** that provides a web-based dashboard and REST-like endpoints to add, remove, and list blocked domains in real time.

---

## Table of Contents

- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Hardware & Software Prerequisites](#hardware--software-prerequisites)
- [Repository Structure](#repository-structure)
- [Source Code Deep-Dive](#source-code-deep-dive)
  - [Memory Allocation & Thread Budgets](#memory-allocation--thread-budgets)
  - [Domain Normalization & Boundary Matching](#domain-normalization--boundary-matching)
  - [DNS Packet Parsing & RFC 1035 NXDOMAIN Construction](#dns-packet-parsing--rfc-1035-nxdomain-construction)
  - [Upstream Forwarding & Failover State Machine](#upstream-forwarding--failover-state-machine)
  - [Embedded Web Server & REST API](#embedded-web-server--rest-api)
- [Setup & Build Instructions](#setup--build-instructions)
- [UART Console Logs](#uart-console-logs)
- [Client-Side Verification](#client-side-verification)
- [License](#license)

---

## Key Features

- **Dual-Thread FreeRTOS Architecture**
  - Separates high-frequency UDP packet processing from client HTTP requests into two dedicated tasks.
  - DNS stack: **6144 B**
  - HTTP stack: **8192 B**

- **RFC 1035 Standards-Compliant DNS Sinkhole**
  - Intercepts queries on UDP port 53.
  - Extracts DNS labels from the QNAME field.
  - Matches domains using dot-boundary checks.
  - Crafts authoritative NXDOMAIN responses.
  - DNS response header flags: **0x8403**
    - `QR = 1` — Response
    - `AA = 1` — Authoritative Answer
    - `RCODE = 3` — NXDOMAIN

- **Dual Upstream Recursive Forwarding**
  - Forwards permitted domain queries to **Cloudflare: 1.1.1.1**.
  - Fails over to **Google: 8.8.8.8**.
  - Uses socket receive timeouts:
    - `SL_SI91X_SO_RCVTIME`
    - BSD `SO_RCVTIMEO`
  - Returns **SERVFAIL (RCODE 2)** if both upstream servers fail.

- **Zero-Dependency Web Portal**
  - Embedded HTTP/1.0 micro-server.
  - Browser-based management dashboard.
  - JSON/REST-like endpoints:
    - `/api/add`
    - `/api/remove`
    - `/api/domains`

- **Thread-Safe Shared State**
  - Protects concurrent access to the blocklist across HTTP and DNS threads.
  - Uses CMSIS-RTOS2 mutex primitives:
    - `osMutexAcquire()`
    - `osMutexRelease()`

- **Low-Level Memory Monitoring**
  - Stack high-water mark monitoring using:
    - `uxTaskGetStackHighWaterMark()`
  - Free heap monitoring using:
    - `xPortGetFreeHeapSize()`
  - Uses FreeRTOS Heap 4.

---

## System Architecture

```text
                              +-------------------------------------------------------------+
                              |                 Silicon Labs SiWG917 (BRD2605A)             |
                              |                                                             |
+-----------------------+     |   +-----------------------------------------------------+   |
|   Client Machine      |     |   |                   FreeRTOS Kernel                   |   |
|   (PC / Smartphone)   |     |   +-----------------------------------------------------+   |
+-----------------------+     |                              |                              |
       |                 |    |          +-------------------+-------------------+          |
       | UDP/53 (DNS)    |    |          |                                       |          |
       |                 |    |          v                                       v          |
       |                 +--------->|  DNS Server Task (UDP:53)|       | HTTP Server (TCP:80) |   |
       |                      |     |  - Label parser (QNAME)  |       | - Dashboard (/)      |   |
       |                      |     |  - Check blocklist mutex |       | - /api/add           |   |
       |                      |     +--------------------------+       | - /api/remove        |   |
       |                      |          |           |                  | - /api/domains       |   |
       |                      |   Match  |           | No Match          +----------------------+   |
       |                      |          v           v                          ^           |
       |<--- NXDOMAIN (0x8403)-+----------+       +-------------------+          |           |
       |                                           | Forward to 1.1.1.1|          |           |
       |                                           | Failover: 8.8.8.8 |          |           |
       |                                           +-------------------+          |           |
       |                                                     |                    |           |
       | HTTP/80 (Browser Management)                        | Upstream Reply     |           |
       +-----------------------------------------------------+--------------------+-----------+
```

### Data Flow

1. A client sends a DNS query to the SiWG917 board on **UDP port 53**.
2. The DNS server task receives the query.
3. The QNAME is parsed into a normalized domain name.
4. The domain is checked against the shared in-memory blocklist.
5. If the domain is blocked:
   - The board returns an **NXDOMAIN** response.
   - The client receives DNS `RCODE = 3`.
6. If the domain is not blocked:
   - The query is forwarded to **1.1.1.1:53**.
   - If the primary resolver times out, the query is retried through **8.8.8.8:53**.
   - If both resolvers fail, the board returns **SERVFAIL**.
7. A browser can connect to the board on **TCP port 80** to:
   - View the dashboard.
   - Add blocked domains.
   - Remove blocked domains.
   - List the current blocklist.

---

## Hardware & Software Prerequisites

### Hardware

| Component | Requirement |
|---|---|
| Radio Board | Silicon Labs SiWx917 Wi-Fi SoC Radio Board — **BRD2605A / SiWG917M111MGTBA** |
| Mainboard / Carrier | Direct USB-C connection to onboard **Segger J-Link debugger** and **Virtual COM port** |
| Host Network | **2.4 GHz 802.11 b/g/n Wi-Fi Access Point** with DHCP enabled |

### Software & SDK

| Component | Requirement |
|---|---|
| IDE | **Simplicity Studio v5** or **VS Code with Silicon Labs Simplicity extension** |
| SDK Suite | **Simplicity SDK 2025.12.3** with **WiSeConnect 3 SDK extension 4.0.2** |
| Toolchain | **GNU Arm Embedded Toolchain (`arm-none-eabi-gcc`)** |
| Compiler Options | `-u _printf_float -Wall -Werror` |
| Serial Terminal | **115200 Baud, 8 Data Bits, 1 Stop Bit, No Parity (8-N-1)** |

---

## Repository Structure

```text
├── app.c                     # Primary application: DNS sinkhole, HTTP server, domain normalization
├── app.h                     # Public interfaces, function prototypes, and constants
├── main.c                    # Hardware initialization and RTOS kernel launch
├── siwg917_ip_blocker.slcp   # Simplicity Studio Project Configuration
├── siwg917_ip_blocker.slpb   # Post-build pipeline descriptor (.rps, .hex, .bin)
├── siwg917_ip_blocker.slps   # Toolchain and target hardware descriptor
├── README.md                 # Technical project documentation
└── LICENSE                   # Project License
```

---

# Source Code Deep-Dive

## Memory Allocation & Thread Budgets

The following memory parameters and execution attributes are defined in `app.c`:

```c
#define MAX_BLOCKED_DOMAINS         20
#define MAX_DOMAIN_LENGTH           64
#define HTTP_PORT                   80
#define DNS_PORT                    53
#define DNS_PACKET_SIZE             1232
#define DNS_UPSTREAM_TIMEOUT_SEC    1
#define DNS_TRANSACTION_COOLDOWN_MS 2000U
#define HTTP_REQUEST_SIZE           2048
#define HTTP_PAGE_SIZE              8192
#define HTTP_HEADER_SIZE            512
#define HTTP_STACK_SIZE             8192
#define DNS_STACK_SIZE              6144
```

### Memory and Resource Summary

| Parameter | Value | Purpose |
|---|---:|---|
| `MAX_BLOCKED_DOMAINS` | 20 | Maximum number of blocked domains |
| `MAX_DOMAIN_LENGTH` | 64 | Maximum stored domain length |
| `HTTP_PORT` | 80 | Embedded HTTP server port |
| `DNS_PORT` | 53 | Embedded DNS server port |
| `DNS_PACKET_SIZE` | 1232 bytes | DNS packet buffer size |
| `DNS_UPSTREAM_TIMEOUT_SEC` | 1 second | Upstream DNS receive timeout |
| `DNS_TRANSACTION_COOLDOWN_MS` | 2000 ms | Cooldown between DNS transactions |
| `HTTP_REQUEST_SIZE` | 2048 bytes | HTTP request buffer |
| `HTTP_PAGE_SIZE` | 8192 bytes | HTTP page buffer |
| `HTTP_HEADER_SIZE` | 512 bytes | HTTP response header buffer |
| `HTTP_STACK_SIZE` | 8192 bytes | HTTP task stack |
| `DNS_STACK_SIZE` | 6144 bytes | DNS task stack |

---

## Domain Normalization & Boundary Matching

The domain matching function is designed to avoid false-positive substring matches.

```c
static int dns_domain_matches(const char *query, const char *blocked)
{
    size_t query_length, blocked_length;

    if (query == NULL || blocked == NULL)
        return 0;

    if (string_equals_ignore_case(query, blocked))
        return 1;

    query_length = strlen(query);
    blocked_length = strlen(blocked);

    if (query_length > blocked_length) {
        if (string_equals_ignore_case(
                query + query_length - blocked_length,
                blocked)) {

            if (query[query_length - blocked_length - 1] == '.') {
                return 1;
            }
        }
    }

    return 0;
}
```

### Matching Behavior

For example, blocking:

```text
youtube.com
```

blocks:

```text
youtube.com
m.youtube.com
www.youtube.com
```

but does **not** match:

```text
notyoutube.com
```

The dot-boundary check ensures that the blocked domain is either the complete queried hostname or a proper parent domain.

---

## DNS Packet Parsing & RFC 1035 NXDOMAIN Construction

The DNS engine decodes label-length pairs starting at byte offset **12**, which is immediately after the standard 12-byte DNS header.

### DNS Domain Extraction

```c
static int dns_extract_domain(const uint8_t *packet,
                              int packet_length,
                              char *domain,
                              size_t domain_size)
{
    int position = 12;
    int domain_length = 0;

    domain[0] = '\0';

    while (position < packet_length) {
        uint8_t label_length = packet[position++];

        if (label_length == 0)
            break;

        if ((label_length & 0xC0) != 0)
            return -1; // Pointer compression unsupported in QNAME

        if (position + label_length > packet_length)
            return -1;

        if (domain_length > 0) {
            if ((size_t)(domain_length + 1) >= domain_size)
                return -1;

            domain[domain_length++] = '.';
        }

        memcpy(domain + domain_length,
               packet + position,
               label_length);

        domain_length += label_length;
        position += label_length;
    }

    domain[domain_length] = '\0';

    return 0;
}
```

### DNS Parsing Behavior

The function:

1. Starts at byte offset `12`.
2. Reads the DNS label length byte.
3. Stops when the label length is `0`.
4. Rejects pointer compression in the QNAME when the two high bits are set.
5. Checks that each label remains inside the received packet.
6. Adds `.` between labels.
7. Copies the label bytes into the destination domain buffer.
8. Null-terminates the final domain string.

---

## RFC 1035 NXDOMAIN Response

When a domain matches the blocklist, `dns_send_nxdomain()` constructs an RFC 1035 NXDOMAIN response.

### Response Header

The DNS flags are set to:

```text
0x8403
```

Meaning:

| Bits / Field | Value | Meaning |
|---|---:|---|
| `QR` | 1 | Response |
| `AA` | 1 | Authoritative Answer |
| `RCODE` | 3 | NXDOMAIN |

The response preserves the original **Transaction ID** and **Question record**.

The Answer, Authority, and Additional record counts are cleared to zero.

### NXDOMAIN Implementation

```c
static void dns_send_nxdomain(int socket_fd,
                              const uint8_t *query,
                              int query_length,
                              const struct sockaddr *client_address,
                              socklen_t client_address_length)
{
    uint8_t response[DNS_PACKET_SIZE];

    memcpy(response, query, query_length);

    response[2] = 0x84;
    response[3] = 0x03;

    memset(&response[6], 0, 6); // Clear ANCOUNT, NSCOUNT, ARCOUNT

    sendto(socket_fd,
           response,
           query_length,
           0,
           client_address,
           client_address_length);
}
```

### Result

For a blocked hostname such as:

```text
chatgpt.com
```

the client receives:

```text
RCODE = 3
NXDOMAIN
```

which indicates that the queried DNS name does not exist according to the DNS response.

---

## Upstream Forwarding & Failover State Machine

Queries for non-blocked domains are forwarded to upstream recursive DNS resolvers.

### Primary and Secondary Resolvers

```text
Primary DNS:
1.1.1.1:53

Secondary DNS:
8.8.8.8:53
```

### Forwarding Sequence

1. Create an unbound UDP datagram socket.
2. Bind it to a dedicated local source port:
   - **40053**
3. Configure a **1-second receive timeout** using:
   - `SL_SI91X_SO_RCVTIME`
   - or BSD `SO_RCVTIMEO`
4. Forward the DNS query to:
   - `1.1.1.1:53`
5. Wait for the response.
6. If the primary resolver times out:
   - Fail over to `8.8.8.8:53`.
7. If both upstream servers fail:
   - Construct and return a **SERVFAIL** response.
8. Apply a **2000 ms transaction cooldown** before processing the next transaction.

### DNS State Flow

```text
             +------------------+
             | Client DNS Query |
             +--------+---------+
                      |
                      v
             +------------------+
             | Parse QNAME      |
             +--------+---------+
                      |
                      v
             +------------------+
             | Check Blocklist  |
             +----+---------+---+
                  |         |
             Match|         |No Match
                  |         |
                  v         v
        +-------------+  +------------------+
        | NXDOMAIN    |  | 1.1.1.1:53       |
        | RCODE = 3   |  +--------+---------+
        +-------------+           |
                                  | Timeout
                                  v
                         +------------------+
                         | 8.8.8.8:53       |
                         +--------+---------+
                                  |
                                  | Timeout
                                  v
                         +------------------+
                         | SERVFAIL         |
                         | RCODE = 2        |
                         +------------------+
```

### SERVFAIL

If both upstream DNS servers fail, the embedded DNS server constructs a DNS response with:

```text
Flags: 0x8182
RCODE: 2
Meaning: SERVFAIL
```

---

## Embedded Web Server & REST API

The HTTP server listens on:

```text
TCP port 80
```

It provides a browser-based dashboard and REST-like management endpoints.

### HTTP Routes

| Route | Method | Purpose |
|---|---|---|
| `/` | `GET` | Generates and sends a single-page HTML/CSS management dashboard |
| `/api/add?domain=<str>` | `GET` | Parses and decodes URL-encoded parameters, validates syntax, and appends the domain to the blocklist |
| `/api/remove?domain=<str>` | `GET` | Locates the domain, removes it, and compacts the array |
| `/api/domains` | `GET` | Returns the current blocklist as a JSON object |
| `/favicon.ico` | `GET` | Returns HTTP/1.1 `204 No Content` to avoid unnecessary processing |

### `/api/domains` Response Format

The endpoint returns the current blocklist in the following JSON structure:

```json
{
  "count": 2,
  "domains": [
    "youtube.com",
    "chatgpt.com"
  ]
}
```

### Domain Addition

Example:

```text
/api/add?domain=www.youtube.com
```

The application normalizes the domain before storing it in the blocklist.

For example:

```text
https://www.youtube.com/
```

is converted to:

```text
youtube.com
```

### Domain Removal

Example:

```text
/api/remove?domain=youtube.com
```

The matching domain is removed from the blocklist and the array is compacted.

### HTTP Transfer Management

Outbound HTTP frames are chunked into transfers of up to:

```text
1400 bytes
```

using:

```text
http_send_all()
```

This is used to stay within **WiSeConnect buffer boundaries**.

---

# Setup & Build Instructions

## 1. Wi-Fi Configuration

Provide your **2.4 GHz Wi-Fi credentials** in:

```text
config/sl_net_default_values.h
```

or configure them through the **Network Manager** component in Simplicity Studio.

Example:

```c
#define SL_NET_DEFAULT_WIFI_CLIENT_PROFILE_SSID       "Your_SSID"
#define SL_NET_DEFAULT_WIFI_CLIENT_CREDENTIAL         "Your_Password"
```

Make sure the access point:

- Supports **2.4 GHz 802.11 b/g/n**.
- Has **DHCP enabled**.
- Allows the SiWG917 board to obtain an IP address.
- Provides Internet access if upstream DNS forwarding is required.

---

## 2. Compilation and Flashing

### Import the Project

Import:

```text
siwg917_ip_blocker.slcp
```

into **Simplicity Studio v5**.

### Verify Toolchain Options

Verify that the project contains:

```text
-u _printf_float
-Wall
-Werror
```

### Build

Build the project using the configured Silicon Labs toolchain.

The post-build generator described by:

```text
siwg917_ip_blocker.slpb
```

outputs the target binaries:

```text
siwg917_ip_blocker.rps
siwg917_ip_blocker.hex
siwg917_ip_blocker_isp.bin
```

### Output File Descriptions

| File | Purpose |
|---|---|
| `siwg917_ip_blocker.rps` | RSI Provisioning Image |
| `siwg917_ip_blocker.hex` | Intel HEX record |
| `siwg917_ip_blocker_isp.bin` | ISP Binary |

### Flashing

Flash the `.rps` image using:

- Simplicity Studio **Flash Programmer**
- or **J-Link Commander**

### ISP Recovery Procedure

If the SoC fails to halt:

1. Hold **ISP + RESET**.
2. Release **RESET**.
3. Release **ISP**.
4. The device should enter **ISP mode**.

---

# UART Console Logs

The UART console operates at:

```text
115200 Baud
8 Data Bits
1 Stop Bit
No Parity
```

The following log traces boot initialization, Wi-Fi association, socket binding, domain addition through the web UI, and subsequent DNS interception.

```text
========================================
[APP] Build: DNS_TIMEOUT_FIX_V4_BSD
 SiWG917 IP / DOMAIN BLOCKER
========================================
[APP] Domain mutex created
[APP] Calling sl_net_init...
[APP] sl_net_init status = 0x00000000
[APP] Connecting to Wi-Fi (attempt 1/3)...
[APP] sl_net_up status = 0x00000000
[APP] Wi-Fi connected
[APP] Device IP: 192.168.137.45
[APP] DNS upstream: 1.1.1.1:53 -> 8.8.8.8:53
[APP] HTTP thread created
[APP] DNS thread created

========================================
 SERVICES
========================================
HTTP : http://192.168.137.45:80
DNS  : 192.168.137.45:53
DNS upstream : 1.1.1.1:53 -> 8.8.8.8:53
========================================

[HTTP] Thread started
[HTTP] Creating TCP socket...
[HTTP] socket() returned: 0
[HTTP] Socket created: 0
[HTTP] Calling bind() on TCP port 80...
[HTTP] bind() returned: 0
[HTTP] Bind successful
[HTTP] Calling listen()...
[HTTP] listen() returned: 0
[HTTP] ========================================
[HTTP] TCP SERVER LISTENING ON PORT 80
[HTTP] ========================================
[HTTP] Waiting for client...

[DNS] Thread started
[DNS] Creating UDP socket...
[DNS] socket() returned: 2
[DNS] Binding UDP port 53...
[DNS] bind() returned: 0
[DNS] UDP port 53 listening
[MEM] DNS thread ready: free_heap=28536 min_ever=24304 DNS_stack_free=1219 words
[DNS] Waiting for DNS query...

[HTTP] accept() returned: 1
[HTTP] Client connected
[HTTP] recv() returned: 373
[HTTP] Add domain request: [https://www.youtube.com/]
[APP] Domain blocked: youtube.com
[APP] Total blocked domains: 1
[HTTP] Response sent: header=147 body=18
[HTTP] Client connection closed

[HTTP] accept() returned: 1
[HTTP] Client connected
[HTTP] recv() returned: 352
[HTTP] Add domain request: chatgpt.com
[APP] Domain blocked: chatgpt.com
[APP] Total blocked domains: 2
[HTTP] Response sent: header=147 body=18
[HTTP] Client connection closed

[DNS] recvfrom returned: 29
[MEM] after client DNS recvfrom(): free_heap=28536 min_ever=24304 DNS_stack_free=1219 words
[DNS] Query domain: chatgpt.com
[DNS] BLOCKED: chatgpt.com
[DNS] NXDOMAIN sent
[DNS] Transaction complete - cooldown 2000 ms
[DNS] Cooldown complete - ready for next DNS query

[DNS] recvfrom returned: 29
[MEM] after client DNS recvfrom(): free_heap=28536 min_ever=24304 DNS_stack_free=1122 words
[DNS] Query domain: youtube.com
[DNS] BLOCKED: youtube.com
[DNS] NXDOMAIN sent
[DNS] Transaction complete - cooldown 2000 ms
[DNS] Cooldown complete - ready for next DNS query
```

---

## UART Log Interpretation

### Application Startup

```text
[APP] Domain mutex created
```

The shared blocklist mutex has been successfully created.

```text
[APP] Calling sl_net_init...
[APP] sl_net_init status = 0x00000000
```

The Silicon Labs network stack initialized successfully.

```text
[APP] sl_net_up status = 0x00000000
[APP] Wi-Fi connected
```

The board successfully brought the Wi-Fi interface up and connected to the access point.

### Network Configuration

The board obtained:

```text
Device IP:
192.168.137.45
```

The configured upstream DNS resolvers are:

```text
Primary:
1.1.1.1:53

Secondary:
8.8.8.8:53
```

### HTTP Service

The HTTP task:

1. Creates a TCP socket.
2. Binds to TCP port 80.
3. Calls `listen()`.
4. Waits for browser clients.

The successful log:

```text
[HTTP] TCP SERVER LISTENING ON PORT 80
```

confirms that the HTTP server is ready.

### DNS Service

The DNS task:

1. Creates a UDP socket.
2. Binds to UDP port 53.
3. Waits for DNS queries.

The successful log:

```text
[DNS] UDP port 53 listening
```

confirms that the DNS sinkhole is ready.

### Memory Monitoring

The log:

```text
[MEM] DNS thread ready: free_heap=28536 min_ever=24304 DNS_stack_free=1219 words
```

provides:

- Current free heap: **28536**
- Minimum ever free heap: **24304**
- DNS task stack high-water mark: **1219 words free**

A later DNS transaction reports:

```text
DNS_stack_free=1122 words
```

which provides an additional stack-margin measurement.

### Blocked Domain Addition

The browser adds:

```text
https://www.youtube.com/
```

The application normalizes it to:

```text
youtube.com
```

and reports:

```text
[APP] Domain blocked: youtube.com
[APP] Total blocked domains: 1
```

A second domain:

```text
chatgpt.com
```

is added, resulting in:

```text
[APP] Total blocked domains: 2
```

### DNS Interception

When the client asks for:

```text
chatgpt.com
```

the DNS task reports:

```text
[DNS] Query domain: chatgpt.com
[DNS] BLOCKED: chatgpt.com
[DNS] NXDOMAIN sent
```

The same behavior is demonstrated for:

```text
youtube.com
```

This verifies the complete blocklist-to-NXDOMAIN path.

---

# Client-Side Verification

Point DNS lookups directly to the board's IP address:

```text
192.168.137.45
```

## 1. Windows PowerShell

Run:

```powershell
Resolve-DnsName -Name chatgpt.com -Server 192.168.137.45 -DnsOnly
Resolve-DnsName -Name youtube.com -Server 192.168.137.45 -DnsOnly
```

### Expected Terminal Output

For a blocked domain such as `chatgpt.com`, Windows should report that the DNS name does not exist:

```text
Resolve-DnsName : chatgpt.com : DNS name does not exist
At line:1 char:1
+ Resolve-DnsName -Name chatgpt.com -Server 192.168.137.45 -DnsOnly
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (chatgpt.com:String) [Resolve-DnsName], Win32Exception
    + FullyQualifiedErrorId : DNS_ERROR_RCODE_NAME_ERROR,Microsoft.DnsClient.Commands.ResolveDns
```

The same behavior should occur for:

```text
youtube.com
```

when it is present in the blocklist.

---

## Verification Checklist

| Test | Expected Result |
|---|---|
| Wi-Fi initialization | `sl_net_init status = 0x00000000` |
| Wi-Fi connection | `Wi-Fi connected` |
| IP assignment | Board receives an IPv4 address |
| HTTP socket | TCP socket created successfully |
| HTTP bind | Port 80 bind succeeds |
| HTTP listen | Server listens on TCP 80 |
| DNS socket | UDP socket created successfully |
| DNS bind | Port 53 bind succeeds |
| Domain addition | Domain added to blocklist |
| Domain normalization | `www.youtube.com` becomes `youtube.com` |
| Exact block match | Blocked domain returns NXDOMAIN |
| Subdomain match | `m.youtube.com` is blocked when `youtube.com` is blocked |
| False-positive prevention | `notyoutube.com` is not blocked by `youtube.com` |
| NXDOMAIN flags | `0x8403` |
| Upstream DNS | Non-blocked domains forwarded to `1.1.1.1` |
| DNS failover | Timeout on `1.1.1.1` triggers `8.8.8.8` |
| Upstream failure | Both failures return SERVFAIL `0x8182` |
| Blocklist listing | `/api/domains` returns JSON |
| Domain removal | `/api/remove` removes the selected domain |
| Memory monitoring | Free heap and stack high-water marks reported |
| Transaction stability | 2000 ms DNS cooldown applied |

---

# License

This project is licensed under the **MIT License**.

See the `LICENSE` file for the complete license text.
