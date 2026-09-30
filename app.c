#include "app.h"
#include "sl_net.h"
#include "sl_net_default_values.h"
#include "cmsis_os2.h"
#include "socket.h"
#include "sl_si91x_socket.h"
#include "FreeRTOS.h"
#include "task.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#define APP_BUILD_TAG "DNS_TIMEOUT_FIX_V4_BSD"

/* ============================================================
 * Configuration
 * ============================================================ */

#define MAX_BLOCKED_DOMAINS    20
#define MAX_DOMAIN_LENGTH      64

#define HTTP_PORT              80
#define DNS_PORT               53
#define DNS_PACKET_SIZE         1232
#define DNS_UPSTREAM_TIMEOUT_SEC 1
#define DNS_TRANSACTION_COOLDOWN_MS 2000U

#ifdef SL_SI91X_SO_RCVTIME
#define DNS_RCVTIMEOUT_OPTION SL_SI91X_SO_RCVTIME
#else
#define DNS_RCVTIMEOUT_OPTION SO_RCVTIMEO
#endif


#define HTTP_REQUEST_SIZE      2048
#define HTTP_PAGE_SIZE         8192
#define HTTP_HEADER_SIZE       512

/* set to 1 to just send "hello" to every client (network test) */
#define HTTP_HELLO_TEST        0

#define HTTP_STACK_SIZE        8192   /* was 4096 - too small */
#define DNS_STACK_SIZE         6144

/* ============================================================
 * Global variables
 * ============================================================ */

static char blocked_domains[MAX_BLOCKED_DOMAINS][MAX_DOMAIN_LENGTH];
static uint32_t blocked_domain_count = 0;

static char device_ip_string[32] = "0.0.0.0";
static const char dns_primary_server[] = "1.1.1.1";
static const char dns_secondary_server[] = "8.8.8.8";

/*
 * The SDK documentation names sl_si91x_time_value for SO_RCVTIMEO.
 * This project SDK does not expose that typedef to app.c, so use the
 * same two-field layout locally: seconds + microseconds.
 */
typedef struct {
    uint32_t tv_sec;
    uint32_t tv_usec;
} app_time_value_t;

static osMutexId_t domain_mutex = NULL;

static osThreadId_t http_thread_id = NULL;
static osThreadId_t dns_thread_id = NULL;

/* ============================================================
 * Case-insensitive string helpers
 * ============================================================ */

static int string_equals_ignore_case(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    while (*a != '\0' && *b != '\0') {
        char ca = (char)tolower((unsigned char)*a);
        char cb = (char)tolower((unsigned char)*b);

        if (ca != cb) {
            return 0;
        }

        a++;
        b++;
    }

    return (*a == '\0' && *b == '\0');
}


static int string_starts_ignore_case(const char *text,
                                     const char *prefix)
{
    if (text == NULL || prefix == NULL) {
        return 0;
    }

    while (*prefix != '\0') {
        char ca = (char)tolower((unsigned char)*text);
        char cb = (char)tolower((unsigned char)*prefix);

        if (ca != cb) {
            return 0;
        }

        text++;
        prefix++;
    }

    return 1;
}


/* ============================================================
 * Domain normalization
 * ============================================================ */

static void normalize_domain(const char *input,
                              char *output,
                              size_t output_size)
{
    const char *start;
    size_t length;
    size_t i;

    if (output == NULL || output_size == 0) {
        return;
    }

    output[0] = '\0';

    if (input == NULL) {
        return;
    }

    start = input;

    while (*start == ' ' ||
           *start == '\t' ||
           *start == '\r' ||
           *start == '\n') {
        start++;
    }

    if (string_starts_ignore_case(start, "http://")) {
        start += 7;
    }
    else if (string_starts_ignore_case(start, "https://")) {
        start += 8;
    }

    if (string_starts_ignore_case(start, "www.")) {
        start += 4;
    }

    length = strlen(start);

    while (length > 0) {
        char c = start[length - 1];

        if (c == '/' ||
            c == ' ' ||
            c == '\t' ||
            c == '\r' ||
            c == '\n') {
            length--;
        }
        else {
            break;
        }
    }

    if (length >= output_size) {
        length = output_size - 1;
    }

    for (i = 0; i < length; i++) {
        output[i] = (char)tolower((unsigned char)start[i]);
    }

    output[length] = '\0';
}


/* ============================================================
 * Domain validation
 * ============================================================ */

static int is_valid_domain(const char *domain)
{
    size_t length;
    size_t i;

    if (domain == NULL) {
        return 0;
    }

    length = strlen(domain);

    if (length == 0 || length >= MAX_DOMAIN_LENGTH) {
        return 0;
    }

    for (i = 0; i < length; i++) {
        char c = domain[i];

        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '.' ||
            c == '-' ||
            c == '_') {
            continue;
        }

        return 0;
    }

    return 1;
}


/* ============================================================
 * DNS domain matching
 *
 * Example:
 * blocked: google.com
 *
 * Matches:
 * google.com
 * www.google.com
 * mail.google.com
 *
 * Does NOT match:
 * google.com.example.com
 * ============================================================ */

static int dns_domain_matches(const char *query,
                              const char *blocked)
{
    size_t query_length;
    size_t blocked_length;

    if (query == NULL || blocked == NULL) {
        return 0;
    }

    if (string_equals_ignore_case(query, blocked)) {
        return 1;
    }

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


/* ============================================================
 * Check whether domain is blocked
 * ============================================================ */

static int domain_is_blocked(const char *domain)
{
    uint32_t i;
    int blocked = 0;

    if (domain_mutex != NULL) {
        osMutexAcquire(domain_mutex, osWaitForever);
    }

    for (i = 0; i < blocked_domain_count; i++) {

        if (dns_domain_matches(domain,
                               blocked_domains[i])) {
            blocked = 1;
            break;
        }
    }

    if (domain_mutex != NULL) {
        osMutexRelease(domain_mutex);
    }

    return blocked;
}


/* ============================================================
 * Public domain functions
 * ============================================================ */

uint32_t app_get_blocked_domain_count(void)
{
    uint32_t count;

    if (domain_mutex != NULL) {
        osMutexAcquire(domain_mutex, osWaitForever);
    }

    count = blocked_domain_count;

    if (domain_mutex != NULL) {
        osMutexRelease(domain_mutex);
    }

    return count;
}


const char *app_get_blocked_domain(uint32_t index)
{
    static char result[MAX_DOMAIN_LENGTH];

    result[0] = '\0';

    if (domain_mutex != NULL) {
        osMutexAcquire(domain_mutex, osWaitForever);
    }

    if (index < blocked_domain_count) {
        strncpy(result,
                blocked_domains[index],
                MAX_DOMAIN_LENGTH - 1);

        result[MAX_DOMAIN_LENGTH - 1] = '\0';
    }

    if (domain_mutex != NULL) {
        osMutexRelease(domain_mutex);
    }

    return result;
}


int app_add_blocked_domain(const char *domain)
{
    char normalized[MAX_DOMAIN_LENGTH];
    uint32_t i;

    normalize_domain(domain,
                     normalized,
                     sizeof(normalized));

    if (!is_valid_domain(normalized)) {
        printf("[APP] Invalid domain: %s\n",
               normalized);

        return -1;
    }

    if (domain_mutex != NULL) {
        osMutexAcquire(domain_mutex, osWaitForever);
    }

    for (i = 0; i < blocked_domain_count; i++) {

        if (string_equals_ignore_case(
                blocked_domains[i],
                normalized)) {

            if (domain_mutex != NULL) {
                osMutexRelease(domain_mutex);
            }

            printf("[APP] Domain already blocked: %s\n",
                   normalized);

            return 1;
        }
    }

    if (blocked_domain_count >= MAX_BLOCKED_DOMAINS) {

        if (domain_mutex != NULL) {
            osMutexRelease(domain_mutex);
        }

        printf("[APP] Domain list full\n");

        return -2;
    }

    strncpy(blocked_domains[blocked_domain_count],
            normalized,
            MAX_DOMAIN_LENGTH - 1);

    blocked_domains[blocked_domain_count]
                    [MAX_DOMAIN_LENGTH - 1] = '\0';

    blocked_domain_count++;

    if (domain_mutex != NULL) {
        osMutexRelease(domain_mutex);
    }

    printf("[APP] Domain blocked: %s\n",
           normalized);

    printf("[APP] Total blocked domains: %lu\n",
           (unsigned long)blocked_domain_count);

    return 0;
}


int app_remove_blocked_domain(const char *domain)
{
    char normalized[MAX_DOMAIN_LENGTH];
    uint32_t i;
    uint32_t j;

    normalize_domain(domain,
                     normalized,
                     sizeof(normalized));

    if (domain_mutex != NULL) {
        osMutexAcquire(domain_mutex, osWaitForever);
    }

    for (i = 0; i < blocked_domain_count; i++) {

        if (string_equals_ignore_case(
                blocked_domains[i],
                normalized)) {

            for (j = i;
                 j + 1 < blocked_domain_count;
                 j++) {

                strcpy(blocked_domains[j],
                       blocked_domains[j + 1]);
            }

            blocked_domain_count--;

            if (domain_mutex != NULL) {
                osMutexRelease(domain_mutex);
            }

            printf("[APP] Domain removed: %s\n",
                   normalized);

            return 0;
        }
    }

    if (domain_mutex != NULL) {
        osMutexRelease(domain_mutex);
    }

    printf("[APP] Domain not found: %s\n",
           normalized);

    return -1;
}


/* ============================================================
 * URL decoding
 * ============================================================ */

static char hex_to_char(char c)
{
    if (c >= '0' && c <= '9') {
        return (char)(c - '0');
    }

    if (c >= 'a' && c <= 'f') {
        return (char)(c - 'a' + 10);
    }

    if (c >= 'A' && c <= 'F') {
        return (char)(c - 'A' + 10);
    }

    return 0;
}


static void url_decode(const char *input,
                       char *output,
                       size_t output_size)
{
    size_t i = 0;
    size_t j = 0;

    if (output_size == 0) {
        return;
    }

    while (input[i] != '\0' &&
           j + 1 < output_size) {

        if (input[i] == '%' &&
            input[i + 1] != '\0' &&
            input[i + 2] != '\0') {

            char high = hex_to_char(input[i + 1]);
            char low = hex_to_char(input[i + 2]);

            output[j++] =
                (char)((high << 4) | low);

            i += 3;
        }
        else if (input[i] == '+') {
            output[j++] = ' ';
            i++;
        }
        else {
            output[j++] = input[i++];
        }
    }

    output[j] = '\0';
}


/* ============================================================
 * Get IP address
 * ============================================================ */

const char *app_get_ip_address(void)
{
    return device_ip_string;
}


/* ============================================================
 * HTTP dashboard
 * ============================================================ */

static int build_http_page(char *page,
                           size_t page_size)
{
    int length = 0;
    uint32_t count;
    uint32_t i;

    count = app_get_blocked_domain_count();

    length += snprintf(
        page + length,
        page_size - (size_t)length,

        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' "
        "content='width=device-width,initial-scale=1'>"
        "<title>SiWG917 IP Blocker</title>"

        "<style>"
        "body{"
        "font-family:Arial,sans-serif;"
        "background:#f4f6f8;"
        "margin:0;"
        "padding:30px;"
        "}"

        ".container{"
        "max-width:900px;"
        "margin:auto;"
        "background:white;"
        "padding:30px;"
        "border-radius:15px;"
        "box-shadow:0 4px 15px rgba(0,0,0,.15);"
        "}"

        "h1{"
        "margin-top:0;"
        "}"

        ".ip{"
        "background:#eef4ff;"
        "padding:15px;"
        "border-radius:10px;"
        "margin-bottom:20px;"
        "}"

        "input{"
        "padding:12px;"
        "width:65%%;"
        "border:1px solid #ccc;"
        "border-radius:8px;"
        "}"

        "button{"
        "padding:12px 18px;"
        "border:0;"
        "border-radius:8px;"
        "cursor:pointer;"
        "}"

        ".add{"
        "background:#198754;"
        "color:white;"
        "}"

        ".remove{"
        "background:#dc3545;"
        "color:white;"
        "}"

        "table{"
        "width:100%%;"
        "border-collapse:collapse;"
        "margin-top:20px;"
        "}"

        "th,td{"
        "padding:12px;"
        "border-bottom:1px solid #ddd;"
        "text-align:left;"
        "}"

        ".status{"
        "padding:10px;"
        "background:#e9f7ef;"
        "border-radius:8px;"
        "margin-top:15px;"
        "}"

        "</style>"

        "<script>"
        "function addDomain(){"
        "var d=document.getElementById('domain').value;"
        "if(!d)return;"
        "fetch('/api/add?domain='+encodeURIComponent(d))"
        ".then(function(){location.reload();});"
        "}"

        "function removeDomain(d){"
        "fetch('/api/remove?domain='+encodeURIComponent(d))"
        ".then(function(){location.reload();});"
        "}"

        "function loadDomains(){"
        "fetch('/api/domains')"
        ".then(function(r){return r.json();})"
        ".then(function(data){"
        "console.log(data);"
        "});"
        "}"

        "</script>"

        "</head>"
        "<body>"
        "<div class='container'>"

        "<h1>SiWG917 IP / Domain Blocker</h1>"

        "<div class='ip'>"
        "<b>Device IP:</b> %s"
        "</div>"

        "<div>"
        "<input id='domain' "
        "placeholder='Fixed test domain: example.com'>"
        "<button class='add' onclick='addDomain()'>"
        "Block Domain"
        "</button>"
        "</div>"

        "<div class='status'>"
        "<b>Total blocked domains:</b> %lu"
        "</div>"

        "<table>"
        "<tr>"
        "<th>#</th>"
        "<th>Blocked Domain</th>"
        "<th>Action</th>"
        "</tr>",

        device_ip_string,
        (unsigned long)count
    );

    for (i = 0; i < count; i++) {

        const char *domain =
            app_get_blocked_domain(i);

        length += snprintf(
            page + length,
            page_size - (size_t)length,

            "<tr>"
            "<td>%lu</td>"
            "<td>%s</td>"
            "<td>"
            "<button class='remove' "
            "onclick=\"removeDomain('%s')\">"
            "Remove"
            "</button>"
            "</td>"
            "</tr>",

            (unsigned long)(i + 1),
            domain,
            domain
        );

        if (length >= (int)page_size) {
            break;
        }
    }

    length += snprintf(
        page + length,
        page_size - (size_t)length,

        "</table>"
        "</div>"
        "</body>"
        "</html>"
    );

    return length;
}


/* ============================================================
 * HTTP API response
 * ============================================================ */

static int32_t http_send_all(int client_socket,
                             const void *data,
                             size_t length)
{
    const uint8_t *ptr = (const uint8_t *)data;
    size_t remaining = length;

    /*
     * Silicon Labs documents a maximum plain send buffer of
     * 1460 bytes. Use 1400-byte chunks for HTTP responses.
     */
    while (remaining > 0) {
        size_t chunk =
            (remaining > 1400U) ? 1400U : remaining;

        int32_t sent =
            send(
                client_socket,
                ptr,
                chunk,
                0
            );

        if (sent <= 0) {
            return -1;
        }

        ptr += sent;
        remaining -= (size_t)sent;
    }

    return (int32_t)length;
}


static void send_http_response(int client_socket,
                               const char *content_type,
                               const char *body)
{
    char header[HTTP_HEADER_SIZE];

    int body_length =
        (int)strlen(body);

    int header_length =
        snprintf(
            header,
            sizeof(header),

            "HTTP/1.0 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "Cache-Control: no-cache\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n",

            content_type,
            body_length
        );

    if (header_length <= 0 ||
        header_length >= (int)sizeof(header)) {

        printf("[HTTP] ERROR: response header build failed\n");
        return;
    }

    int32_t header_sent =
        http_send_all(
            client_socket,
            header,
            (size_t)header_length
        );

    int32_t body_sent =
        http_send_all(
            client_socket,
            body,
            (size_t)body_length
        );

    printf("[HTTP] Response sent: header=%ld body=%ld\n",
           (long)header_sent,
           (long)body_sent);
}


/* ============================================================
 * HTTP request handler
 * ============================================================ */

static void handle_http_request(int client_socket,
                                const char *request)
{
    char domain_encoded[MAX_DOMAIN_LENGTH * 2];
    char domain[MAX_DOMAIN_LENGTH];
    /* static so it is not on the thread stack (8 KB) */
    static char body[HTTP_PAGE_SIZE];

    memset(domain_encoded, 0, sizeof(domain_encoded));
    memset(domain, 0, sizeof(domain));

    printf("[HTTP] Request:\n%s\n",
           request);

    /* --------------------------------------------------------
     * Dashboard
     * -------------------------------------------------------- */

    if (strncmp(request,
                "GET / ",
                6) == 0) {

        memset(body, 0, sizeof(body));

        build_http_page(
            body,
            sizeof(body)
        );

        send_http_response(
            client_socket,
            "text/html",
            body
        );

        return;
    }


    /* --------------------------------------------------------
     * Add domain
     * -------------------------------------------------------- */

    if (string_starts_ignore_case(
            request,
            "GET /api/add?domain=")) {

        const char *start =
            request + strlen("GET /api/add?domain=");

        const char *end =
            strchr(start, ' ');

        size_t length;

        if (end != NULL) {
            length = (size_t)(end - start);
        }
        else {
            length = strlen(start);
        }

        if (length >= sizeof(domain_encoded)) {
            length = sizeof(domain_encoded) - 1;
        }

        memcpy(
            domain_encoded,
            start,
            length
        );

        domain_encoded[length] = '\0';

        url_decode(
            domain_encoded,
            domain,
            sizeof(domain)
        );

        printf("[HTTP] Add domain request: %s\n",
               domain);


        if (app_add_blocked_domain(domain) == 0) {

            send_http_response(
                client_socket,
                "application/json",
                "{\"status\":\"added\"}"
            );
        }
        else {

            send_http_response(
                client_socket,
                "application/json",
                "{\"status\":\"error\"}"
            );
        }

        return;
    }


    /* --------------------------------------------------------
     * Remove domain
     * -------------------------------------------------------- */

    if (string_starts_ignore_case(
            request,
            "GET /api/remove?domain=")) {

        const char *start =
            request + strlen("GET /api/remove?domain=");

        const char *end =
            strchr(start, ' ');

        size_t length;

        if (end != NULL) {
            length = (size_t)(end - start);
        }
        else {
            length = strlen(start);
        }

        if (length >= sizeof(domain_encoded)) {
            length = sizeof(domain_encoded) - 1;
        }

        memcpy(
            domain_encoded,
            start,
            length
        );

        domain_encoded[length] = '\0';

        url_decode(
            domain_encoded,
            domain,
            sizeof(domain)
        );

        printf("[HTTP] Remove domain request: %s\n",
               domain);


        if (app_remove_blocked_domain(domain) == 0) {

            send_http_response(
                client_socket,
                "application/json",
                "{\"status\":\"removed\"}"
            );
        }
        else {

            send_http_response(
                client_socket,
                "application/json",
                "{\"status\":\"not_found\"}"
            );
        }

        return;
    }


    /* --------------------------------------------------------
     * Domains API
     * -------------------------------------------------------- */

    if (strncmp(request,
                "GET /api/domains ",
                17) == 0) {

        int length = 0;
        uint32_t count =
            app_get_blocked_domain_count();

        length += snprintf(
            body + length,
            sizeof(body) - (size_t)length,
            "{\"count\":%lu,\"domains\":[",
            (unsigned long)count
        );

        for (uint32_t i = 0;
             i < count;
             i++) {

            const char *domain_item =
                app_get_blocked_domain(i);

            length += snprintf(
                body + length,
                sizeof(body) - (size_t)length,
                "%s\"%s\"",
                (i == 0) ? "" : ",",
                domain_item
            );
        }

        snprintf(
            body + length,
            sizeof(body) - (size_t)length,
            "]}"
        );

        send_http_response(
            client_socket,
            "application/json",
            body
        );

        return;
    }


    /* --------------------------------------------------------
     * Favicon
     * -------------------------------------------------------- */

    if (strncmp(request,
                "GET /favicon.ico",
                16) == 0) {

        char header[HTTP_HEADER_SIZE];

        int header_length =
            snprintf(
                header,
                sizeof(header),

                "HTTP/1.1 204 No Content\r\n"
                "Connection: close\r\n"
                "\r\n"
            );

        http_send_all(
            client_socket,
            header,
            (size_t)header_length
        );

        return;
    }


    /* --------------------------------------------------------
     * 404
     * -------------------------------------------------------- */

    {
        const char *not_found =
            "<html><body>"
            "<h1>404 Not Found</h1>"
            "</body></html>";

        char header[HTTP_HEADER_SIZE];

        int body_length =
            (int)strlen(not_found);

        int header_length =
            snprintf(
                header,
                sizeof(header),

                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n"
                "\r\n",

                body_length
            );

        http_send_all(
            client_socket,
            header,
            (size_t)header_length
        );

        http_send_all(
            client_socket,
            not_found,
            (size_t)body_length
        );
    }
}


/* ============================================================
 * HTTP server thread
 * ============================================================ */

static void http_server_thread(void *argument)
{
    int32_t server_socket;
    int32_t client_socket;

    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

    socklen_t client_address_length;

    /* static so it is not on the thread stack */
    static char request[HTTP_REQUEST_SIZE];

    (void)argument;

    printf("\n[HTTP] Thread started\n");

    /* --------------------------------------------------------
     * Create TCP socket
     * -------------------------------------------------------- */

    printf("[HTTP] Creating TCP socket...\n");

    server_socket =
        socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP
        );

    printf("[HTTP] socket() returned: %ld\n",
           (long)server_socket);

    if (server_socket < 0) {

        printf("[HTTP] ERROR: socket creation failed\n");

        return;
    }

    printf("[HTTP] Socket created: %ld\n",
           (long)server_socket);


    /* --------------------------------------------------------
     * Server address
     * -------------------------------------------------------- */

    memset(
        &server_address,
        0,
        sizeof(server_address)
    );

    server_address.sin_family =
        AF_INET;

    server_address.sin_port =
        htons(HTTP_PORT);

    /*
     * Do not use INADDR_ANY here because of
     * the SiWG917 SDK type definitions.
     *
     * Zero means bind to the local interface.
     */
    server_address.sin_addr.s_addr = 0;


    /* --------------------------------------------------------
     * Bind
     * -------------------------------------------------------- */

    printf("[HTTP] Calling bind() on TCP port %d...\n",
           HTTP_PORT);

    int32_t bind_status =
        bind(
            server_socket,
            (struct sockaddr *)&server_address,
            sizeof(server_address)
        );

    printf("[HTTP] bind() returned: %ld\n",
           (long)bind_status);

    if (bind_status < 0) {

        printf("[HTTP] ERROR: bind() failed\n");

        close(server_socket);

        return;
    }

    printf("[HTTP] Bind successful\n");


    /* --------------------------------------------------------
     * Listen
     * -------------------------------------------------------- */

    printf("[HTTP] Calling listen()...\n");

    int32_t listen_status =
        listen(
            server_socket,
            5
        );

    printf("[HTTP] listen() returned: %ld\n",
           (long)listen_status);

    if (listen_status < 0) {

        printf("[HTTP] ERROR: listen() failed\n");

        close(server_socket);

        return;
    }

    printf("[HTTP] ========================================\n");
    printf("[HTTP] TCP SERVER LISTENING ON PORT 80\n");
    printf("[HTTP] ========================================\n");


    /* --------------------------------------------------------
     * Accept clients forever
     * -------------------------------------------------------- */

    while (1) {

        memset(
            &client_address,
            0,
            sizeof(client_address)
        );

        client_address_length =
            sizeof(client_address);

        printf("[HTTP] Waiting for client...\n");

        client_socket =
            accept(
                server_socket,
                (struct sockaddr *)&client_address,
                &client_address_length
            );

        printf("[HTTP] accept() returned: %ld\n",
               (long)client_socket);

        if (client_socket < 0) {

            printf("[HTTP] ERROR: accept() failed\n");

            osDelay(100);

            continue;
        }

        printf("[HTTP] Client connected\n");

#if HTTP_HELLO_TEST
        {
            const char *reply =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 5\r\n"
                "Connection: close\r\n"
                "\r\n"
                "hello";

            int32_t sent = send(client_socket, reply, strlen(reply), 0);
            printf("[HTTP] send() returned: %ld\n", (long)sent);

            close(client_socket);
            printf("[HTTP] Client connection closed\n");
            continue;
        }
#endif


        /* ----------------------------------------------------
         * Receive HTTP request
         * ---------------------------------------------------- */

        memset(
            request,
            0,
            sizeof(request)
        );

        int32_t received =
            recv(
                client_socket,
                request,
                sizeof(request) - 1,
                0
            );

        printf("[HTTP] recv() returned: %ld\n",
               (long)received);

        if (received > 0) {

            request[received] = '\0';

            handle_http_request(
                client_socket,
                request
            );
        }
        else {

            printf("[HTTP] No HTTP request received\n");
        }


        /* ----------------------------------------------------
         * Close client
         * ---------------------------------------------------- */

        close(client_socket);

        printf("[HTTP] Client connection closed\n");
    }
}


/* ============================================================
 * DNS QNAME extraction
 * ============================================================ */

static int dns_extract_domain(const uint8_t *packet,
                              int packet_length,
                              char *domain,
                              size_t domain_size)
{
    int position = 12;
    int domain_length = 0;

    if (packet == NULL ||
        domain == NULL ||
        domain_size == 0) {
        return -1;
    }

    domain[0] = '\0';

    while (position < packet_length) {

        uint8_t label_length =
            packet[position++];

        if (label_length == 0) {
            break;
        }

        if ((label_length & 0xC0) != 0) {
            return -1;
        }

        if (position + label_length >
            packet_length) {
            return -1;
        }

        if (domain_length > 0) {

            if ((size_t)(domain_length + 1) >=
                domain_size) {
                return -1;
            }

            domain[domain_length++] = '.';
        }

        if ((size_t)(domain_length + label_length) >=
            domain_size) {
            return -1;
        }

        memcpy(
            domain + domain_length,
            packet + position,
            label_length
        );

        domain_length += label_length;

        position += label_length;
    }

    domain[domain_length] = '\0';

    return 0;
}


/* ============================================================
 * DNS blocked response
 * ============================================================ */

static void dns_send_nxdomain(
    int socket_fd,
    const uint8_t *query,
    int query_length,
    const struct sockaddr *client_address,
    socklen_t client_address_length)
{
    uint8_t response[DNS_PACKET_SIZE];

    int response_length;

    if (query_length < 12) {
        return;
    }

    if (query_length > (int)sizeof(response)) {
        return;
    }

    memcpy(
        response,
        query,
        query_length
    );

    /*
     * DNS header flags:
     *
     * 0x8403
     *
     * QR = 1
     * AA = 1
     * RCODE = 3 (NXDOMAIN)
     */
    response[2] = 0x84;
    response[3] = 0x03;

    /* Question count remains unchanged. */

    response[6] = 0x00;
    response[7] = 0x00;

    response[8] = 0x00;
    response[9] = 0x00;

    response[10] = 0x00;
    response[11] = 0x00;

    response_length =
        query_length;

    sendto(
        socket_fd,
        response,
        response_length,
        0,
        client_address,
        client_address_length
    );

    printf("[DNS] NXDOMAIN sent\n");
}


/* ============================================================
 * DNS upstream forwarding
 *
 * Client-facing socket:
 *     UDP/53
 *
 * Upstream:
 *     UDP socket with an automatically assigned local port
 *     TCP/53 fallback
 *
 * The upstream UDP socket is intentionally NOT bound to a fixed
 * local port. WiSeConnect permits an unbound UDP socket to use
 * sendto(), and the stack chooses the local source port.
 * ============================================================ */

static void dns_print_memory(const char *where)
{
    UBaseType_t stack_free_words = uxTaskGetStackHighWaterMark(NULL);

    printf(
        "[MEM] %s: free_heap=%lu min_ever=%lu DNS_stack_free=%lu words\n",
        where,
        (unsigned long)xPortGetFreeHeapSize(),
        (unsigned long)xPortGetMinimumEverFreeHeapSize(),
        (unsigned long)stack_free_words
    );
}


static int dns_set_upstream_timeout(int socket_fd)
{
    app_time_value_t timeout;
    int result;

    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_sec = DNS_UPSTREAM_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    printf("[DNS] Setting receive timeout = %d second\n",
           DNS_UPSTREAM_TIMEOUT_SEC);
    printf("[DNS] timeout struct: size=%lu tv_sec=%lu tv_usec=%lu\n",
           (unsigned long)sizeof(timeout),
           (unsigned long)timeout.tv_sec,
           (unsigned long)timeout.tv_usec);

    result = setsockopt(socket_fd,
                        SOL_SOCKET,
                        DNS_RCVTIMEOUT_OPTION,
                        &timeout,
                        sizeof(timeout));

#if defined(SL_SI91X_SO_RCVTIME)
    printf("[DNS] timeout API: SL_SI91X_SO_RCVTIME option=%d result=%d errno=%d\n",
           DNS_RCVTIMEOUT_OPTION, result, errno);
#else
    printf("[DNS] timeout API: BSD SO_RCVTIMEO option=%d result=%d errno=%d\n",
           DNS_RCVTIMEOUT_OPTION, result, errno);
#endif

    if (result < 0) {
        printf("[DNS] ERROR: receive timeout configuration failed\n");
        return -1;
    }

    return 0;
}

static void dns_make_upstream_address(
    struct sockaddr_in *address,
    const char *ip_string)
{
    memset(
        address,
        0,
        sizeof(*address)
    );

    address->sin_family =
        AF_INET;

    /*
     * Silicon Labs WiSeConnect BSD socket documentation uses
     * the destination port directly for IPv4 socket addresses.
     */
    address->sin_port =
        htons(DNS_PORT);

    sl_net_inet_addr(
        ip_string,
        &address->sin_addr.s_addr
    );
}


static int dns_response_matches_query(
    const uint8_t *query,
    int query_length,
    const uint8_t *response,
    int response_length)
{
    if (query == NULL ||
        response == NULL ||
        query_length < 12 ||
        response_length < 12) {

        return 0;
    }

    /*
     * Match DNS transaction ID.
     */
    if (query[0] != response[0] ||
        query[1] != response[1]) {

        return 0;
    }

    /*
     * QR bit must indicate a response.
     */
    if ((response[2] & 0x80U) == 0) {
        return 0;
    }

    return 1;
}


/* TCP send/receive helpers intentionally omitted: UDP-only DNS forwarding. */

static int dns_forward_udp(
    const uint8_t *query,
    int query_length,
    const char *server_ip,
    uint8_t *response,
    int response_size)
{
    int32_t upstream_socket;

    struct sockaddr_in upstream_address;
    struct sockaddr_in response_address;
    struct sockaddr_in local_address;

    socklen_t response_address_length;

    int32_t sent;
    int32_t received;

    upstream_socket =
        socket(
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_UDP
        );

    printf(
        "[DNS] UDP upstream socket() returned: %ld\n",
        (long)upstream_socket
    );

    dns_print_memory("after upstream socket()");

    if (upstream_socket < 0) {

        printf(
            "[DNS] UDP upstream socket failed, errno=%d\n",
            errno
        );

        return -1;
    }

    /*
     * Give the upstream UDP socket an explicit local source port.
     * This avoids relying on an unbound UDP socket for the reply path.
     * The socket is closed after one DNS transaction, so a fixed test
     * port is sufficient here.
     */
    memset(&local_address, 0, sizeof(local_address));
    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(40053);
    local_address.sin_addr.s_addr = 0;

    printf("[DNS] Binding upstream UDP local port 40053...\n");

    if (bind(
            upstream_socket,
            (struct sockaddr *)&local_address,
            sizeof(local_address)) < 0) {

        printf(
            "[DNS] Upstream UDP bind failed, errno=%d\n",
            errno
        );

        close(upstream_socket);
        return -1;
    }

    printf("[DNS] Upstream UDP local bind successful\n");

    if (dns_set_upstream_timeout(
            upstream_socket) < 0) {

        close(upstream_socket);
        return -1;
    }

    dns_make_upstream_address(
        &upstream_address,
        server_ip
    );

    printf(
        "[DNS] UDP destination: %s:53\n",
        server_ip
    );

    printf("[DNS] UDP source port: 40053\n");
    dns_print_memory("before upstream sendto()");

    sent =
        sendto(
            upstream_socket,
            query,
            query_length,
            0,
            (const struct sockaddr *)&upstream_address,
            sizeof(upstream_address)
        );

    printf(
        "[DNS] UDP sendto returned: %ld\n",
        (long)sent
    );

    if (sent != query_length) {

        printf(
            "[DNS] UDP send failed, errno=%d\n",
            errno
        );

        close(upstream_socket);
        return -1;
    }

    response_address_length =
        sizeof(response_address);

    memset(
        &response_address,
        0,
        sizeof(response_address)
    );

    printf(
        "[DNS] Waiting for UDP upstream response...\n"
    );

    dns_print_memory("before upstream recvfrom()");

    printf(
        "[DNS] BEFORE recvfrom(): socket=%ld timeout=%d sec\n",
        (long)upstream_socket,
        DNS_UPSTREAM_TIMEOUT_SEC
    );

    uint32_t recv_start_tick = osKernelGetTickCount();

    received =
        recvfrom(
            upstream_socket,
            response,
            response_size,
            0,
            (struct sockaddr *)&response_address,
            &response_address_length
        );

    uint32_t recv_end_tick = osKernelGetTickCount();
    uint32_t recv_elapsed_ticks = recv_end_tick - recv_start_tick;
    uint32_t tick_frequency = osKernelGetTickFreq();
    uint32_t recv_elapsed_ms = 0;

    if (tick_frequency != 0U) {
        recv_elapsed_ms =
            (recv_elapsed_ticks * 1000U) / tick_frequency;
    }

    printf(
        "[DNS] AFTER recvfrom(): returned=%ld errno=%d elapsed=%lu ms\n",
        (long)received,
        errno,
        (unsigned long)recv_elapsed_ms
    );

    dns_print_memory("after upstream recvfrom()");

    if (received < 0) {

        printf(
            "[DNS] UDP upstream timeout/error, errno=%d\n",
            errno
        );

        close(upstream_socket);
        return -1;
    }

    if (received < 12) {

        printf(
            "[DNS] UDP upstream response too short\n"
        );

        close(upstream_socket);
        return -1;
    }

    /*
     * Accept only a DNS response matching this query.
     * The fresh socket is used for one transaction, so there
     * is no other expected application traffic on it.
     */
    if (!dns_response_matches_query(
            query,
            query_length,
            response,
            received)) {

        printf(
            "[DNS] UDP upstream response did not match query\n"
        );

        close(upstream_socket);
        return -1;
    }

    printf(
        "[DNS] UDP upstream response accepted: %ld bytes\n",
        (long)received
    );

    close(upstream_socket);

    return (int)received;
}


/* ============================================================
 * DNS over TCP
 *
 * DNS over TCP puts a two-byte network-order message length
 * before the DNS message.
 * ============================================================ */

/* DNS-over-TCP fallback intentionally omitted. */

static void dns_server_thread(void *argument)
{
    int32_t dns_socket;

    struct sockaddr_in server_address;
    struct sockaddr_in client_address;

    socklen_t client_address_length;

    static uint8_t packet[DNS_PACKET_SIZE];
    static uint8_t response[DNS_PACKET_SIZE];

    char domain[MAX_DOMAIN_LENGTH];

    (void)argument;

    osDelay(500);

    printf("\n[DNS] Thread started\n");
    printf("[DNS] Creating UDP socket...\n");

    dns_socket =
        socket(
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_UDP
        );

    printf("[DNS] socket() returned: %ld\n",
           (long)dns_socket);

    if (dns_socket < 0) {
        printf("[DNS] ERROR: socket creation failed, errno=%d\n", errno);
        return;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(DNS_PORT);
    server_address.sin_addr.s_addr = 0;

    printf("[DNS] Binding UDP port %d...\n", DNS_PORT);

    int32_t bind_status =
        bind(
            dns_socket,
            (struct sockaddr *)&server_address,
            sizeof(server_address)
        );

    printf("[DNS] bind() returned: %ld\n",
           (long)bind_status);

    if (bind_status < 0) {
        printf("[DNS] ERROR: bind port 53 failed, errno=%d\n", errno);
        close(dns_socket);
        return;
    }

    printf("[DNS] UDP port 53 listening\n");
    dns_print_memory("DNS thread ready");

    while (1) {
        memset(&client_address, 0, sizeof(client_address));
        memset(packet, 0, sizeof(packet));
        memset(response, 0, sizeof(response));
        memset(domain, 0, sizeof(domain));

        client_address_length = sizeof(client_address);

        printf("[DNS] Waiting for DNS query...\n");

        int32_t received =
            recvfrom(
                dns_socket,
                packet,
                sizeof(packet),
                0,
                (struct sockaddr *)&client_address,
                &client_address_length
            );

        if (received < 0) {
            printf("[DNS] Client recvfrom failed, errno=%d\n", errno);
            osDelay(50);
            continue;
        }

        if (received < 12) {
            printf("[DNS] Ignoring short DNS packet: %ld bytes\n",
                   (long)received);
            continue;
        }

        printf("[DNS] recvfrom returned: %ld\n", (long)received);
        dns_print_memory("after client DNS recvfrom()");

        if (dns_extract_domain(
                packet,
                received,
                domain,
                sizeof(domain)) != 0) {
            printf("[DNS] Could not parse query\n");
            continue;
        }

        printf("[DNS] Query domain: %s\n", domain);

        /* BLOCKED -> NXDOMAIN -> cooldown -> next query */
        if (domain_is_blocked(domain)) {
            printf("[DNS] BLOCKED: %s\n", domain);

            dns_send_nxdomain(
                dns_socket,
                packet,
                received,
                (struct sockaddr *)&client_address,
                client_address_length
            );

            printf("[DNS] Transaction complete - cooldown %lu ms\n",
                   (unsigned long)DNS_TRANSACTION_COOLDOWN_MS);
            osDelay(DNS_TRANSACTION_COOLDOWN_MS);
            printf("[DNS] Cooldown complete - ready for next DNS query\n");
            continue;
        }

        /*
         * ALLOWED -> 1.1.1.1 -> 8.8.8.8 -> SERVFAIL.
         * Each upstream recvfrom() gets a strict 1-second timeout.
         */
        printf("[DNS] ALLOWED: %s\n", domain);
        dns_print_memory("before upstream DNS transaction");

        int response_length =
            dns_forward_udp(
                packet,
                received,
                dns_primary_server,
                response,
                sizeof(response)
            );

        if (response_length < 0) {
            printf("[DNS] Primary timeout/failure -> trying %s:53\n",
                   dns_secondary_server);

            response_length =
                dns_forward_udp(
                    packet,
                    received,
                    dns_secondary_server,
                    response,
                    sizeof(response)
                );
        }

        if (response_length > 0) {
            int32_t sent_to_client =
                sendto(
                    dns_socket,
                    response,
                    response_length,
                    0,
                    (const struct sockaddr *)&client_address,
                    client_address_length
                );

            printf("[DNS] Response sent to client: %ld\n",
                   (long)sent_to_client);

            if (sent_to_client != response_length) {
                printf("[DNS] Client response send failed, errno=%d\n",
                       errno);
            }
        }
        else {
            /* Both upstream servers failed -> SERVFAIL. */
            memcpy(response, packet, (size_t)received);

            /* QR=1, preserve RD, RCODE=2 (SERVFAIL). */
            response[2] =
                (uint8_t)(0x80U | (packet[2] & 0x01U));
            response[3] = 0x02;

            response[6] = 0x00;
            response[7] = 0x00;
            response[8] = 0x00;
            response[9] = 0x00;
            response[10] = 0x00;
            response[11] = 0x00;

            int32_t sent_to_client =
                sendto(
                    dns_socket,
                    response,
                    received,
                    0,
                    (const struct sockaddr *)&client_address,
                    client_address_length
                );

            printf("[DNS] Both upstream DNS servers failed\n");
            printf("[DNS] SERVFAIL sent: %ld\n",
                   (long)sent_to_client);
        }

        /* Every complete transaction gets exactly one cooldown. */
        printf("[DNS] Transaction complete - cooldown %lu ms\n",
               (unsigned long)DNS_TRANSACTION_COOLDOWN_MS);
        osDelay(DNS_TRANSACTION_COOLDOWN_MS);
        printf("[DNS] Cooldown complete - ready for next DNS query\n");
    }
}


/* ============================================================
 * Application initialization
 * ============================================================ */



/* ============================================================
 * Application initialization
 * ============================================================ */

/* ============================================================
 * Application initialization
 * ============================================================ */

void app_init(void)
{
    sl_status_t status;

    printf("\n");
    printf("========================================\n");
    printf("[APP] Build: %s\n", APP_BUILD_TAG);
    printf(" SiWG917 IP / DOMAIN BLOCKER\n");
    printf("========================================\n");

    domain_mutex =
        osMutexNew(NULL);

    if (domain_mutex == NULL) {
        printf("[APP] ERROR: Domain mutex creation failed\n");
        return;
    }

    printf("[APP] Domain mutex created\n");
    printf("[APP] Calling sl_net_init...\n");

    status =
        sl_net_init(
            SL_NET_WIFI_CLIENT_INTERFACE,
            NULL,
            NULL,
            NULL
        );

    printf("[APP] sl_net_init status = 0x%08lx\n",
           (unsigned long)status);

    if (status != SL_STATUS_OK) {
        printf("[APP] ERROR: sl_net_init failed\n");
        return;
    }

    /*
     * Do not create sockets until the Wi-Fi client is up.
     * Retry three times because the user's board has shown an
     * intermittent first sl_net_up failure.
     */
    for (uint32_t attempt = 1; attempt <= 3; attempt++) {
        printf("[APP] Connecting to Wi-Fi (attempt %lu/3)...\n",
               (unsigned long)attempt);

        status =
            sl_net_up(
                SL_NET_WIFI_CLIENT_INTERFACE,
                SL_NET_DEFAULT_WIFI_CLIENT_PROFILE_ID
            );

        printf("[APP] sl_net_up status = 0x%08lx\n",
               (unsigned long)status);

        if (status == SL_STATUS_OK) {
            break;
        }

        if (attempt < 3) {
            osDelay(1000);
        }
    }

    if (status != SL_STATUS_OK) {
        printf("[APP] Wi-Fi connection failed after 3 attempts\n");
        return;
    }

    printf("[APP] Wi-Fi connected\n");

    /*
     * Give DHCP and the network interface a short settling time.
     */
    osDelay(500);

    sl_net_wifi_client_profile_t profile;

    memset(
        &profile,
        0,
        sizeof(profile)
    );

    status =
        sl_net_get_profile(
            SL_NET_WIFI_CLIENT_INTERFACE,
            SL_NET_DEFAULT_WIFI_CLIENT_PROFILE_ID,
            (sl_net_profile_t *)&profile
        );

    if (status == SL_STATUS_OK) {
        uint32_t ip =
            profile.ip.ip.v4.ip_address.value;

        snprintf(
            device_ip_string,
            sizeof(device_ip_string),
            "%lu.%lu.%lu.%lu",

            (unsigned long)(ip & 0xFF),

            (unsigned long)((ip >> 8) & 0xFF),

            (unsigned long)((ip >> 16) & 0xFF),

            (unsigned long)((ip >> 24) & 0xFF)
        );

        printf("[APP] Device IP: %s\n",
               device_ip_string);

        printf("[APP] DNS upstream: %s:53 -> %s:53\n",
               dns_primary_server,
               dns_secondary_server);
    }
    else {
        strcpy(
            device_ip_string,
            "0.0.0.0"
        );

        printf("[APP] ERROR: Could not get network profile\n");
    }

    const osThreadAttr_t http_attributes = {
        .name = "HTTP",
        .stack_size = HTTP_STACK_SIZE,
        .priority = osPriorityNormal
    };

    http_thread_id =
        osThreadNew(
            http_server_thread,
            NULL,
            &http_attributes
        );

    if (http_thread_id == NULL) {
        printf("[APP] ERROR: HTTP thread creation failed\n");
    }
    else {
        printf("[APP] HTTP thread created\n");
    }

    const osThreadAttr_t dns_attributes = {
        .name = "DNS",
        .stack_size = DNS_STACK_SIZE,
        .priority = osPriorityNormal
    };

    dns_thread_id =
        osThreadNew(
            dns_server_thread,
            NULL,
            &dns_attributes
        );

    if (dns_thread_id == NULL) {
        printf("[APP] ERROR: DNS thread creation failed\n");
    }
    else {
        printf("[APP] DNS thread created\n");
    }

    printf("\n");
    printf("========================================\n");
    printf(" SERVICES\n");
    printf("========================================\n");
    printf("HTTP : http://%s:80\n",
           device_ip_string);
    printf("DNS  : %s:53\n",
           device_ip_string);
    printf("DNS upstream : %s:53 -> %s:53\n",
           dns_primary_server,
           dns_secondary_server);
    printf("========================================\n");
}


/* ============================================================
 * Application process action
 * ============================================================ */

void app_process_action(void)
{
    /*
     * Network services run in their own RTOS threads.
     *
     * Keep the main application task alive.
     */
    osDelay(100);
}
