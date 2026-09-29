#ifndef APP_H
#define APP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void app_init(void);
void app_process_action(void);

const char *app_get_ip_address(void);

uint32_t app_get_blocked_domain_count(void);
const char *app_get_blocked_domain(uint32_t index);

int app_add_blocked_domain(const char *domain);
int app_remove_blocked_domain(const char *domain);

#ifdef __cplusplus
}
#endif

#endif