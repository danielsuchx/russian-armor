#pragma once
#include <stddef.h>
typedef enum {
    RA_OK, RA_BIND, RA_TIMEOUT, RA_DNS, RA_TLS, RA_TOO_LARGE, RA_CANCELLED, RA_NETWORK
} RAResult;
typedef int (*RACancelled)(void);
RAResult ra_tunnel_get(const char *url, const char *interface_name,
                       unsigned char *body, size_t capacity, size_t *length,
                       long *status, long *retry_after, RACancelled cancelled);

RAResult ra_tunnel_get_resolved(const char *url, const char *interface_name, const char *resolution,
                       unsigned char *body, size_t capacity, size_t *length,
                       long *status, long *retry_after, RACancelled cancelled);
