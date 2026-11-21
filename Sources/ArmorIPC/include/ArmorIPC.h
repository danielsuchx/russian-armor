#pragma once
#include <stddef.h>
// Authenticated protocol payloads are opaque to this bounded local transport.
int ra_engine_exchange(const char *path, unsigned int timeout_seconds, const unsigned char *request, size_t request_length,
                       unsigned char *response, size_t capacity, size_t *response_length);
