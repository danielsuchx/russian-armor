#include "BoundCurl.h"
#include <curl/curl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>

struct Request {
    unsigned int index;
    unsigned char *body;
    size_t capacity, length;
    bool bind_failed, overflow;
    RACancelled cancelled;
};

static pthread_once_t once = PTHREAD_ONCE_INIT;
static CURLcode init_result;
static void init_curl(void) { init_result = curl_global_init(CURL_GLOBAL_DEFAULT); }

static int bind_socket(void *context, curl_socket_t fd, curlsocktype purpose) {
    struct Request *r = context;
    if (purpose != CURLSOCKTYPE_IPCXN ||
        setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &r->index, sizeof(r->index)) != 0) {
        r->bind_failed = true;
        return CURL_SOCKOPT_ERROR;
    }
    return CURL_SOCKOPT_OK;
}

static size_t receive_body(char *data, size_t size, size_t count, void *context) {
    struct Request *r = context;
    if (size && count > (r->capacity - r->length) / size) {
        r->overflow = true;
        return 0;
    }
    size_t bytes = size * count;
    memcpy(r->body + r->length, data, bytes);
    r->length += bytes;
    return bytes;
}

static int progress(void *context, curl_off_t total, curl_off_t received, curl_off_t upload, curl_off_t sent) {
    return ((struct Request *)context)->cancelled();
}

RAResult ra_tunnel_get_resolved(const char *url, const char *interface_name, const char *resolution,
                       unsigned char *body, size_t capacity, size_t *length,
                       long *status, long *retry_after, RACancelled cancelled) {
    struct Request r = {.index = if_nametoindex(interface_name), .body = body,
                        .capacity = capacity, .cancelled = cancelled};
    if (!r.index) return RA_BIND;
    pthread_once(&once, init_curl);
    if (init_result != CURLE_OK) return RA_NETWORK;
    CURL *curl = curl_easy_init();
    if (!curl) return RA_NETWORK;
    CURLcode code;
    struct curl_slist *addresses = NULL;
#define SET(option, value) do { code = curl_easy_setopt(curl, option, value); if (code != CURLE_OK) goto done; } while (0)
    SET(CURLOPT_URL, url);
    if (resolution && *resolution) {
        addresses = curl_slist_append(NULL, resolution);
        if (!addresses) { code = CURLE_OUT_OF_MEMORY; goto done; }
        SET(CURLOPT_RESOLVE, addresses);
    }
    SET(CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTPS);
    SET(CURLOPT_PROXY, "");
    SET(CURLOPT_IPRESOLVE, (long)CURL_IPRESOLVE_V4);
    SET(CURLOPT_SOCKOPTFUNCTION, bind_socket);
    SET(CURLOPT_SOCKOPTDATA, &r);
    SET(CURLOPT_NOSIGNAL, 1L);
    SET(CURLOPT_TIMEOUT_MS, 8000L);
    SET(CURLOPT_WRITEFUNCTION, receive_body);
    SET(CURLOPT_WRITEDATA, &r);
    SET(CURLOPT_XFERINFOFUNCTION, progress);
    SET(CURLOPT_XFERINFODATA, &r);
    SET(CURLOPT_NOPROGRESS, 0L);
    // A new handle has no redirect following, cookies or shared connections.
    // libcurl's default HTTPS peer and host verification remain enabled.
    code = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    curl_off_t retry = 0;
    curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry);
    *retry_after = retry;
    *length = r.length;
done:
    curl_easy_cleanup(curl);
    curl_slist_free_all(addresses);
    if (r.bind_failed) return RA_BIND;
    if (r.overflow) return RA_TOO_LARGE;
    switch (code) {
        case CURLE_OK: return RA_OK;
        case CURLE_OPERATION_TIMEDOUT: return RA_TIMEOUT;
        case CURLE_COULDNT_RESOLVE_HOST: return RA_DNS;
        case CURLE_PEER_FAILED_VERIFICATION:
        case CURLE_SSL_CONNECT_ERROR: return RA_TLS;
        case CURLE_ABORTED_BY_CALLBACK: return RA_CANCELLED;
        default: return RA_NETWORK;
    }
}

RAResult ra_tunnel_get(const char *url, const char *interface_name,
                       unsigned char *body, size_t capacity, size_t *length,
                       long *status, long *retry_after, RACancelled cancelled) {
    return ra_tunnel_get_resolved(url, interface_name, NULL, body, capacity, length, status, retry_after, cancelled);
}
