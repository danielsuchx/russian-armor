#include "ArmorIPC.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int ra_engine_exchange(const char *path, unsigned int timeout_seconds, const unsigned char *request, size_t request_length,
                       unsigned char *response, size_t capacity, size_t *response_length) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof(address.sun_path) || request_length > 1024 * 1024) return -1;
    struct stat info;
    if (lstat(path, &info) != 0 || !S_ISSOCK(info.st_mode) || info.st_uid != getuid() || (info.st_mode & 077)) return -2;
    strcpy(address.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -3;
    int no_sigpipe = 1;
    struct timeval receive_timeout = {.tv_sec = timeout_seconds}, send_timeout = {.tv_sec = 10};
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) { close(fd); return -4; }
    size_t sent = 0;
    while (sent < request_length) {
        ssize_t count = write(fd, request + sent, request_length - sent);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return -5; }
        sent += count;
    }
    if (write(fd, "\n", 1) != 1) { close(fd); return -5; }
    *response_length = 0;
    while (*response_length < capacity) {
        ssize_t count = read(fd, response + *response_length, capacity - *response_length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); return -6; }
        unsigned char *end = memchr(response + *response_length, '\n', (size_t)count);
        *response_length += (size_t)count;
        if (end) { *response_length = (size_t)(end - response); close(fd); return 0; }
    }
    close(fd); return -7;
}
