#include <stdint.h>

struct rawsock;

struct rawsock *rawsock_create(const char *interface, uint16_t protocol);
int rawsock_close(struct rawsock *sock);
int rawsock_send(struct rawsock *sock, void *buf, size_t len);
ssize_t rawsock_recv(struct rawsock *sock, void *buf, size_t len);
int rawsock_set_timeout(struct rawsock *sock, unsigned msec);
