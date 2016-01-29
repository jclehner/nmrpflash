#include <stdint.h>

struct rawsock;

struct rawsock *rawsock_create(const char *interface);
int rawsock_close(struct rawsock *sock);
int rawsock_send(struct rawsock *sock, uint8_t *buffer, size_t size);
int rawsock_recv(struct rawsock *sock, uint8_t **buffer, unsigned *size);
int rawsock_set_timeout(struct rawsock *sock, unsigned msec);
