#include <stdint.h>

struct ethsock;

struct ethsock *ethsock_create(const char *interface, uint16_t protocol);
int ethsock_close(struct ethsock *sock);
int ethsock_send(struct ethsock *sock, void *buf, size_t len);
ssize_t ethsock_recv(struct ethsock *sock, void *buf, size_t len);
int ethsock_set_timeout(struct ethsock *sock, unsigned msec);
uint8_t *ethsock_get_hwaddr(struct ethsock *sock);
int ethsock_list_all(void);
