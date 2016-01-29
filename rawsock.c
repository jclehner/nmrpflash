#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

struct rawsock
{
	pcap_t *pcap;
	struct timeval timeout;
	int fd;
};

struct rawsock *rawsock_create(const char *interface)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	struct rawsock *sock;
	int err;

	sock = malloc(sizeof(struct rawsock));
	if (!sock) {
		perror("malloc");
		return NULL;
	}

	errbuf[0] = '\0';

	sock->pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (!sock->pcap) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		goto cleanup_malloc;
	}

	if (*errbuf) {
		fprintf(stderr, "Warning: %s.\n", errbuf);
	}

	if (pcap_datalink(sock->pcap) != DLT_EN10MB) {
		fprintf(stderr, "Interface %s not supported.\n", interface);
		goto cleanup_pcap;
	}

	err = pcap_compile(sock->pcap, &fp, "ether proto 0x0912", 0,
			PCAP_NETMASK_UNKNOWN);
	if (err) {
		pcap_perror(sock->pcap, "pcap_compile");
		goto cleanup_pcap;
	}

	if ((err = pcap_setfilter(sock->pcap, &fp))) {
		pcap_perror(sock->pcap, "pcap_setfilter");
		goto cleanup_pcap;
	}

	sock->fd = pcap_get_selectable_fd(sock->pcap);
	if (sock->fd == -1) {
		fprintf(stderr, "No selectable file descriptor available.\n");
		goto cleanup_pcap;
	}

	return sock;

cleanup_pcap:
	pcap_close(sock->pcap);
cleanup_malloc:
	free(sock);
	return NULL;
}

int rawsock_recv(struct rawsock *sock, uint8_t **buffer, unsigned *size)
{
	struct pcap_pkthdr* hdr;
	int status;
	fd_set fds;

	if (sock->timeout.tv_sec || sock->timeout.tv_usec) {
		FD_ZERO(&fds);
		FD_SET(sock->fd, &fds);

		status = select(sock->fd + 1, &fds, NULL, NULL, &sock->timeout);
		if (status == -1) {
			perror("select");
			return -1;
		} else if (status == 0) {
			return 1;
		}
	}

	status = pcap_next_ex(sock->pcap, &hdr, (const u_char**)buffer);
	switch (status) {
		case 1:
			status = 0;
			*size = hdr->caplen;
			break;
		case 0:
			status = 1;
			break;
		case -1:
			pcap_perror(sock->pcap, "pcap_next_ex");
			status = -1;
			break;
		default:
			fprintf(stderr, "pcap_next_ex: returned %d.\n", status);
			status = -1;
			break;
	}

	return status;
}

int rawsock_send(struct rawsock *sock, uint8_t *buffer, size_t size)
{
#if defined(_WIN32) || defined(_WIN64)
	if (pcap_sendpacket(sock->pcap, buffer, size) == 0) {
		return 0;
	} else {
		pcap_perror(sock->pcap, "pcap_sendpacket");
		return -1;
	}
#else
	if (pcap_inject(sock->pcap, buffer, size) != size) {
		return 0;
	} else {
		pcap_perror(sock->pcap, "pcap_inject");
		return -1;
	}
#endif
}

int rawsock_close(struct rawsock *sock)
{
	pcap_close(sock->pcap);
	free(sock);
	return 0;
}

int rawsock_set_timeout(struct rawsock *sock, unsigned msec)
{
	sock->timeout.tv_sec = msec / 1000;
	sock->timeout.tv_usec = (msec % 1000) * 1000;
	return 0;
}
