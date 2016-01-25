#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct ethsock
{
	int fd;
	struct timeval timeout;
};

static int init_filter(struct ethsock *sock, int protocol, int mtu)
{
	struct bpf_program prog;
	struct bpf_insn insns[] = {
			BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, protocol, 0, 1),
			BPF_STMT(BPF_RET+BPF_K, mtu),
			BPF_STMT(BPF_RET+BPF_K, 0)
     };

	prog.bf_insns = insns;
	prog.bf_len = sizeof(insns) / sizeof(insns[0]);

	if (ioctl(sock->fd, BIOCSETFNR, &prog) != 0) {
		perror("ioctl(BIOCSETFNR)");
		return -1;
	}

	return 0;
}

static int get_mtu(struct ifreq *ifr)
{
	int fd, stat;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	stat = ioctl(fd, SIOCGIFMTU, ifr);
	if (stat < 0) {
		perror("ioctl(SIOCGIFMTU)");
		stat = -1;
	} else {
		stat = 0;
	}

	close(fd);
	return stat;
}

int ethsock_create(struct ethsock *sock, const char *interface, int protocol)
{
	struct ifreq ifr;
	struct bpf_program bf;
	int i, val;
	char buf[12];

	for (i = 0; i < 100; ++i) {
		sprintf(buf, "/dev/bpf%d", i);
		sock->fd = open(buf, O_RDWR);
		if (sock->fd != -1) {
			break;
		}
	}

	if (sock->fd == -1) {
		fprintf(stderr, "Failed to open bpf device\n");
		return -1;
	}

	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(sock->fd, BIOCSETIF, &ifr) != 0) {
		perror("ioctl(BIOCSETIF)");
		return -1;
	}

	val = 1;

	if (ioctl(sock->fd, BIOCIMMEDIATE, &val) != 0) {
		perror("ioctl(BIOCIMMEDIATE)");
		return -1;
	}

	if (ioctl(sock->fd, BIOCGBLEN, &val) != 0) {
		perror("ioctl(BIOCGBLEN)");
		return -1;
	}

	if (get_mtu(&ifr) != 0) {
		return -1;
	}

	if (init_filter(sock, protocol, ifr.ifr_mtu) != 0) {
		return -1;
	}

	sock->timeout.tv_sec = 0;
	sock->timeout.tv_usec = 0;

	return 0;
}

int ethsock_close(struct ethsock *sock)
{
	close(sock->fd);
	return 0;
}

int ethsock_set_timeout(struct ethsock *sock, unsigned msec)
{
	sock->timeout.tv_sec = msec / 1000;
	sock->timeout.tv_usec = (msec % 1000) * 1000;
	return 0;
}

ssize_t ethsock_read(struct ethsock *sock, void *buf, size_t size)
{
	struct bpf_hdr *bh;
	ssize_t len;
	fd_set fds;
	int err;

	if (sock->timeout.tv_sec || sock->timeout.tv_usec) {
		FD_ZERO(&fds);
		FD_SET(sock->fd, &fds);

		err = select(sock->fd + 1, &fds, NULL, NULL, &sock->timeout);
		if (err == -1) {
			perror("select");
			return -1;
		} else if (!err) {
			return 0;
		}
	}

	len = read(sock->fd, buf, size);
	if (len < 0) {
		perror("read");
	}

	bh = (struct bpf_hdr*)buf;
	len = MIN(size, bh->bh_datalen);
	memmove(buf, (char*)buf + bh->bh_hdrlen, len);

	return len;
}

int main()
{
	struct ethsock sock;
	ssize_t len;
	char buf[1024];

	if (ethsock_create(&sock, "en0", 0x0912) != 0) {
		return 1;
	}

	ethsock_set_timeout(&sock, 1000);

	len = ethsock_read(&sock, buf, sizeof(buf));
	if (len > 0) {
		write(1, buf, len);
	}

	ethsock_close(&sock);
	return len > 0 ? 0 : 1;
}
