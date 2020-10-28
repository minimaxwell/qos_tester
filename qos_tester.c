/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <pcap.h>

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x11
#define MY_DEST_MAC2	0x22
#define MY_DEST_MAC3	0x33
#define MY_DEST_MAC4	0x44
#define MY_DEST_MAC5	0x55

#define vid_from_tci(tci)	(tci & 0x0fff)
#define dei_from_tci(tci)	((tci & 0x1000) >> 12)
#define pri_from_tci(tci)	((tci & 0xe000) >> 13)

struct vlan_cfg {
	uint16_t id;
	uint8_t pri;
	uint8_t dei;
};

static struct vlan_cfg send_config[] = {
	{.id = 4, .pri = 0},
	{.id = 4, .pri = 0},
	{.id = 4, .pri = 0},
	{.id = 5, .pri = 0},
	{.id = 6, .pri = 7},
	{.id = 4, .pri = 0},
};

struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_tpid;
	__be16		h_tci;
	__be16		h_proto;
};

struct qost_packet {
	struct sockaddr_ll *sock_addr;
	uint8_t *packet_buffer;
	size_t packet_size;
	int vlan;

	uint64_t n_sent;
};

struct qost_sender {
	pthread_t thread;
	bool run;

	int sock_fd;
	const char *iface;
	int if_id;

	struct qost_packet **packets;
	unsigned int n_packets;

	uint64_t sent_cnt[4096];
};

struct qost_snapshot {
	uint64_t	sent_per_vlan[4096];
	uint64_t	received_per_vlan[4096];
	struct timespec	ts;
};

struct qost_monitor {
	const char *iface;
	struct pcap *handle;

	uint64_t received_cnt[4096];
};

struct qost_display {
	pthread_t thread;
	bool run;

	struct qost_monitor *m;
	struct qost_sender *s;

	struct qost_snapshot last_snap;
};

static int qost_get_if_index(int sock_fd, const char *iface)
{
	struct ifreq if_idx;
	int ret;

	memset(&if_idx, 0, sizeof(struct ifreq));

	strncpy(if_idx.ifr_name, iface, IFNAMSIZ-1);

	ret = ioctl(sock_fd, SIOCGIFINDEX, &if_idx);
	if (ret < 0) {
		fprintf(stderr, "SIOCGIFINDEX failed : %d\n", ret);
		return ret;
	}

	return if_idx.ifr_ifindex;
}

static int qost_send_packet(struct qost_sender *s, struct qost_packet *p)
{
	int ret;
	ret = sendto(s->sock_fd, p->packet_buffer, p->packet_size, 0,
		     (struct sockaddr*)p->sock_addr, sizeof(struct sockaddr_ll));
	if (ret < 0) {
		fprintf(stderr, "Error sending packet : %s\n", strerror(errno));
		return ret;
	}

	p->n_sent++;
	s->sent_cnt[p->vlan]++;

	return 0;
}

static struct sockaddr_ll *qost_get_socket_address(struct qost_sender *s)
{
	struct sockaddr_ll *sock_addr = malloc(sizeof(struct sockaddr_ll));
	if (!sock_addr)
		return NULL;

	memset(sock_addr, 0, sizeof(struct sockaddr_ll));

	/* Index of the network device */
	sock_addr->sll_ifindex = s->if_id;
	/* Address length*/
	sock_addr->sll_halen = ETH_ALEN;
	/* Destination MAC */
	sock_addr->sll_addr[0] = MY_DEST_MAC0;
	sock_addr->sll_addr[1] = MY_DEST_MAC1;
	sock_addr->sll_addr[2] = MY_DEST_MAC2;
	sock_addr->sll_addr[3] = MY_DEST_MAC3;
	sock_addr->sll_addr[4] = MY_DEST_MAC4;
	sock_addr->sll_addr[5] = MY_DEST_MAC5;

	return sock_addr;
}

static int qost_craft_vlan_packet(struct qost_sender *s, struct qost_packet *p,
				  int vlan_id, int vlan_pri, int vlan_dei)
{
	struct vlan_ethhdr *vh;
	uint8_t payload[] = {1, 2, 3, 4};
	struct ifreq if_mac;
	int ret, buff_index;

	p->packet_size = sizeof(*vh) + sizeof(payload);

	p->packet_buffer = malloc(p->packet_size);
	if (!p->packet_buffer)
		goto err;

	vh = (struct vlan_ethhdr *)p->packet_buffer;

	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, s->iface, IFNAMSIZ-1);

	ret = ioctl(s->sock_fd, SIOCGIFHWADDR, &if_mac);
	if (ret < 0) {
		fprintf(stderr, "SIOCGIFHWADDR failed : %d\n", ret);
		goto err_free;
	}

	memset(p->packet_buffer, 0, p->packet_size);

	/* Ethernet header */
	vh->h_source[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	vh->h_source[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	vh->h_source[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	vh->h_source[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	vh->h_source[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	vh->h_source[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	vh->h_dest[0] = MY_DEST_MAC0;
	vh->h_dest[1] = MY_DEST_MAC1;
	vh->h_dest[2] = MY_DEST_MAC2;
	vh->h_dest[3] = MY_DEST_MAC3;
	vh->h_dest[4] = MY_DEST_MAC4;
	vh->h_dest[5] = MY_DEST_MAC5;

	/* Ethertype field */
	vh->h_proto = htons(ETH_P_IP);
	vh->h_tpid = htons(ETH_P_8021Q);
	vh->h_tci = htons((vlan_pri << 13) | (vlan_dei << 12) | vlan_id);
	buff_index = sizeof(struct vlan_ethhdr);

	/* Copy the payload */
	memcpy(&p->packet_buffer[buff_index], payload, sizeof(payload));

	p->vlan = vlan_id;

	return 0;

err_free:
	free(p->packet_buffer);
err:
	p->packet_size = 0;

	return -1;
}

static int qost_open_sock()
{
	int sock_fd, ret;

	sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sock_fd < 0)
		fprintf(stderr, "Error opening socket : %s", strerror(errno));

	return sock_fd;
}

static void *qost_sender_thread(void *data)
{
	struct qost_sender *s = (struct qost_sender *)data;
	int i, ret;

	while (s->run) {
		for(i = 0; i < s->n_packets && s->run; i++) {
			ret = qost_send_packet(s, s->packets[i]);
			if (ret) {
				s->run = false;
			}
		}
	}
}

static int qost_start_sender_thread(struct qost_sender *s)
{
	s->run = true;

	if (pthread_create(&s->thread, NULL, qost_sender_thread, s)) {
		fprintf(stderr, "Couldn't start sender thread\n");
		return -1;
	}

	return 0;
}

static void qost_stop_sender_thread(struct qost_sender *s)
{
	s->run = false;

	pthread_join(s->thread, NULL);
}

static int qost_sender_init_packets(struct qost_sender *s, struct vlan_cfg *cfg, int n_cfg)
{
	int i;

	s->packets = malloc(n_cfg * sizeof(struct qost_packet *));
	if (!s->packets)
		return -1;

	s->n_packets = n_cfg;

	for (i = 0; i < n_cfg; i++) {
		struct sockaddr_ll *sock_addr;

		sock_addr = qost_get_socket_address(s);
		if (!sock_addr) {
			fprintf(stderr, "Error initializing addr\n");
			return -2;
		}

		s->packets[i] = malloc(sizeof(struct qost_packet));
		if (!s->packets[i])
			return -1;

		memset(s->packets[i], 0, sizeof(*s->packets[i]));

		if (qost_craft_vlan_packet(s, s->packets[i],
					   cfg[i].id, cfg[i].pri, cfg[i].dei)) {
			fprintf(stderr, "Can't craft packet\n");
			return -3;
		}

		s->packets[i]->sock_addr = sock_addr;
	}

	return 0;
}

static int qost_sender_init(struct qost_sender *s, struct vlan_cfg *cfg, int n_cfg)
{
	s->sock_fd = qost_open_sock();
	if (s->sock_fd < 0) {
		fprintf(stderr, "Error opening sock : %d\n", s->sock_fd);
		return -1;
	}

	s->if_id = qost_get_if_index(s->sock_fd, s->iface);
	if (s->if_id < 0) {
		fprintf(stderr, "Error getting if index\n");
		return -1;
	}

	if (qost_sender_init_packets(s, cfg, n_cfg)) {
		fprintf(stderr, "Can't craft packet\n");
		return -3;
	}

	return 0;
}

void qost_display_print_stats(struct qost_display *d,
			      struct qost_snapshot *ss_old,
			      struct qost_snapshot *ss_new)
{
	int i;
	uint64_t elapsed_us = (ss_new->ts.tv_sec * 1000000 + ss_new->ts.tv_nsec / 1000) -
			      (ss_old->ts.tv_sec * 1000000 + ss_old->ts.tv_nsec / 1000);

	for (i = 0; i < 4096; i++) {
		if (ss_new->sent_per_vlan[i]) {
			uint64_t sent_pps = ((ss_new->sent_per_vlan[i] -
					      ss_old->sent_per_vlan[i]) * 1000000) / elapsed_us;

			uint64_t received_pps = ((ss_new->received_per_vlan[i] -
						  ss_old->received_per_vlan[i]) * 1000000) / elapsed_us;

			uint64_t percentage = (received_pps * 100) / sent_pps;

			printf("VLAN %04d : %03d %\t%05d pps sent, %05d pps received\n",
				i, percentage, sent_pps, received_pps);
		}
	}
	printf("\n");

}

void qost_display_take_snapshot(struct qost_display *d, struct qost_snapshot *ss)
{
	/* For now, lockless */
	memcpy(ss->sent_per_vlan, d->s->sent_cnt, sizeof(ss->sent_per_vlan));
	memcpy(ss->received_per_vlan, d->m->received_cnt, sizeof(ss->received_per_vlan));
	clock_gettime(CLOCK_MONOTONIC, &ss->ts);
}

void *qost_display_thread(void *data)
{
	struct qost_display *d = (struct qost_display *)data;
	struct timespec ts;
	struct qost_snapshot ss;

	while (d->run) {
		qost_display_take_snapshot(d, &ss);

		qost_display_print_stats(d, &d->last_snap, &ss);

		memcpy(&d->last_snap, &ss, sizeof(ss));

		sleep(1);
	}

	return NULL;
}

static int qost_start_display_thread(struct qost_display *d)
{
	d->run = true;

	if (pthread_create(&d->thread, NULL, qost_display_thread, d))
		return -1;

	return 0;
}

static int qost_display_init(struct qost_display *d)
{
	memset(&d->last_snap, 0, sizeof(struct qost_snapshot));
	clock_gettime(CLOCK_MONOTONIC, &d->last_snap.ts);

	return 0;
}

static void qost_stop_display_thread(struct qost_display *d)
{
	d->run = false;

	pthread_join(d->thread, NULL);
}

void qost_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header,
			 const u_char *packet_body)
{
	struct qost_monitor *m = (struct qost_monitor *)args;
	struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)packet_body;
	static unsigned long long counter = 0;
	uint16_t tci;

	if (vhdr->h_tpid != htons(ETH_P_8021Q))
		return;

	tci = ntohs(vhdr->h_tci);
	m->received_cnt[vid_from_tci(tci)]++;
}

int qost_monitor_init(struct qost_monitor *m)
{
	char error_buffer[PCAP_ERRBUF_SIZE];

	m->handle = pcap_create(m->iface, error_buffer);
	if (!m->handle) {
		fprintf(stderr, "Error creating capture handle");
		return -1;
	}

	pcap_set_promisc(m->handle, 1);
	pcap_set_snaplen(m->handle, 2048);
	pcap_activate(m->handle);

	return 0;
}

int qost_monitor_loop(struct qost_monitor *m)
{
	pcap_loop(m->handle, 0, qost_packet_handler, (u_char *)m);
}

int main(int argc, char **argv)
{
	struct qost_sender s = {0};
	struct qost_monitor m = {0};
	struct qost_display d = {0};
	int ret;

	s.iface = argv[1];
	if (qost_sender_init(&s, send_config, 6)) {
		fprintf(stderr, "Error initializing sender\n");
		return -1;
	}

	m.iface = argv[2];
	if (qost_monitor_init(&m)) {
		fprintf(stderr, "Error initializing monitor\n");
		return -1;
	}

	d.m = &m;
	d.s = &s;
	if (qost_display_init(&d)) {
		fprintf(stderr, "Error initializing display thread\n");
		return -1;
	}

	if (qost_start_display_thread(&d)) {
		fprintf(stderr, "Error starting display thread\n");
		return -1;
	}

	if (qost_start_sender_thread(&s)) {
		fprintf(stderr, "Error starting sender thread\n");
		return -1;
	}

	qost_monitor_loop(&m);

	qost_stop_sender_thread(&s);
	qost_stop_display_thread(&d);

	return 0;
}
