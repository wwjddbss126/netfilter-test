#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

int flag = 0;
char *target = "test.gilgil.net";

void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}


void dump2(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

void dump(unsigned char* buf, int size) {
	unsigned char IPstr[21];
	unsigned char TCPstr[21];
	unsigned char HOSTstr[100];

	int i;
	printf("================== IP Header ===================\n");
	for (i = 0; i < 20; i++) {
		IPstr[i] = buf[i];
	}
	printf("Source IP: ");
	for (i = 12; i <16; i++){
		if (i != 15)
			printf("%d.", IPstr[i]);
		else
			printf("%d", IPstr[i]);
	}
	printf("\nDestination IP: ");
	for (i = 16; i <20; i++){
		if (i != 19)
			printf("%d.", IPstr[i]);
		else
			printf("%d", IPstr[i]);	}
	printf("\n");

	printf("================== TCP Header ==================\n");
	int cnt1 = 0;
	for (i = 20; i < 40; i++) {
		TCPstr[cnt1] = buf[i];
		printf("%02x ", TCPstr[cnt1]);
		cnt1++;
	}
	printf("\nSource PORT: ");
	for (i = 0; i <2; i++){
		printf("%d, %02x ", IPstr[i], IPstr[i]);
	}
	printf("\nDestination PORT: ");
	for (i = 2; i <4; i++){
		printf("%d, %02x ", IPstr[i], IPstr[i]);
	}
	printf("\n");
	printf("================== Host Info ==================");
	int cnt2 = 0;
	for (i = 40; i < size; i++) {
		HOSTstr[cnt2] = buf[i];
		if ((i+40) != 0 && (i+40) % 16 == 0)
			printf("\n");
		printf("%02X ", HOSTstr[cnt2]);
		cnt2++;
	}
	printf("\n");

	for (i=0; i<sizeof(HOSTstr)-sizeof(target); i++){
		if (HOSTstr[i] == target[0]){
			int checksum = 0;
			int cnt = 1;
			for (int n = i+1; sizeof(target); n++){
				if (HOSTstr[n] != target[cnt]){
					checksum = 1;
					break;
				}
				cnt++;
			if (checksum == 0){
				flag = 1;
				printf("Detected!!!!\n");
				break;
			}
			}
		}

	}
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d\n", ret);
		dump(data, ret); // ipv4 start pointer
	}

	fputc('\n', stdout);

	return id;
}
 

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(flag == 0){
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	// 유해 사이트: flag == 1
	else if(flag == 1){ 
		printf("Netfilter blocked this site!!\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

	}
}

int main(int argc, char **argv)
{
	if (argc != 2){
        usage();
        return -1;
    }
    else{
    	target = argv[1];
    }

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
