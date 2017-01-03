#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include <netinet/if_ether.h>
#include <net/ethernet.h>

static int verbose = 0;

static void
usage(void)
{
	fprintf(stderr, "Usage: spoofarp [-i interface]\n");
	exit(1);
}

static int
arp_send(libnet_t *l, int op, u_int8_t *sha,
	 in_addr_t spa, u_int8_t *tha, in_addr_t tpa)
{
	int retval;

	libnet_autobuild_arp(op, sha, (u_int8_t *)&spa,
			     tha, (u_int8_t *)&tpa, l);
	libnet_build_ethernet(tha, sha, ETHERTYPE_ARP, NULL, 0, l, 0);

	if (verbose)
		fprintf(stderr, "%s ",
			ether_ntoa((struct ether_addr *)sha));

	if (op == ARPOP_REQUEST && verbose) {
		fprintf(stderr, "%s 0806 42: arp who-has %s tell %s\n",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(tpa, LIBNET_DONT_RESOLVE),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
	} else if (verbose) {
		fprintf(stderr, "%s 0806 42: arp reply %s is-at ",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
		fprintf(stderr, "%s\n",
			ether_ntoa((struct ether_addr *)sha));
	}
	retval = libnet_write(l);
	if (retval && verbose)
		fprintf(stderr, "%s", libnet_geterror(l));

	libnet_clear_packet(l);

	return retval;
}

int
main(int argc, char *argv[])
{
	libnet_t *l;
	struct in_addr spoof_ip, target_ip;
	char *intf;
	struct ether_addr spoof_mac, target_mac;
	extern char *optarg;
	extern int optind;
	char pcap_ebuf[PCAP_ERRBUF_SIZE];
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
	int c;
	
	intf = NULL;

	while ((c = getopt(argc, argv, "i:h")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (intf == NULL && (intf = pcap_lookupdev(pcap_ebuf)) == NULL)
		errx(1, "%s", pcap_ebuf);
	
	if ((l = libnet_init(LIBNET_LINK, intf, libnet_ebuf)) == NULL)
		errx(1, "%s", libnet_ebuf);

	(void) ether_aton_r("ff:ff:ff:ff:ff:ff", &target_mac);
	(void) ether_aton_r("3c:97:12:00:00:00", &spoof_mac);
	(void) inet_aton("10.0.0.0", &target_ip);
	(void) inet_aton("192.168.0.0", &spoof_ip);

	for (;;) {
		uint32_t src_random, dst_random;

		/* generate random numbers, for random src/dst */
		src_random = arc4random();
		dst_random = arc4random();

		/*
		 * Last three octets of the target IP and spoof MAC
		 * should be the same - just to aid in debugging.
		 */
		bcopy(&src_random, ((char *) &spoof_mac) + 3, 3);
		bcopy((char *) &src_random, ((char *) &target_ip) + 1, 3);

		/* for now, separate.. */
		bcopy((char *) &dst_random, ((char *) &spoof_ip) + 2, 2);

		arp_send(l, ARPOP_REQUEST,
		    (u_int8_t *) &spoof_mac, spoof_ip.s_addr,
		    (u_int8_t *)&target_mac, target_ip.s_addr);

		/* Sleep 1ms */
		usleep(1000);
	}
	/* NOTREACHED */
	
	exit(0);
}
