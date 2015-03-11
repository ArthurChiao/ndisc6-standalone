/*
 * ndisc.c - ICMPv6 neighbour discovery command line tool
 */

/*************************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                           *
 *  This program is free software: you can redistribute and/or modify    *
 *  it under the terms of the GNU General Public License as published by *
 *  the Free Software Foundation, versions 2 or 3 of the license.        *
 *                                                                       *
 *  This program is distributed in the hope that it will be useful,      *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *  GNU General Public License for more details.                         *
 *                                                                       *
 *  You should have received a copy of the GNU General Public License    *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>. *
 *************************************************************************/

#include "gettext.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h> /* div() */
#include <inttypes.h> /* uint8_t */
#include <limits.h> /* UINT_MAX */
#include <locale.h>
#include <stdbool.h>

#include <errno.h> /* EMFILE */
#include <sys/types.h>
#include <unistd.h> /* close() */
#include <time.h> /* clock_gettime() */
#include <poll.h> /* poll() */
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>

# include <getopt.h>

#include <netdb.h> /* getaddrinfo() */
#include <arpa/inet.h> /* inet_ntop() */
#include <net/if.h> /* if_nametoindex() */

# include <ifaddrs.h> /* getifaddrs and freeifaddrs*/

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/ioctl.h>

#include "gettime.h"

enum ndisc_flags {
    NDISC_VERBOSE1=0x1,
    NDISC_VERBOSE2=0x2,
    NDISC_VERBOSE3=0x3,
    NDISC_VERBOSE =0x3,
    NDISC_NUMERIC =0x4,
    NDISC_SINGLE  =0x8,
};


#ifndef IPV6_RECVHOPLIMIT
/* Using obsolete RFC 2292 instead of RFC 3542 */
# define IPV6_RECVHOPLIMIT IPV6_HOPLIMIT
#endif

/* Version number of package */
#define PACKAGE "ndisc6"
#define VERSION "1.0.3"

#define clock_nanosleep( c, f, d, r ) nanosleep( d, r )

static int
getipv6byname (const char *name, const char *ifname, int numeric,
               struct sockaddr_in6 *addr)
{
	struct addrinfo hints, *res;
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_DGRAM; /* dummy */
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;

	int val = getaddrinfo (name, NULL, &hints, &res);
	if (val) {
		fprintf (stderr, "%s: %s\n", name, gai_strerror (val));
		return -1;
	}

	memcpy (addr, res->ai_addr, sizeof (struct sockaddr_in6));
	freeaddrinfo (res);

	val = if_nametoindex (ifname);
	if (val == 0) {
		perror (ifname);
		return -1;
	}
	addr->sin6_scope_id = val;

	return 0;
}


static inline int
sethoplimit (int fd, int value)
{
	return (setsockopt (fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	                    &value, sizeof (value))
	     || setsockopt (fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
	                    &value, sizeof (value))) ? -1 : 0;
}

static int
setsourceip (int fd, const char *src, const char *ifname, int flags)
{
	struct sockaddr_in6 addr;

	if (getipv6byname (src, ifname, (flags & NDISC_NUMERIC) ? 1 : 0, &addr))
		return -1;

	if (bind (fd, (const struct sockaddr *)&addr, sizeof (addr))) {
		perror (src);
		return -1;
	}
	return 0;
}


static void
printmacaddress (const uint8_t *ptr, size_t len)
{
	while (len > 1) {
		printf ("%02X:", *ptr);
		ptr++;
		len--;
	}

	if (len == 1)
		printf ("%02X\n", *ptr);
}


static int
getmacaddress (const char *ifname, uint8_t *addr)
{
# ifdef SIOCGIFHWADDR
	struct ifreq req;
	memset (&req, 0, sizeof (req));

	if (((unsigned)strlen (ifname)) >= (unsigned)IFNAMSIZ)
		return -1; /* buffer overflow = local root */
	strcpy (req.ifr_name, ifname);

	int fd = socket (AF_INET6, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;

	if (ioctl (fd, SIOCGIFHWADDR, &req)) {
		perror (ifname);
		close (fd);
		return -1;
	}
	close (fd);

	memcpy (addr, req.ifr_hwaddr.sa_data, 6);
	return 0;
# else
	/* No SIOCGIFHWADDR, which seems Linux specific. */
	struct ifaddrs *ifa = NULL, *ifp;
	getifaddrs(&ifa);
	ifp = ifa;    /* preserve the address of ifa to free memory later */
	while (ifp != NULL) {
		if (ifp->ifa_addr->sa_family == AF_LINK && strcmp(ifp->ifa_name, ifname) == 0) {
			const struct sockaddr_dl* sdl = (const struct sockaddr_dl*) ifp->ifa_addr;
			memcpy(addr, sdl->sdl_data + sdl->sdl_nlen, 6);
			freeifaddrs(ifa);
			return 0;
		}
		ifp = ifp->ifa_next;
	}
	freeifaddrs(ifa);
	(void)ifname;
	(void)addr;
	return -1;
# endif
}


static const uint8_t nd_type_advert = ND_NEIGHBOR_ADVERT;
static const unsigned nd_delay_ms = 1000;
static const unsigned ndisc_default = NDISC_VERBOSE1 | NDISC_SINGLE;
static const char ndisc_usage[] = "Usage: %s [options] <IPv6 address> <interface>\n"
	"Looks up an on-link IPv6 node link-layer address (Neighbor Discovery)\n";
static const char ndisc_dataname[] = "link-layer address";

typedef struct {
	struct nd_neighbor_solicit hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[6];
} solicit_packet;


static ssize_t
build_solicitation (solicit_packet *ns, struct sockaddr_in6 *tgt, const char *ifname)
{
	/* builds ICMPv6 Neighbor Solicitation packet */
	ns->hdr.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	ns->hdr.nd_ns_code = 0;
	ns->hdr.nd_ns_cksum = 0; /* computed by the kernel */
	ns->hdr.nd_ns_reserved = 0;
	memcpy (&ns->hdr.nd_ns_target, &tgt->sin6_addr, 16);

	/* determines actual multicast destination address */
	memcpy (tgt->sin6_addr.s6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00"
	                                "\x00\x00\x00\x01\xff", 13);

	/* gets our own interface's link-layer address (MAC) */
	if (getmacaddress (ifname, ns->hw_addr))
		return sizeof (ns->hdr);

	ns->opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	ns->opt.nd_opt_len = 1; /* 8 bytes */
	return sizeof (*ns);
}

static int
parseadv (const uint8_t *buf, size_t len, const struct sockaddr_in6 *tgt,
          bool verbose)
{
	const struct nd_neighbor_advert *na =
		(const struct nd_neighbor_advert *)buf;
	const uint8_t *ptr;

	/* checks if the packet is a Neighbor Advertisement, and
	 * if the target IPv6 address is the right one */
	if ((len < sizeof (struct nd_neighbor_advert))
	 || (na->nd_na_type != ND_NEIGHBOR_ADVERT)
	 || (na->nd_na_code != 0)
	 || memcmp (&na->nd_na_target, &tgt->sin6_addr, 16))
		return -1;

	len -= sizeof (struct nd_neighbor_advert);

	/* looks for Target Link-layer address option */
	ptr = buf + sizeof (struct nd_neighbor_advert);

	while (len >= 8)
	{
		uint16_t optlen;

		optlen = ((uint16_t)(ptr[1])) << 3;
		if (optlen == 0)
			break; /* invalid length */

		if (len < optlen) /* length > remaining bytes */
			break;
		len -= optlen;


		/* skips unrecognized option */
		if (ptr[0] != ND_OPT_TARGET_LINKADDR)
		{
			ptr += optlen;
			continue;
		}

		/* Found! displays link-layer address */
		ptr += 2;
		optlen -= 2;
		if (verbose)
			fputs ("Target link-layer address: ", stdout);

		printmacaddress (ptr, optlen);
		return 0;
	}

	return -1;
}

static ssize_t
recvfromLL (int fd, void *buf, size_t len, int flags,
            struct sockaddr_in6 *addr)
{
	char cbuf[CMSG_SPACE (sizeof (int))];
	struct iovec iov =
	{
		.iov_base = buf,
		.iov_len = len
	};
	struct msghdr hdr =
	{
		.msg_name = addr,
		.msg_namelen = sizeof (*addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	ssize_t val = recvmsg (fd, &hdr, flags);
	if (val == -1)
		return val;

	/* ensures the hop limit is 255 */
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR (&hdr);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR (&hdr, cmsg))
	{
		if ((cmsg->cmsg_level == IPPROTO_IPV6)
		 && (cmsg->cmsg_type == IPV6_HOPLIMIT))
		{
			if (255 != *(int *)CMSG_DATA (cmsg))
			{
				// pretend to be a spurious wake-up
				errno = EAGAIN;
				return -1;
			}
		}
	}

	return val;
}


static ssize_t
recvadv (int fd, const struct sockaddr_in6 *tgt, unsigned wait_ms,
         unsigned flags)
{
	struct timespec end;
	unsigned responses = 0;

	/* computes deadline time */
	mono_gettime (&end);
	{
		div_t d;

		d = div (wait_ms, 1000);
		end.tv_sec += d.quot;
		end.tv_nsec += d.rem * 1000000;
	}

	/* receive loop */
	for (;;)
	{
		/* waits for reply until deadline */
		struct timespec now;
		ssize_t val = 0;

		mono_gettime (&now);
		if (end.tv_sec >= now.tv_sec)
		{
			val = (end.tv_sec - now.tv_sec) * 1000
				+ (int)((end.tv_nsec - now.tv_nsec) / 1000000);
			if (val < 0)
				val = 0;
		}

		val = poll (&(struct pollfd){ .fd = fd, .events = POLLIN }, 1, val);
		if (val < 0)
			break;

		if (val == 0)
			return responses;

		/* receives an ICMPv6 packet */
		// TODO: use interface MTU as buffer size
		union
		{
			uint8_t  b[1460];
			uint64_t align;
		} buf;
		struct sockaddr_in6 addr;

		val = recvfromLL (fd, &buf, sizeof (buf), MSG_DONTWAIT, &addr);
		if (val == -1)
		{
			if (errno != EAGAIN)
				perror ("Receiving ICMPv6 packet");
			continue;
		}

		/* ensures the response came through the right interface */
		if (addr.sin6_scope_id
		 && (addr.sin6_scope_id != tgt->sin6_scope_id))
			continue;

		if (parseadv (buf.b, val, tgt, (flags & NDISC_VERBOSE) != 0) == 0)
		{
			if (flags & NDISC_VERBOSE)
			{
				char str[INET6_ADDRSTRLEN];

				if (inet_ntop (AF_INET6, &addr.sin6_addr, str,
						sizeof (str)) != NULL)
					printf (" from %s\n", str);
			}

			if (responses < INT_MAX)
				responses++;

			if (flags & NDISC_SINGLE)
				return 1 /* = responses */;
		}
	}

	return -1; /* error */
}


static int fd;

static int
ndisc (const char *name, const char *ifname, unsigned flags, unsigned retry,
       unsigned wait_ms, const char *source)
{
	struct sockaddr_in6 tgt;

	if (fd == -1) {
		perror ("Raw IPv6 socket");
		return -1;
	}

	fcntl (fd, F_SETFD, FD_CLOEXEC);

	/* set ICMPv6 filter */
	{
		struct icmp6_filter f;

		ICMP6_FILTER_SETBLOCKALL (&f);
		ICMP6_FILTER_SETPASS (nd_type_advert, &f);
		setsockopt (fd, IPPROTO_ICMPV6, ICMP6_FILTER, &f, sizeof (f));
	}

	setsockopt (fd, SOL_SOCKET, SO_DONTROUTE, &(int){ 1 }, sizeof (int));

	/* sets Hop-by-hop limit to 255 */
	sethoplimit (fd, 255);
	setsockopt (fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
	            &(int){ 1 }, sizeof (int));

	/* sets source address */
	if ((source != NULL) && setsourceip (fd, source, ifname, flags))
		goto error;

	/* resolves target's IPv6 address */
	if (getipv6byname (name, ifname, (flags & NDISC_NUMERIC) ? 1 : 0, &tgt))
		goto error;
	else {
		char s[INET6_ADDRSTRLEN];

		inet_ntop (AF_INET6, &tgt.sin6_addr, s, sizeof (s));
		if (flags & NDISC_VERBOSE)
			printf ("Soliciting %s (%s) on %s...\n", name, s, ifname);
	}

	{
		solicit_packet packet;
		struct sockaddr_in6 dst;
		ssize_t plen;

		memcpy (&dst, &tgt, sizeof (dst));
		plen = build_solicitation (&packet, &dst, ifname);
		if (plen == -1)
			goto error;

		while (retry > 0) {
			/* sends a Solitication */
			if (sendto (fd, &packet, plen, 0, (const struct sockaddr *)&dst,
			            sizeof (dst)) != plen) {
				perror ("Sending ICMPv6 packet");
				goto error;
			}
			retry--;

			/* receives an Advertisement */
			ssize_t val = recvadv (fd, &tgt, wait_ms, flags);
			if (val > 0) {
				close (fd);
				return 0;
			}
			else if (val == 0) {
				if (flags & NDISC_VERBOSE)
					puts ("Timed out.");
			}
			else
				goto error;
		}
	}

	close (fd);
	if (flags & NDISC_VERBOSE)
		puts ("No response.");
	return -2;

error:
	close (fd);
	return -1;
}


static int
quick_usage (const char *path)
{
	fprintf (stderr, "Try \"%s -h\" for more information.\n", path);
	return 2;
}


static int
usage (const char *path)
{
	printf (gettext (ndisc_usage), path);

    printf ("\n"
                "  -1, --single   display first response and exit\n"
                "  -h, --help     display this help and exit\n"
                "  -m, --multiple wait and display all responses\n"
                "  -n, --numeric  don't resolve host names\n"
                "  -q, --quiet    only print the %s (mainly for scripts)\n"
                "  -r, --retry    maximum number of attempts (default: 3)\n"
                "  -s, --source   specify source IPv6 address\n"
                "  -V, --version  display program version and exit\n"
                "  -v, --verbose  verbose display (this is the default)\n"
                "  -w, --wait     how long to wait for a response [ms] (default: 1000)\n"
                "\n", gettext (ndisc_dataname));

    return 0;
}

static int
version (void)
{
	printf (
"ndisc6: IPv6 Neighbor/Router Discovery userland tool %s (%s)\n", VERSION, "$Rev$");

	puts ("Written by Remi Denis-Courmont\n");

	printf ("Copyright (C) %u-%u Remi Denis-Courmont\n", 2004, 2007);
	puts ("This is free software; see the source for copying conditions.\n"
	        "There is NO warranty; not even for MERCHANTABILITY or\n"
	        "FITNESS FOR A PARTICULAR PURPOSE.\n");
	return 0;
}

int
main (int argc, char *argv[])
{
	fd = socket (PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	int errval = errno;

	/* Drops root privileges (if setuid not run by root).
	 * Also make sure the socket is not STDIN/STDOUT/STDERR. */
	if (setuid (getuid ()) || ((fd >= 0) && (fd <= 2)))
		return 1;

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, "/usr/local/share/locale/");
	textdomain (PACKAGE);

	int val;
	unsigned retry = 3, flags = ndisc_default, wait_ms = nd_delay_ms;
	const char *hostname, *ifname, *source = NULL;

	while ((val = getopt(argc, argv, "1hmnqr:s:Vvw:")) != EOF) {
		switch (val) {
			case '1':
				flags |= NDISC_SINGLE;
				break;
			case 'h':
				return usage (argv[0]);
			case 'm':
				flags &= ~NDISC_SINGLE;
				break;
			case 'n':
				flags |= NDISC_NUMERIC;
				break;
			case 'q':
				flags &= ~NDISC_VERBOSE;
				break;
			case 'r': {
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
				retry = l;
				break;
			}
			case 's':
				source = optarg;
				break;
			case 'V':
				return version ();
			case 'v':
				/* NOTE: assume NDISC_VERBOSE occupies low-order bits */
				if ((flags & NDISC_VERBOSE) < NDISC_VERBOSE)
					flags++;
				break;
			case 'w': {
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if (*end || l > UINT_MAX)
					return quick_usage (argv[0]);
				wait_ms = l;
				break;
			}
			case '?':
			default:
				return quick_usage (argv[0]);
		}
	}

	if (optind < argc) {
		hostname = argv[optind++];

		if (optind < argc)
			ifname = argv[optind++];
		else
			ifname = NULL;
	}
	else
		return quick_usage (argv[0]);

	if ((optind != argc) || (ifname == NULL))
		return quick_usage (argv[0]);

	errno = errval; /* restore socket() error value */
	return -ndisc (hostname, ifname, flags, retry, wait_ms, source);
}
