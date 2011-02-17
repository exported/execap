/*  execap -- Snarf Windows executables off the wire (Driftnet for EXEs)
 *  Copyright (C) 2010-2011, Brandon Enright <bmenrigh@ucsd.edu>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef EXECAP_H
#define EXECAP_H 1


/* ===
 * General includes
 * ===
 */
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <openssl/md5.h>

/* ===
 * Threading
 * ===
 */
#include <pthread.h>

/* ===
 * Network includes
 * ===
 */
/* We want to favor the BSD structs over the Linux ones */
#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>


/* ===
 * Knobs to turn
 * ===
 */
#define CAPTUREBUFFER 256 * 1024 * 1024 /* 2 seconds at a Gigabit */
#define SNAPLEN 65535
#define PCAPTIMEOUT 1000

#define ETH_HDR_SIZE 14
#define MIN_IP_HDR_SIZE 20
#define MIN_TCP_HDR_SIZE 20

#define MAX_CONN_LEN 2 * 1024 * 1024
#define MAX_CONN_FRAG 6
#define MAX_SEQ_DIST 32 * 1024 * 1024

#define MAX_EXE_DEPTH 4096

#define MAX_LOG_LINE 256
#define MAX_FILE_LEN 256
/* The log file handle */
int log_fd;

pcap_t *pch; /* PCAP handle must be global so signal handler can access it */
int terminate = 0;

#define TREES 65536 /* Don't change unless you know what you're doing */
struct hash_node_tree {
  struct pavl_table *tree;
  pthread_mutex_t tree_mutex;
};
struct hash_node_tree connection_tree[TREES];

#define PURGE_RATE 10 /* Seconds */

/* Some packet statistics */
time_t stats_start, stats_end;
unsigned long long stats_packets = 0;
unsigned long long stats_bytes = 0;

/* The arg parsing vars in getopt */
extern char *optarg;
extern int optind, opterr, optopt;


/* ===
 * Macros
 * ===
 */

/* This macro checks if A > B in the strange world of 32 bit integer wrap
 * For example, 5 > 2**32 - 1 is true
 * This macro is nice and fast because it is branch-free.
 * You can only pass in 32 bit integers!
 */
#define GT_32(a, b) (((a) > (b)) ^					\
		     ((((a) > (b)) & (((a) - (b)) > 0x7FFFFFFF)) |	\
		      (((b) > (a)) & (((b) - (a)) > 0x7FFFFFFF))))
#define LT_32(a, b) (GT_32(b, a))
#define GTE_32(a, b) (((a) == (b)) | (GT_32(a, b)))
#define LTE_32(a, b) (((a) == (b)) | (LT_32(a, b)))

#define ROL16(x,a) ((((x) << (a))  & 0xFFFF) | (((x) & 0xFFFF) >> (16 - (a))))

#define TREEHASH(c) (((((struct connection *)(c))->ip_src.s_addr) &	\
		      0xFFFF) ^						\
		     (ROL16((((((struct connection *)(c))->ip_src.s_addr) & \
			      0xFFFF0000) >> 16), 7)) ^			\
		     ((((struct connection *)(c))->ip_dst.s_addr) &	\
		      0xFFFF) ^						\
		     (ROL16((((((struct connection *)(c))->ip_dst.s_addr) & \
			      0xFFFF0000) >> 16), 13)) ^		\
		     (((struct connection *)(c))->th_sport) ^		\
		     (ROL16((((struct connection *)(c))->th_dport), 3)))


/* For checking if two SEQ numbers are too far appart */
#define EXCEEDS_DIST(a, b) (((((a) - (b)) & 0xFFFFFFFF) > MAX_SEQ_DIST) & \
			    ((((a) - (b)) & 0xFFFFFFFF) <		\
			     (0xFFFFFFFF - MAX_SEQ_DIST)))



/* ===
 * Struct definitions
 * ===
 */
struct packet_data {
  struct packet_data *next;
  tcp_seq seq;
  size_t datalen;
  u_char searched;
  u_char *data;
};

struct connection {
  struct in_addr ip_src;
  struct in_addr ip_dst;
  u_short th_sport;
  u_short th_dport;
  time_t last_seen;
  u_char abandon;
  size_t total_data;
  size_t search_offset;
  struct packet_data *datalist;
};


/* ===
 * Function prototypes
 * ===
 */

/* execap.c */
int main(int argc, char * const argv[]);
void packet_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void sig_stop_pcap(int);
int compare_connections(const void *, const void *, void *);
void * copy_connection(const void *, void *);
void abandon_packets(struct packet_data *);
void md5_hex(const u_char *, const size_t, u_char *);
void *thread_connection_reaper(void *);

/* findexe.c */
extern u_char * find_exe(const u_char *, const size_t, u_char **, size_t *,
			 u_short *, u_short *, u_short *);


#endif /* end ifdef EXECAP_H */
