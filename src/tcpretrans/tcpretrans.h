// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __TCPRETRANS_H
#define __TCPRETRANS_H

/* The maximum number of items in maps */
#define MAX_ENTRIES	8192

#define RETRANSMIT	1
#define TLP		2

struct ipv4_flow_key_t {
	__u32 saddr;
	__u32 daddr;
	__u16 lport;
	__u16 dport;
};

struct ipv6_flow_key_t {
	__u8 saddr[16];
	__u8 daddr[16];
	__u16 lport;
	__u16 dport;
};