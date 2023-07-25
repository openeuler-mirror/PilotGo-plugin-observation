#ifndef _UAPI_LINUX_IF_LINK_H
#define _UAPI_LINUX_IF_LINK_H

#include <linux/types.h>
#include <linux/netlink.h>

/* This struct should be in sync with struct rtnl_link_stats64 */
struct rtnl_link_stats {
	__u32	rx_packets;
	__u32	tx_packets;
	__u32	rx_bytes;
	__u32	tx_bytes;
	__u32	rx_errors;
	__u32	tx_errors;
	__u32	rx_dropped;
	__u32	tx_dropped;
	__u32	multicast;
	__u32	collisions;
	/* detailed rx_errors: */
	__u32	rx_length_errors;
	__u32	rx_over_errors;
	__u32	rx_crc_errors;
	__u32	rx_frame_errors;
	__u32	rx_fifo_errors;
	__u32	rx_missed_errors;

	/* detailed tx_errors */
	__u32	tx_aborted_errors;
	__u32	tx_carrier_errors;
	__u32	tx_fifo_errors;
	__u32	tx_heartbeat_errors;
	__u32	tx_window_errors;

	/* for cslip etc */
	__u32	rx_compressed;
	__u32	tx_compressed;

	__u32	rx_nohandler;
};
struct rtnl_link_stats64 {
	__u64	rx_packets;
	__u64	tx_packets;
	__u64	rx_bytes;
	__u64	tx_bytes;
	__u64	rx_errors;
	__u64	tx_errors;
	__u64	rx_dropped;
	__u64	tx_dropped;
	__u64	multicast;
	__u64	collisions;

	/* detailed rx_errors: */
	__u64	rx_length_errors;
	__u64	rx_over_errors;
	__u64	rx_crc_errors;
	__u64	rx_frame_errors;
	__u64	rx_fifo_errors;
	__u64	rx_missed_errors;

	/* detailed tx_errors */
	__u64	tx_aborted_errors;
	__u64	tx_carrier_errors;
	__u64	tx_fifo_errors;
	__u64	tx_heartbeat_errors;
	__u64	tx_window_errors;

	/* for cslip etc */
	__u64	rx_compressed;
	__u64	tx_compressed;
	__u64	rx_nohandler;
};

/* The struct should be in sync with struct ifmap */
struct rtnl_link_ifmap {
	__u64	mem_start;
	__u64	mem_end;
	__u64	base_addr;
	__u16	irq;
	__u8	dma;
	__u8	port;
};
