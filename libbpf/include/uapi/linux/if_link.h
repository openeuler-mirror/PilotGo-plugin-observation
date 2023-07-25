/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
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

/**
 * struct rtnl_link_stats64 - The main device statistics structure.
 *
 * @rx_packets: Number of good packets received by the interface.
 *   For hardware interfaces counts all good packets received from the device
 *   by the host, including packets which host had to drop at various stages
 *   of processing (even in the driver).
 *
 * @tx_packets: Number of packets successfully transmitted.
 *   For hardware interfaces counts packets which host was able to successfully
 *   hand over to the device, which does not necessarily mean that packets
 *   had been successfully transmitted out of the device, only that device
 *   acknowledged it copied them out of host memory.
 *
 * @rx_bytes: Number of good received bytes, corresponding to @rx_packets.
 *
 *   For IEEE 802.3 devices should count the length of Ethernet Frames
 *   excluding the FCS.
 *
 * @tx_bytes: Number of good transmitted bytes, corresponding to @tx_packets.
 *
 *   For IEEE 802.3 devices should count the length of Ethernet Frames
 *   excluding the FCS.
 *
 * @rx_errors: Total number of bad packets received on this network device.
 *   This counter must include events counted by @rx_length_errors,
 *   @rx_crc_errors, @rx_frame_errors and other errors not otherwise
 *   counted.
 *
 * @tx_errors: Total number of transmit problems.
 *   This counter must include events counter by @tx_aborted_errors,
 *   @tx_carrier_errors, @tx_fifo_errors, @tx_heartbeat_errors,
 *   @tx_window_errors and other errors not otherwise counted.
 *
 * @rx_dropped: Number of packets received but not processed,
 *   e.g. due to lack of resources or unsupported protocol.
 *   For hardware interfaces this counter may include packets discarded
 *   due to L2 address filtering but should not include packets dropped
 *   by the device due to buffer exhaustion which are counted separately in
 *   @rx_missed_errors (since procfs folds those two counters together).
 *
 * @tx_dropped: Number of packets dropped on their way to transmission,
 *   e.g. due to lack of resources.
 *
 * @multicast: Multicast packets received.
 *   For hardware interfaces this statistic is commonly calculated
 *   at the device level (unlike @rx_packets) and therefore may include
 *   packets which did not reach the host.
 *
 *   For IEEE 802.3 devices this counter may be equivalent to:
 *
 *    - 30.3.1.1.21 aMulticastFramesReceivedOK
 *
 * @collisions: Number of collisions during packet transmissions.
 *
 * @rx_length_errors: Number of packets dropped due to invalid length.
 *   Part of aggregate "frame" errors in `/proc/net/dev`.
 *
 *   For IEEE 802.3 devices this counter should be equivalent to a sum
 *   of the following attributes:
 *
 *    - 30.3.1.1.23 aInRangeLengthErrors
 *    - 30.3.1.1.24 aOutOfRangeLengthField
 *    - 30.3.1.1.25 aFrameTooLongErrors
 *
 * @rx_over_errors: Receiver FIFO overflow event counter.
 *
 *   Historically the count of overflow events. Such events may be
 *   reported in the receive descriptors or via interrupts, and may
 *   not correspond one-to-one with dropped packets.
 *
 *   The recommended interpretation for high speed interfaces is -
 *   number of packets dropped because they did not fit into buffers
 *   provided by the host, e.g. packets larger than MTU or next buffer
 *   in the ring was not available for a scatter transfer.
 *
 *   Part of aggregate "frame" errors in `/proc/net/dev`.
 *
 *   This statistics was historically used interchangeably with
 *   @rx_fifo_errors.
 *
 *   This statistic corresponds to hardware events and is not commonly used
 *   on software devices.
 *
 * @rx_crc_errors: Number of packets received with a CRC error.
 *   Part of aggregate "frame" errors in `/proc/net/dev`.
 *
 *   For IEEE 802.3 devices this counter must be equivalent to:
 *
 *    - 30.3.1.1.6 aFrameCheckSequenceErrors
 *
 * @rx_frame_errors: Receiver frame alignment errors.
 *   Part of aggregate "frame" errors in `/proc/net/dev`.
 *
 *   For IEEE 802.3 devices this counter should be equivalent to:
 *
 *    - 30.3.1.1.7 aAlignmentErrors
 *
 * @rx_fifo_errors: Receiver FIFO error counter.
 *
 *   Historically the count of overflow events. Those events may be
 *   reported in the receive descriptors or via interrupts, and may
 *   not correspond one-to-one with dropped packets.
 *
 *   This statistics was used interchangeably with @rx_over_errors.
 *   Not recommended for use in drivers for high speed interfaces.
 *
 *   This statistic is used on software devices, e.g. to count software
 *   packet queue overflow (can) or sequencing errors (GRE).
 *
 * @rx_missed_errors: Count of packets missed by the host.
 *   Folded into the "drop" counter in `/proc/net/dev`.
 *
 *   Counts number of packets dropped by the device due to lack
 *   of buffer space. This usually indicates that the host interface
 *   is slower than the network interface, or host is not keeping up
 *   with the receive packet rate.
 *
 *   This statistic corresponds to hardware events and is not used
 *   on software devices.
 *
 * @tx_aborted_errors:
 *   Part of aggregate "carrier" errors in `/proc/net/dev`.
 *   For IEEE 802.3 devices capable of half-duplex operation this counter
 *   must be equivalent to:
 *
 *    - 30.3.1.1.11 aFramesAbortedDueToXSColls
 *
 *   High speed interfaces may use this counter as a general device
 *   discard counter.
 *
 * @tx_carrier_errors: Number of frame transmission errors due to loss
 *   of carrier during transmission.
 *   Part of aggregate "carrier" errors in `/proc/net/dev`.
 *
 *   For IEEE 802.3 devices this counter must be equivalent to:
 *
 *    - 30.3.1.1.13 aCarrierSenseErrors
 *
 * @tx_fifo_errors: Number of frame transmission errors due to device
 *   FIFO underrun / underflow. This condition occurs when the device
 *   begins transmission of a frame but is unable to deliver the
 *   entire frame to the transmitter in time for transmission.
 *   Part of aggregate "carrier" errors in `/proc/net/dev`.
 *
 * @tx_heartbeat_errors: Number of Heartbeat / SQE Test errors for
 *   old half-duplex Ethernet.
 *   Part of aggregate "carrier" errors in `/proc/net/dev`.
 *
 *   For IEEE 802.3 devices possibly equivalent to:
 *
 *    - 30.3.2.1.4 aSQETestErrors
 *
 * @tx_window_errors: Number of frame transmission errors due
 *   to late collisions (for Ethernet - after the first 64B of transmission).
 *   Part of aggregate "carrier" errors in `/proc/net/dev`.
 *
 *   For IEEE 802.3 devices this counter must be equivalent to:
 *
 *    - 30.3.1.1.10 aLateCollisions
 *
 * @rx_compressed: Number of correctly received compressed packets.
 *   This counters is only meaningful for interfaces which support
 *   packet compression (e.g. CSLIP, PPP).
 *
 * @tx_compressed: Number of transmitted compressed packets.
 *   This counters is only meaningful for interfaces which support
 *   packet compression (e.g. CSLIP, PPP).
 *
 * @rx_nohandler: Number of packets received on the interface
 *   but dropped by the networking stack because the device is
 *   not designated to receive packets (e.g. backup link in a bond).
 */
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