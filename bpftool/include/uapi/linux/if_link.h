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
enum {
	IFLA_UNSPEC,
	IFLA_ADDRESS,
	IFLA_BROADCAST,
	IFLA_IFNAME,
	IFLA_MTU,
	IFLA_LINK,
	IFLA_QDISC,
	IFLA_STATS,
	IFLA_COST,
#define IFLA_COST IFLA_COST
	IFLA_PRIORITY,
#define IFLA_PRIORITY IFLA_PRIORITY
	IFLA_MASTER,
#define IFLA_MASTER IFLA_MASTER
	IFLA_WIRELESS,		/* Wireless Extension event - see wireless.h */
#define IFLA_WIRELESS IFLA_WIRELESS
	IFLA_PROTINFO,		/* Protocol specific information for a link */
#define IFLA_PROTINFO IFLA_PROTINFO
	IFLA_TXQLEN,
#define IFLA_TXQLEN IFLA_TXQLEN
	IFLA_MAP,
#define IFLA_MAP IFLA_MAP
	IFLA_WEIGHT,
#define IFLA_WEIGHT IFLA_WEIGHT
	IFLA_OPERSTATE,
	IFLA_LINKMODE,
	IFLA_LINKINFO,
#define IFLA_LINKINFO IFLA_LINKINFO
	IFLA_NET_NS_PID,
	IFLA_IFALIAS,
	IFLA_NUM_VF,		/* Number of VFs if device is SR-IOV PF */
	IFLA_VFINFO_LIST,
	IFLA_STATS64,
	IFLA_VF_PORTS,
	IFLA_PORT_SELF,
	IFLA_AF_SPEC,
	IFLA_GROUP,		/* Group the device belongs to */
	IFLA_NET_NS_FD,
	IFLA_EXT_MASK,		/* Extended info mask, VFs, etc */
	IFLA_PROMISCUITY,
#define IFLA_PROMISCUITY IFLA_PROMISCUITY
	IFLA_NUM_TX_QUEUES,
	IFLA_NUM_RX_QUEUES,
	IFLA_CARRIER,
	IFLA_PHYS_PORT_ID,
	IFLA_CARRIER_CHANGES,
	IFLA_PHYS_SWITCH_ID,
	IFLA_LINK_NETNSID,
	IFLA_PHYS_PORT_NAME,
	IFLA_PROTO_DOWN,
	IFLA_GSO_MAX_SEGS,
	IFLA_GSO_MAX_SIZE,
	IFLA_PAD,
	IFLA_XDP,
	IFLA_EVENT,
	IFLA_NEW_NETNSID,
	IFLA_IF_NETNSID,
	IFLA_TARGET_NETNSID = IFLA_IF_NETNSID, /* new alias */
	IFLA_CARRIER_UP_COUNT,
	IFLA_CARRIER_DOWN_COUNT,
	IFLA_NEW_IFINDEX,
	IFLA_MIN_MTU,
	IFLA_MAX_MTU,
	IFLA_PROP_LIST,
	IFLA_ALT_IFNAME, /* Alternative ifname */
	IFLA_PERM_ADDRESS,
	IFLA_PROTO_DOWN_REASON,

	/* device (sysfs) name as parent, used instead
	 * of IFLA_LINK where there's no parent netdev
	 */
	IFLA_PARENT_DEV_NAME,
	IFLA_PARENT_DEV_BUS_NAME,
	IFLA_GRO_MAX_SIZE,
	IFLA_TSO_MAX_SIZE,
	IFLA_TSO_MAX_SEGS,

	__IFLA_MAX
};


#define IFLA_MAX (__IFLA_MAX - 1)
enum {
	IFLA_PROTO_DOWN_REASON_UNSPEC,
	IFLA_PROTO_DOWN_REASON_MASK,	/* u32, mask for reason bits */
	IFLA_PROTO_DOWN_REASON_VALUE,   /* u32, reason bit value */

	__IFLA_PROTO_DOWN_REASON_CNT,
	IFLA_PROTO_DOWN_REASON_MAX = __IFLA_PROTO_DOWN_REASON_CNT - 1
};

/* backwards compatibility for userspace */
#ifndef __KERNEL__
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif

enum {
	IFLA_INET_UNSPEC,
	IFLA_INET_CONF,
	__IFLA_INET_MAX,
};

#define IFLA_INET_MAX (__IFLA_INET_MAX - 1)


enum {
	IFLA_INET6_UNSPEC,
	IFLA_INET6_FLAGS,	/* link flags			*/
	IFLA_INET6_CONF,	/* sysctl parameters		*/
	IFLA_INET6_STATS,	/* statistics			*/
	IFLA_INET6_MCAST,	/* MC things. What of them?	*/
	IFLA_INET6_CACHEINFO,	/* time values and max reasm size */
	IFLA_INET6_ICMP6STATS,	/* statistics (icmpv6)		*/
	IFLA_INET6_TOKEN,	/* device token			*/
	IFLA_INET6_ADDR_GEN_MODE, /* implicit address generator mode */
	IFLA_INET6_RA_MTU,	/* mtu carried in the RA message */
	__IFLA_INET6_MAX
};
#define IFLA_INET6_MAX	(__IFLA_INET6_MAX - 1)

enum in6_addr_gen_mode {
	IN6_ADDR_GEN_MODE_EUI64,
	IN6_ADDR_GEN_MODE_NONE,
	IN6_ADDR_GEN_MODE_STABLE_PRIVACY,
	IN6_ADDR_GEN_MODE_RANDOM,
};

/* Bridge section */

enum {
	IFLA_BR_UNSPEC,
	IFLA_BR_FORWARD_DELAY,
	IFLA_BR_HELLO_TIME,
	IFLA_BR_MAX_AGE,
	IFLA_BR_AGEING_TIME,
	IFLA_BR_STP_STATE,
	IFLA_BR_PRIORITY,
	IFLA_BR_VLAN_FILTERING,
	IFLA_BR_VLAN_PROTOCOL,
	IFLA_BR_GROUP_FWD_MASK,
	IFLA_BR_ROOT_ID,
	IFLA_BR_BRIDGE_ID,
	IFLA_BR_ROOT_PORT,
	IFLA_BR_ROOT_PATH_COST,
	IFLA_BR_TOPOLOGY_CHANGE,
	IFLA_BR_TOPOLOGY_CHANGE_DETECTED,
	IFLA_BR_HELLO_TIMER,
	IFLA_BR_TCN_TIMER,
	IFLA_BR_TOPOLOGY_CHANGE_TIMER,
	IFLA_BR_GC_TIMER,
	IFLA_BR_GROUP_ADDR,
	IFLA_BR_FDB_FLUSH,
	IFLA_BR_MCAST_ROUTER,
	IFLA_BR_MCAST_SNOOPING,
	IFLA_BR_MCAST_QUERY_USE_IFADDR,
	IFLA_BR_MCAST_QUERIER,
	IFLA_BR_MCAST_HASH_ELASTICITY,
	IFLA_BR_MCAST_HASH_MAX,
	IFLA_BR_MCAST_LAST_MEMBER_CNT,
	IFLA_BR_MCAST_STARTUP_QUERY_CNT,
	IFLA_BR_MCAST_LAST_MEMBER_INTVL,
	IFLA_BR_MCAST_MEMBERSHIP_INTVL,
	IFLA_BR_MCAST_QUERIER_INTVL,
	IFLA_BR_MCAST_QUERY_INTVL,
	IFLA_BR_MCAST_QUERY_RESPONSE_INTVL,
	IFLA_BR_MCAST_STARTUP_QUERY_INTVL,
	IFLA_BR_NF_CALL_IPTABLES,
	IFLA_BR_NF_CALL_IP6TABLES,
	IFLA_BR_NF_CALL_ARPTABLES,
	IFLA_BR_VLAN_DEFAULT_PVID,
	IFLA_BR_PAD,
	IFLA_BR_VLAN_STATS_ENABLED,
	IFLA_BR_MCAST_STATS_ENABLED,
	IFLA_BR_MCAST_IGMP_VERSION,
	IFLA_BR_MCAST_MLD_VERSION,
	IFLA_BR_VLAN_STATS_PER_PORT,
	IFLA_BR_MULTI_BOOLOPT,
	IFLA_BR_MCAST_QUERIER_STATE,
	__IFLA_BR_MAX,
};
#define IFLA_BR_MAX	(__IFLA_BR_MAX - 1)

struct ifla_bridge_id {
	__u8	prio[2];
	__u8	addr[6]; /* ETH_ALEN */
};

enum {
	BRIDGE_MODE_UNSPEC,
	BRIDGE_MODE_HAIRPIN,
};

enum {
	IFLA_BRPORT_UNSPEC,
	IFLA_BRPORT_STATE,	/* Spanning tree state     */
	IFLA_BRPORT_PRIORITY,	/* "             priority  */
	IFLA_BRPORT_COST,	/* "             cost      */
	IFLA_BRPORT_MODE,	/* mode (hairpin)          */
	IFLA_BRPORT_GUARD,	/* bpdu guard              */
	IFLA_BRPORT_PROTECT,	/* root port protection    */
	IFLA_BRPORT_FAST_LEAVE,	/* multicast fast leave    */
	IFLA_BRPORT_LEARNING,	/* mac learning */
	IFLA_BRPORT_UNICAST_FLOOD, /* flood unicast traffic */
	IFLA_BRPORT_PROXYARP,	/* proxy ARP */
	IFLA_BRPORT_LEARNING_SYNC, /* mac learning sync from device */
	IFLA_BRPORT_PROXYARP_WIFI, /* proxy ARP for Wi-Fi */
	IFLA_BRPORT_ROOT_ID,	/* designated root */
	IFLA_BRPORT_BRIDGE_ID,	/* designated bridge */
	IFLA_BRPORT_DESIGNATED_PORT,
	IFLA_BRPORT_DESIGNATED_COST,
	IFLA_BRPORT_ID,
	IFLA_BRPORT_NO,
	IFLA_BRPORT_TOPOLOGY_CHANGE_ACK,
	IFLA_BRPORT_CONFIG_PENDING,
	IFLA_BRPORT_MESSAGE_AGE_TIMER,
	IFLA_BRPORT_FORWARD_DELAY_TIMER,
	IFLA_BRPORT_HOLD_TIMER,
	IFLA_BRPORT_FLUSH,
	IFLA_BRPORT_MULTICAST_ROUTER,
	IFLA_BRPORT_PAD,
	IFLA_BRPORT_MCAST_FLOOD,
	IFLA_BRPORT_MCAST_TO_UCAST,
	IFLA_BRPORT_VLAN_TUNNEL,
	IFLA_BRPORT_BCAST_FLOOD,
	IFLA_BRPORT_GROUP_FWD_MASK,
	IFLA_BRPORT_NEIGH_SUPPRESS,
	IFLA_BRPORT_ISOLATED,
	IFLA_BRPORT_BACKUP_PORT,
	IFLA_BRPORT_MRP_RING_OPEN,
	IFLA_BRPORT_MRP_IN_OPEN,
	IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT,
	IFLA_BRPORT_MCAST_EHT_HOSTS_CNT,
	__IFLA_BRPORT_MAX
};
#define IFLA_BRPORT_MAX (__IFLA_BRPORT_MAX - 1)

struct ifla_cacheinfo {
	__u32	max_reasm_len;
	__u32	tstamp;		/* ipv6InterfaceTable updated timestamp */
	__u32	reachable_time;
	__u32	retrans_time;
};

enum {
	IFLA_INFO_UNSPEC,
	IFLA_INFO_KIND,
	IFLA_INFO_DATA,
	IFLA_INFO_XSTATS,
	IFLA_INFO_SLAVE_KIND,
	IFLA_INFO_SLAVE_DATA,
	__IFLA_INFO_MAX,
};

#define IFLA_INFO_MAX	(__IFLA_INFO_MAX - 1)

/* VLAN section */

enum {
	IFLA_VLAN_UNSPEC,
	IFLA_VLAN_ID,
	IFLA_VLAN_FLAGS,
	IFLA_VLAN_EGRESS_QOS,
	IFLA_VLAN_INGRESS_QOS,
	IFLA_VLAN_PROTOCOL,
	__IFLA_VLAN_MAX,
};
#define IFLA_VLAN_MAX	(__IFLA_VLAN_MAX - 1)

struct ifla_vlan_flags {
	__u32	flags;
	__u32	mask;
};

enum {
	IFLA_VLAN_QOS_UNSPEC,
	IFLA_VLAN_QOS_MAPPING,
	__IFLA_VLAN_QOS_MAX
};

#define IFLA_VLAN_QOS_MAX	(__IFLA_VLAN_QOS_MAX - 1)

struct ifla_vlan_qos_mapping {
	__u32 from;
	__u32 to;
};

/* MACVLAN section */
enum {
	IFLA_MACVLAN_UNSPEC,
	IFLA_MACVLAN_MODE,
	IFLA_MACVLAN_FLAGS,
	IFLA_MACVLAN_MACADDR_MODE,
	IFLA_MACVLAN_MACADDR,
	IFLA_MACVLAN_MACADDR_DATA,
	IFLA_MACVLAN_MACADDR_COUNT,
	IFLA_MACVLAN_BC_QUEUE_LEN,
	IFLA_MACVLAN_BC_QUEUE_LEN_USED,
	IFLA_MACVLAN_BC_CUTOFF,
	__IFLA_MACVLAN_MAX,
};

#define IFLA_MACVLAN_MAX (__IFLA_MACVLAN_MAX - 1)

enum macvlan_mode {
	MACVLAN_MODE_PRIVATE = 1, /* don't talk to other macvlans */
	MACVLAN_MODE_VEPA    = 2, /* talk to other ports through ext bridge */
	MACVLAN_MODE_BRIDGE  = 4, /* talk to bridge ports directly */
	MACVLAN_MODE_PASSTHRU = 8,/* take over the underlying device */
	MACVLAN_MODE_SOURCE  = 16,/* use source MAC address list to assign */
};

enum macvlan_macaddr_mode {
	MACVLAN_MACADDR_ADD,
	MACVLAN_MACADDR_DEL,
	MACVLAN_MACADDR_FLUSH,
	MACVLAN_MACADDR_SET,
};