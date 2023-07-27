/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_PKT_SCHED_H
#define __LINUX_PKT_SCHED_H

#include <linux/types.h>

#define TC_PRIO_BESTEFFORT		0
#define TC_PRIO_FILLER			1
#define TC_PRIO_BULK			2
#define TC_PRIO_INTERACTIVE_BULK	4
#define TC_PRIO_INTERACTIVE		6
#define TC_PRIO_CONTROL			7

#define TC_PRIO_MAX			15

/* Generic queue statistics, available for all the elements.
   Particular schedulers may have also their private records.
 */

struct tc_stats {
	__u64	bytes;			/* Number of enqueued bytes */
	__u32	packets;		/* Number of enqueued packets	*/
	__u32	drops;			/* Packets dropped because of lack of resources */
	__u32	overlimits;		/* Number of throttle events when this
					 * flow goes out of allocated bandwidth */
	__u32	bps;			/* Current flow byte rate */
	__u32	pps;			/* Current flow packet rate */
	__u32	qlen;
	__u32	backlog;
};

struct tc_estimator {
	signed char	interval;
	unsigned char	ewma_log;
};

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)
#define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK))

#define TC_H_UNSPEC	(0U)
#define TC_H_ROOT	(0xFFFFFFFFU)
#define TC_H_INGRESS    (0xFFFFFFF1U)
#define TC_H_CLSACT	TC_H_INGRESS

#define TC_H_MIN_PRIORITY	0xFFE0U
#define TC_H_MIN_INGRESS	0xFFF2U
#define TC_H_MIN_EGRESS		0xFFF3U

/* Need to corrospond to iproute2 tc/tc_core.h "enum link_layer" */
enum tc_link_layer {
	TC_LINKLAYER_UNAWARE, /* Indicate unaware old iproute2 util */
	TC_LINKLAYER_ETHERNET,
	TC_LINKLAYER_ATM,
};
#define TC_LINKLAYER_MASK 0x0F /* limit use to lower 4 bits */

struct tc_ratespec {
	unsigned char	cell_log;
	__u8		linklayer; /* lower 4 bits */
	unsigned short	overhead;
	short		cell_align;
	unsigned short	mpu;
	__u32		rate;
};

#define TC_RTAB_SIZE	1024

struct tc_sizespec {
	unsigned char	cell_log;
	unsigned char	size_log;
	short		cell_align;
	int		overhead;
	unsigned int	linklayer;
	unsigned int	mpu;
	unsigned int	mtu;
	unsigned int	tsize;
};

enum {
	TCA_STAB_UNSPEC,
	TCA_STAB_BASE,
	TCA_STAB_DATA,
	__TCA_STAB_MAX
};

#define TCA_STAB_MAX (__TCA_STAB_MAX - 1)

/* FIFO section */

struct tc_fifo_qopt {
	__u32	limit;	/* Queue length: bytes for bfifo, packets for pfifo */
};

#define SKBPRIO_MAX_PRIORITY 64

struct tc_skbprio_qopt {
	__u32	limit;		/* Queue length in packets. */
};

/* PRIO section */

#define TCQ_PRIO_BANDS	16
#define TCQ_MIN_PRIO_BANDS 2

struct tc_prio_qopt {
	int	bands;			/* Number of bands */
	__u8	priomap[TC_PRIO_MAX+1];	/* Map: logical priority -> PRIO band */
};

/* MULTIQ section */

struct tc_multiq_qopt {
	__u16	bands;			/* Number of bands */
	__u16	max_bands;		/* Maximum number of queues */
};

/* PLUG section */

#define TCQ_PLUG_BUFFER                0
#define TCQ_PLUG_RELEASE_ONE           1
#define TCQ_PLUG_RELEASE_INDEFINITE    2
#define TCQ_PLUG_LIMIT                 3

struct tc_plug_qopt {
	int             action;
	__u32           limit;
};

/* TBF section */

struct tc_tbf_qopt {
	struct tc_ratespec rate;
	struct tc_ratespec peakrate;
	__u32		limit;
	__u32		buffer;
	__u32		mtu;
};

enum {
	TCA_TBF_UNSPEC,
	TCA_TBF_PARMS,
	TCA_TBF_RTAB,
	TCA_TBF_PTAB,
	TCA_TBF_RATE64,
	TCA_TBF_PRATE64,
	TCA_TBF_BURST,
	TCA_TBF_PBURST,
	TCA_TBF_PAD,
	__TCA_TBF_MAX,
};

#define TCA_TBF_MAX (__TCA_TBF_MAX - 1)


/* TEQL section */
/* TEQL does not require any parameters */
/* SFQ section */

struct tc_sfq_qopt {
	unsigned	quantum;	/* Bytes per round allocated to flow */
	int		perturb_period;	/* Period of hash perturbation */
	__u32		limit;		/* Maximal packets in queue */
	unsigned	divisor;	/* Hash divisor  */
	unsigned	flows;		/* Maximal number of flows  */
};

struct tc_sfqred_stats {
	__u32           prob_drop;      /* Early drops, below max threshold */
	__u32           forced_drop;	/* Early drops, after max threshold */
	__u32           prob_mark;      /* Marked packets, below max threshold */
	__u32           forced_mark;    /* Marked packets, after max threshold */
	__u32           prob_mark_head; /* Marked packets, below max threshold */
	__u32           forced_mark_head;/* Marked packets, after max threshold */
};

struct tc_sfq_qopt_v1 {
	struct tc_sfq_qopt v0;
	unsigned int	depth;		/* max number of packets per flow */
	unsigned int	headdrop;
/* SFQRED parameters */
	__u32		limit;		/* HARD maximal flow queue length (bytes) */
	__u32		qth_min;	/* Min average length threshold (bytes) */
	__u32		qth_max;	/* Max average length threshold (bytes) */
	unsigned char   Wlog;		/* log(W)		*/
	unsigned char   Plog;		/* log(P_max/(qth_max-qth_min))	*/
	unsigned char   Scell_log;	/* cell size for idle damping */
	unsigned char	flags;
	__u32		max_P;		/* probability, high resolution */
/* SFQRED stats */
	struct tc_sfqred_stats stats;
};


struct tc_sfq_xstats {
	__s32		allot;
};

/* RED section */

enum {
	TCA_RED_UNSPEC,
	TCA_RED_PARMS,
	TCA_RED_STAB,
	TCA_RED_MAX_P,
	__TCA_RED_MAX,
};

#define TCA_RED_MAX (__TCA_RED_MAX - 1)

struct tc_red_qopt {
	__u32		limit;		/* HARD maximal queue length (bytes)	*/
	__u32		qth_min;	/* Min average length threshold (bytes) */
	__u32		qth_max;	/* Max average length threshold (bytes) */
	unsigned char   Wlog;		/* log(W)		*/
	unsigned char   Plog;		/* log(P_max/(qth_max-qth_min))	*/
	unsigned char   Scell_log;	/* cell size for idle damping */
	unsigned char	flags;
#define TC_RED_ECN		1
#define TC_RED_HARDDROP		2
#define TC_RED_ADAPTATIVE	4
};

struct tc_red_xstats {
	__u32           early;          /* Early drops */
	__u32           pdrop;          /* Drops due to queue limits */
	__u32           other;          /* Drops due to drop() calls */
	__u32           marked;         /* Marked packets */
};

/* GRED section */

#define MAX_DPs 16

enum {
       TCA_GRED_UNSPEC,
       TCA_GRED_PARMS,
       TCA_GRED_STAB,
       TCA_GRED_DPS,
       TCA_GRED_MAX_P,
       TCA_GRED_LIMIT,
       TCA_GRED_VQ_LIST,	/* nested TCA_GRED_VQ_ENTRY */
       __TCA_GRED_MAX,
};

#define TCA_GRED_MAX (__TCA_GRED_MAX - 1)

enum {
	TCA_GRED_VQ_ENTRY_UNSPEC,
	TCA_GRED_VQ_ENTRY,	/* nested TCA_GRED_VQ_* */
	__TCA_GRED_VQ_ENTRY_MAX,
};
#define TCA_GRED_VQ_ENTRY_MAX (__TCA_GRED_VQ_ENTRY_MAX - 1)

enum {
	TCA_GRED_VQ_UNSPEC,
	TCA_GRED_VQ_PAD,
	TCA_GRED_VQ_DP,			/* u32 */
	TCA_GRED_VQ_STAT_BYTES,		/* u64 */
	TCA_GRED_VQ_STAT_PACKETS,	/* u32 */
	TCA_GRED_VQ_STAT_BACKLOG,	/* u32 */
	TCA_GRED_VQ_STAT_PROB_DROP,	/* u32 */
	TCA_GRED_VQ_STAT_PROB_MARK,	/* u32 */
	TCA_GRED_VQ_STAT_FORCED_DROP,	/* u32 */
	TCA_GRED_VQ_STAT_FORCED_MARK,	/* u32 */
	TCA_GRED_VQ_STAT_PDROP,		/* u32 */
	TCA_GRED_VQ_STAT_OTHER,		/* u32 */
	TCA_GRED_VQ_FLAGS,		/* u32 */
	__TCA_GRED_VQ_MAX
};
