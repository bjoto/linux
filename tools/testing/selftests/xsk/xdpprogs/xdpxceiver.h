/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2020 Intel Corporation.
 */

#ifndef XDPXCEIVER_H_
#define XDPXCEIVER_H_

#define MAX_SOCKS 1

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define MIN_PKT_SIZE 64

#define MAX_INTERFACES 2
#define MAX_INTERFACE_NAME_CHARS 7
#define MAX_INTERFACES_NAMESPACE_CHARS 10
#define MAX_MAC_STR 18
#define MAX_IP4_STR 16
#define MAX_IP6_STR 40

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;

/*TESTS Specific*/
enum TESTS {
	ORDER_CONTENT_VALIDATE_XDP_SKB = 1,
	ORDER_CONTENT_VALIDATE_XDP_DRV = 2,
};
u8 UUT;
u8 DEBUG_PKTDUMP;
u32 NUM_FRAMES;

static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int opt_queue;
static u32 opt_batch_size = 64;
static int opt_pkt_count;
static u16 opt_pkt_size = MIN_PKT_SIZE;
static int opt_poll;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;
static int opt_mmap_flags;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static int opt_timeout = 1000;
static bool opt_need_wakeup = true;
static int num_socks = 1;
static u8 pkt_data[XSK_UMEM__DEFAULT_FRAME_SIZE];
static u32 pktCounter;
static int sigVar;
static u32 prevPkt = -1;

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long prev_rx_npkts;
	unsigned long prev_tx_npkts;
	u32 outstanding_tx;
};

struct flow_vector {
	enum fvector {
		tx,
		rx,
		bidi,
		undef,
	} vector;
};

struct generic_data {
	u32 seqnum;
};

struct ifaceConfigObj {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	struct in_addr dst_ip;
	struct in_addr src_ip;
	u16 src_port;
	u16 dst_port;
} *ifaceConfig;

struct ifObjectStruct {
	int opt_ifindex;
	int ifDict_index;
	char opt_if[MAX_INTERFACE_NAME_CHARS];
	char opt_ns[MAX_INTERFACES_NAMESPACE_CHARS];
	struct flow_vector fv;
	struct xsk_socket_info *xsk;
	struct xsk_umem_info *umem;
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	u32 dst_ip;
	u32 src_ip;
	u16 src_port;
	u16 dst_port;
};
static struct ifObjectStruct *ifDict[MAX_INTERFACES];

/*packet*/
#define ETH_FCS_SIZE		4
#define PKT_HDR_SIZE		(sizeof(struct ethhdr) + sizeof(struct iphdr) + \
				sizeof(struct udphdr))
#define PKT_SIZE		(opt_pkt_size - ETH_FCS_SIZE)
#define IP_PKT_SIZE		(PKT_SIZE - sizeof(struct ethhdr))
#define UDP_PKT_SIZE		(IP_PKT_SIZE - sizeof(struct iphdr))
#define UDP_PKT_DATA_SIZE	(UDP_PKT_SIZE - sizeof(struct udphdr))

/*threads*/
#define TMOUT_SEC	(3)
#define EOT		(-1)
#define USLEEP_MAX	200000
#define THREAD_STACK	60000000
atomic_int spinningTx;
atomic_int spinningRx;
pthread_mutex_t syncMutex;
pthread_mutex_t syncMutexTx;
pthread_mutex_t syncMutexRx;
pthread_cond_t signalRxCondition;
pthread_cond_t signalTxCondition;
pthread_t t0, t1, rxthread, nsthread;
pthread_attr_t attr;

struct targs {
	bool retptr;
	int idx;
};

TAILQ_HEAD(head_s, pkt) head = TAILQ_HEAD_INITIALIZER(head);
struct head_s *headp;
struct pkt {
	char *pktFrame;

	TAILQ_ENTRY(pkt) pktNodes;
} *pktNodeRx, *pktNodeRxQ;

struct pktFrame {
	char *payload;
} *pktObj;
struct pktFrame **pktBuf;

#endif				/* XDPXCEIVER_H */
