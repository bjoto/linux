// SPDX-License-Identifier: GPL-2.0
/* XDP sockets
 *
 * AF_XDP sockets allows a channel between XDP programs and userspace
 * applications.
 * Copyright(c) 2018 Intel Corporation.
 *
 * Author(s): Björn Töpel <bjorn.topel@intel.com>
 *	      Magnus Karlsson <magnus.karlsson@intel.com>
 */

#define pr_fmt(fmt) "AF_XDP: %s: " fmt, __func__

#include <linux/if_xdp.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <net/xdp_sock.h>
#include <net/xdp.h>
#include <net/busy_poll.h>

#include <net/xsk_queue.h>
#include "xdp_umem.h"

#define TX_BATCH_SIZE 16

static struct xdp_sock *xdp_sk(struct sock *sk)
{
	return (struct xdp_sock *)sk;
}

bool xsk_is_setup_for_bpf_map(struct xdp_sock *xs)
{
	return READ_ONCE(xs->rx) &&  READ_ONCE(xs->umem) &&
		READ_ONCE(xs->umem->fq);
}

u64 *xsk_umem_peek_addr(struct xdp_umem *umem, u64 *addr)
{
	return xskq_peek_addr(umem->fq, addr);
}
EXPORT_SYMBOL(xsk_umem_peek_addr);

void xsk_umem_discard_addr(struct xdp_umem *umem)
{
	xskq_discard_addr(umem->fq);
}
EXPORT_SYMBOL(xsk_umem_discard_addr);

static int __xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len)
{
	void *to_buf, *from_buf;
	u32 metalen;
	u64 addr;
	int err;

	if (!xskq_peek_addr(xs->umem->fq, &addr) ||
	    len > xs->umem->chunk_size_nohr - XDP_PACKET_HEADROOM) {
		xs->rx_dropped++;
		return -ENOSPC;
	}

	addr += xs->umem->headroom;

	if (unlikely(xdp_data_meta_unsupported(xdp))) {
		from_buf = xdp->data;
		metalen = 0;
	} else {
		from_buf = xdp->data_meta;
		metalen = xdp->data - xdp->data_meta;
	}

	to_buf = xdp_umem_get_data(xs->umem, addr);
	memcpy(to_buf, from_buf, len + metalen);
	addr += metalen;
	err = xskq_produce_batch_desc(xs->rx, addr, len);
	if (!err) {
		xskq_discard_addr(xs->umem->fq);
		xdp_return_buff(xdp);
		return 0;
	}

	xs->rx_dropped++;
	return err;
}

static int __xsk_rcv_zc(struct xdp_sock *xs, struct xdp_buff *xdp, u32 len)
{
	int err = xskq_produce_batch_desc(xs->rx, (u64)xdp->handle, len);

	if (err)
		xs->rx_dropped++;

	return err;
}

int xsk_attached_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	u32 len = xdp->data_end - xdp->data;

	return (xdp->rxq->mem.type == MEM_TYPE_ZERO_COPY) ?
		__xsk_rcv_zc(xs, xdp, len) : __xsk_rcv(xs, xdp, len);
}

int xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	if (xs->dev != xdp->rxq->dev || xs->queue_id != xdp->rxq->queue_index)
		return -EINVAL;

	return xsk_attached_rcv(xs, xdp);
}

int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	u32 metalen = xdp->data - xdp->data_meta;
	u32 len = xdp->data_end - xdp->data;
	void *buffer;
	u64 addr;
	int err;

	if (xs->dev != xdp->rxq->dev || xs->queue_id != xdp->rxq->queue_index)
		return -EINVAL;

	if (!xskq_peek_addr(xs->umem->fq, &addr) ||
	    len > xs->umem->chunk_size_nohr - XDP_PACKET_HEADROOM) {
		xs->rx_dropped++;
		return -ENOSPC;
	}

	addr += xs->umem->headroom;

	buffer = xdp_umem_get_data(xs->umem, addr);
	memcpy(buffer, xdp->data_meta, len + metalen);
	addr += metalen;
	err = xskq_produce_batch_desc(xs->rx, addr, len);
	if (!err) {
		xskq_discard_addr(xs->umem->fq);
		xsk_flush(xs);
		return 0;
	}

	xs->rx_dropped++;
	return err;
}

void xsk_umem_complete_tx(struct xdp_umem *umem, u32 nb_entries)
{
	xskq_produce_flush_addr_n(umem->cq, nb_entries);
}
EXPORT_SYMBOL(xsk_umem_complete_tx);

void xsk_umem_consume_tx_done(struct xdp_umem *umem)
{
	struct xdp_sock *xs;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &umem->xsk_list, list) {
		xs->sk.sk_write_space(&xs->sk);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL(xsk_umem_consume_tx_done);

bool xsk_umem_consume_tx(struct xdp_umem *umem, dma_addr_t *dma, u32 *len)
{
	struct xdp_desc desc;
	struct xdp_sock *xs;

	rcu_read_lock();
	list_for_each_entry_rcu(xs, &umem->xsk_list, list) {
		if (!xskq_peek_desc(xs->tx, &desc))
			continue;

		if (!umem->inorder_completion &&
		    xskq_produce_addr_lazy(umem->cq, desc.addr))
			goto out;

		*dma = xdp_umem_get_dma(umem, desc.addr);
		*len = desc.len;

		xskq_discard_desc(xs->tx);
		rcu_read_unlock();
		return true;
	}

out:
	rcu_read_unlock();
	return false;
}
EXPORT_SYMBOL(xsk_umem_consume_tx);

static int xsk_zc_xmit(struct sock *sk)
{
	struct xdp_sock *xs = xdp_sk(sk);
	struct net_device *dev = xs->dev;

	return dev->netdev_ops->ndo_xsk_async_xmit(dev, xs->queue_id);
}

static void xsk_destruct_skb(struct sk_buff *skb)
{
	u64 addr = (u64)(long)skb_shinfo(skb)->destructor_arg;
	struct xdp_sock *xs = xdp_sk(skb->sk);
	unsigned long flags;

	spin_lock_irqsave(&xs->tx_completion_lock, flags);
	WARN_ON_ONCE(xskq_produce_addr(xs->umem->cq, addr));
	spin_unlock_irqrestore(&xs->tx_completion_lock, flags);

	sock_wfree(skb);
}

static int xsk_generic_xmit(struct sock *sk)
{
	u32 max_batch = TX_BATCH_SIZE;
	struct xdp_sock *xs = xdp_sk(sk);
	bool sent_frame = false;
	struct xdp_desc desc;
	struct sk_buff *skb;
	int err = 0;

	mutex_lock(&xs->mutex);

	while (xskq_peek_desc(xs->tx, &desc)) {
		char *buffer;
		u64 addr;
		u32 len;

		if (max_batch-- == 0) {
			err = -EAGAIN;
			goto out;
		}

		if (xskq_reserve_addr(xs->umem->cq))
			goto out;

		if (xs->queue_id >= xs->dev->real_num_tx_queues)
			goto out;

		len = desc.len;
		skb = sock_alloc_send_skb(sk, len, 1, &err);
		if (unlikely(!skb)) {
			err = -EAGAIN;
			goto out;
		}

		skb_put(skb, len);
		addr = desc.addr;
		buffer = xdp_umem_get_data(xs->umem, addr);
		err = skb_store_bits(skb, 0, buffer, len);
		if (unlikely(err)) {
			kfree_skb(skb);
			goto out;
		}

		skb->dev = xs->dev;
		skb->priority = sk->sk_priority;
		skb->mark = sk->sk_mark;
		skb_shinfo(skb)->destructor_arg = (void *)(long)addr;
		skb->destructor = xsk_destruct_skb;

		err = dev_direct_xmit(skb, xs->queue_id);
		xskq_discard_desc(xs->tx);
		/* Ignore NET_XMIT_CN as packet might have been sent */
		if (err == NET_XMIT_DROP || err == NETDEV_TX_BUSY) {
			/* SKB completed but not sent */
			err = -EBUSY;
			goto out;
		}

		sent_frame = true;
	}

out:
	if (sent_frame)
		sk->sk_write_space(sk);

	mutex_unlock(&xs->mutex);
	return err;
}

static int xsk_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	bool need_wait = !(m->msg_flags & MSG_DONTWAIT);
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);

	if (unlikely(!xs->dev))
		return -ENXIO;
	if (unlikely(!(xs->dev->flags & IFF_UP)))
		return -ENETDOWN;
	if (unlikely(!xs->tx))
		return -ENOBUFS;
	if (need_wait)
		return -EOPNOTSUPP;

	return xs->zc ? xsk_zc_xmit(sk) : xsk_generic_xmit(sk);
}

static bool xsk_tx_busy_loop_end(void *p, unsigned long start_time)
{
	struct xdp_sock *xs = p;

	return (!xskq_full_desc(xs->tx) || busy_loop_timeout(start_time));
}

static void xsk_tx_busy_loop(struct xdp_sock *xs, int nonblock)
{
	unsigned int napi_id = xs->umem->napi_id;

	if ((napi_id >= MIN_NAPI_ID) && net_busy_loop_on())
		napi_busy_loop(napi_id, nonblock ? NULL : xsk_tx_busy_loop_end,
			       xs);
}
static bool xsk_rx_busy_loop_end(void *p, unsigned long start_time)
{
	struct xdp_sock *xs = p;

	return (!xskq_empty_desc(xs->rx) || busy_loop_timeout(start_time));
}

static void xsk_rx_busy_loop(struct xdp_sock *xs, int nonblock)
{
	unsigned int napi_id = xs->umem->napi_id;

	if ((napi_id >= MIN_NAPI_ID) && net_busy_loop_on())
		napi_busy_loop(napi_id, nonblock ? NULL : xsk_rx_busy_loop_end,
			       xs);
}

static unsigned int xsk_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	unsigned int mask = 0;//datagram_poll(file, sock, wait);
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	__poll_t events = poll_requested_events(wait);

	if (events & POLL_BUSY_LOOP) {
		if (events & (POLLIN | POLLRDNORM))
			xsk_rx_busy_loop(xs, false);
		if (events & (POLLOUT | POLLWRNORM))
			xsk_tx_busy_loop(xs, false);
	}

	if (xs->rx && !xskq_empty_desc(xs->rx))
		mask |= POLLIN | POLLRDNORM;
	if (xs->tx && !xskq_full_desc(xs->tx))
		mask |= POLLOUT | POLLWRNORM;

	return mask;
}

static int xsk_init_queue(u32 entries, struct xsk_queue **queue,
			  bool umem_queue)
{
	struct xsk_queue *q;

	if (entries == 0 || *queue || !is_power_of_2(entries))
		return -EINVAL;

	q = xskq_create(entries, umem_queue);
	if (!q)
		return -ENOMEM;

	/* Make sure queue is ready before it can be seen by others */
	smp_wmb();
	*queue = q;
	return 0;
}

static const struct bpf_insn xsk_prog_insn[] = {
	BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_xsk_redirect),
	BPF_EXIT_INSN(),
};
static const unsigned int xsk_prog_insn_cnt = ARRAY_SIZE(xsk_prog_insn);
static struct bpf_prog *xsk_builtin_prog;
static unsigned int xsk_builtin_prog_refcnt;

static struct bpf_prog *xsk_load_builtin_prog(void)
{
	union bpf_attr attr = {};
	struct bpf_prog *prog;
	int err = 0;

	if (xsk_builtin_prog) {
		xsk_builtin_prog_refcnt++;
		return xsk_builtin_prog;
	}

	prog = bpf_prog_alloc(bpf_prog_size(xsk_prog_insn_cnt), 0);
        if (!prog)
                return ERR_PTR(-ENOMEM);

        memcpy(prog->insns, &xsk_prog_insn[0], sizeof(xsk_prog_insn));
        prog->len = xsk_prog_insn_cnt;
	prog->orig_prog = NULL;
	prog->jited = 0;
	atomic_set(&prog->aux->refcnt, 1);
	prog->gpl_compatible = 1;
	prog->xsk_builtin = 1;

	err = find_prog_type(BPF_PROG_TYPE_XDP, prog);
	if (err < 0)
		goto out_err_free;

	prog->aux->load_time = ktime_get_boot_ns();
	err = bpf_obj_name_cpy(prog->aux->name, "AF_XDP_BUILTIN");
	if (err)
		goto out_err_free;

	err = bpf_check(&prog, &attr);
	if (err < 0)
		goto out_err_free;

        prog = bpf_prog_select_runtime(prog, &err);
        if (err)
                goto out_err_free;

	err = bpf_prog_alloc_id(prog);
	if (err)
		goto out_err_free;

	bpf_prog_kallsyms_add(prog);
	xsk_builtin_prog_refcnt++;
	xsk_builtin_prog = prog;
        return prog;

out_err_free:
        bpf_prog_free(prog);
        return ERR_PTR(err);
}

static bool xsk_unload_builtin_prog(void)
{
	xsk_builtin_prog_refcnt--;

	if (xsk_builtin_prog_refcnt)
		return false;

	bpf_prog_put(xsk_builtin_prog);
	xsk_builtin_prog = NULL;
	return true;
}

static struct xdp_sock *xsk_get_attached(struct net_device *dev, u16 qid)
{
	return dev->_rx[qid].xsk;
}

static void xsk_detach(struct xdp_sock *xs)
{
	if (xsk_get_attached(xs->dev, xs->queue_id)) {
		rtnl_lock();
		xs->dev->_rx[xs->queue_id].xsk = NULL;
		// XXX This is broken for multiple sockets on same dev/qid
		xsk_unload_builtin_prog();
		dev_xsk_prog_uninstall(xs->dev);
		rtnl_unlock();
	}
}

static int xsk_attach(struct xdp_sock *xs, struct net_device *dev, u16 qid)
{
	struct bpf_prog *prog;
	int err = 0;

	// No need to check if qid is OK here.
	rtnl_lock();
	if (xsk_get_attached(dev, qid)) {
		err = -EBUSY;
		goto out;
	}

	dev->_rx[qid].xsk = xs;

	prog = xsk_load_builtin_prog();
	if (IS_ERR(prog)) {
		err = PTR_ERR(prog);
		goto out;
	}

	err = dev_xsk_prog_install(dev, prog, 0);
	if (err)
		goto out_unload;

	goto out_unlock;

out_unload:
	(void)xsk_unload_builtin_prog();
out:
	dev->_rx[qid].xsk = NULL;
out_unlock:
	rtnl_unlock();
	return err;
}

static int xsk_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct net *net;

	if (!sk)
		return 0;

	net = sock_net(sk);

	local_bh_disable();
	sock_prot_inuse_add(net, sk->sk_prot, -1);
	local_bh_enable();

	if (xs->dev) {
		struct net_device *dev = xs->dev;

		/* Wait for driver to stop using the xdp socket. */
		xdp_del_sk_umem(xs->umem, xs);
		xsk_detach(xs);
		xs->dev = NULL;
		synchronize_net();
		dev_put(dev);
	}

	xskq_destroy(xs->rx);
	xskq_destroy(xs->tx);

	sock_orphan(sk);
	sock->sk = NULL;

	sk_refcnt_debug_release(sk);
	sock_put(sk);

	return 0;
}

static struct socket *xsk_lookup_xsk_from_fd(int fd)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	if (sock->sk->sk_family != PF_XDP) {
		sockfd_put(sock);
		return ERR_PTR(-ENOPROTOOPT);
	}

	return sock;
}

static int xsk_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_xdp *sxdp = (struct sockaddr_xdp *)addr;
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	struct net_device *dev;
	u32 flags, qid;
	int err = 0;

	if (addr_len < sizeof(struct sockaddr_xdp))
		return -EINVAL;
	if (sxdp->sxdp_family != AF_XDP)
		return -EINVAL;

	mutex_lock(&xs->mutex);
	if (xs->dev) {
		err = -EBUSY;
		goto out_release;
	}

	dev = dev_get_by_index(sock_net(sk), sxdp->sxdp_ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out_release;
	}

	if (!xs->rx && !xs->tx) {
		err = -EINVAL;
		goto out_unlock;
	}

	qid = sxdp->sxdp_queue_id;
	flags = sxdp->sxdp_flags;

	if (flags & XDP_SHARED_UMEM) {
		struct xdp_sock *umem_xs;
		struct socket *sock;

		if ((flags & XDP_COPY) || (flags & XDP_ZEROCOPY) ||
		    (flags & XDP_ATTACH)) {
			/* Cannot specify flags for shared sockets. */
			err = -EINVAL;
			goto out_unlock;
		}

		if (xs->umem) {
			/* We have already our own. */
			err = -EINVAL;
			goto out_unlock;
		}

		sock = xsk_lookup_xsk_from_fd(sxdp->sxdp_shared_umem_fd);
		if (IS_ERR(sock)) {
			err = PTR_ERR(sock);
			goto out_unlock;
		}

		umem_xs = xdp_sk(sock->sk);
		if (!umem_xs->umem) {
			/* No umem to inherit. */
			err = -EBADF;
			sockfd_put(sock);
			goto out_unlock;
		} else if (umem_xs->dev != dev || umem_xs->queue_id != qid ||
			   umem_xs->umem->inorder_completion) {
			err = -EINVAL;
			sockfd_put(sock);
			goto out_unlock;
		}

		xdp_get_umem(umem_xs->umem);
		xs->umem = umem_xs->umem;
		sockfd_put(sock);
	} else if (!xs->umem || !xdp_umem_validate_queues(xs->umem)) {
		err = -EINVAL;
		goto out_unlock;
	} else {
		/* This xsk has its own umem. */
		xskq_set_umem(xs->umem->fq, xs->umem->size,
			      xs->umem->chunk_mask);
		xskq_set_umem(xs->umem->cq, xs->umem->size,
			      xs->umem->chunk_mask);

		err = xdp_umem_assign_dev(xs->umem, dev, qid, flags);
		if (err)
			goto out_unlock;

		if (flags & XDP_ATTACH) {
			err = xsk_attach(xs, dev, qid);
			if (err)
				goto out_unlock;
		}
	}

	xs->dev = dev;
	xs->zc = xs->umem->zc;
	xs->queue_id = qid;
	xskq_set_umem(xs->rx, xs->umem->size, xs->umem->chunk_mask);
	xskq_set_umem(xs->tx, xs->umem->size, xs->umem->chunk_mask);
	xdp_add_sk_umem(xs->umem, xs);

out_unlock:
	if (err)
		dev_put(dev);
out_release:
	mutex_unlock(&xs->mutex);
	return err;
}

static int xsk_setsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int err;

	if (level != SOL_XDP)
		return -ENOPROTOOPT;

	switch (optname) {
	case XDP_RX_RING:
	case XDP_TX_RING:
	{
		struct xsk_queue **q;
		int entries;

		if (optlen < sizeof(entries))
			return -EINVAL;
		if (copy_from_user(&entries, optval, sizeof(entries)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		q = (optname == XDP_TX_RING) ? &xs->tx : &xs->rx;
		err = xsk_init_queue(entries, q, false);
		mutex_unlock(&xs->mutex);
		return err;
	}
	case XDP_UMEM_REG:
	{
		struct xdp_umem_reg mr;
		struct xdp_umem *umem;

		if (copy_from_user(&mr, optval, sizeof(mr)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (xs->umem) {
			mutex_unlock(&xs->mutex);
			return -EBUSY;
		}

		umem = xdp_umem_create(&mr);
		if (IS_ERR(umem)) {
			mutex_unlock(&xs->mutex);
			return PTR_ERR(umem);
		}

		/* Make sure umem is ready before it can be seen by others */
		smp_wmb();
		xs->umem = umem;
		mutex_unlock(&xs->mutex);
		return 0;
	}
	case XDP_UMEM_FILL_RING:
	case XDP_UMEM_COMPLETION_RING:
	{
		struct xsk_queue **q;
		int entries;

		if (copy_from_user(&entries, optval, sizeof(entries)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (!xs->umem) {
			mutex_unlock(&xs->mutex);
			return -EINVAL;
		}

		q = (optname == XDP_UMEM_FILL_RING) ? &xs->umem->fq :
			&xs->umem->cq;
		err = xsk_init_queue(entries, q, true);
		mutex_unlock(&xs->mutex);
		return err;
	}
	case XDP_INORDER_COMPLETION:
	{
		u64 flags;

		/* Flags there for possible future extensions. */
		if (copy_from_user(&flags, optval, sizeof(flags)))
			return -EFAULT;

		mutex_lock(&xs->mutex);
		if (!xs->umem) {
			mutex_unlock(&xs->mutex);
			return -EINVAL;
		}

		xs->umem->inorder_completion = true;
		mutex_unlock(&xs->mutex);
		return 0;
	}
	default:
		break;
	}

	return -ENOPROTOOPT;
}

static int xsk_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct xdp_sock *xs = xdp_sk(sk);
	int len;

	if (level != SOL_XDP)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case XDP_STATISTICS:
	{
		struct xdp_statistics stats;

		if (len < sizeof(stats))
			return -EINVAL;

		mutex_lock(&xs->mutex);
		stats.rx_dropped = xs->rx_dropped;
		stats.rx_invalid_descs = xskq_nb_invalid_descs(xs->rx);
		stats.tx_invalid_descs = xskq_nb_invalid_descs(xs->tx);
		mutex_unlock(&xs->mutex);

		if (copy_to_user(optval, &stats, sizeof(stats)))
			return -EFAULT;
		if (put_user(sizeof(stats), optlen))
			return -EFAULT;

		return 0;
	}
	case XDP_MMAP_OFFSETS:
	{
		struct xdp_mmap_offsets off;

		if (len < sizeof(off))
			return -EINVAL;

		off.rx.producer = offsetof(struct xdp_rxtx_ring, ptrs.producer);
		off.rx.consumer = offsetof(struct xdp_rxtx_ring, ptrs.consumer);
		off.rx.desc	= offsetof(struct xdp_rxtx_ring, desc);
		off.tx.producer = offsetof(struct xdp_rxtx_ring, ptrs.producer);
		off.tx.consumer = offsetof(struct xdp_rxtx_ring, ptrs.consumer);
		off.tx.desc	= offsetof(struct xdp_rxtx_ring, desc);

		off.fr.producer = offsetof(struct xdp_umem_ring, ptrs.producer);
		off.fr.consumer = offsetof(struct xdp_umem_ring, ptrs.consumer);
		off.fr.desc	= offsetof(struct xdp_umem_ring, desc);
		off.cr.producer = offsetof(struct xdp_umem_ring, ptrs.producer);
		off.cr.consumer = offsetof(struct xdp_umem_ring, ptrs.consumer);
		off.cr.desc	= offsetof(struct xdp_umem_ring, desc);

		len = sizeof(off);
		if (copy_to_user(optval, &off, len))
			return -EFAULT;
		if (put_user(len, optlen))
			return -EFAULT;

		return 0;
	}
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int xsk_mmap(struct file *file, struct socket *sock,
		    struct vm_area_struct *vma)
{
	loff_t offset = (loff_t)vma->vm_pgoff << PAGE_SHIFT;
	unsigned long size = vma->vm_end - vma->vm_start;
	struct xdp_sock *xs = xdp_sk(sock->sk);
	struct xsk_queue *q = NULL;
	struct xdp_umem *umem;
	unsigned long pfn;
	struct page *qpg;

	if (offset == XDP_PGOFF_RX_RING) {
		q = READ_ONCE(xs->rx);
	} else if (offset == XDP_PGOFF_TX_RING) {
		q = READ_ONCE(xs->tx);
	} else {
		umem = READ_ONCE(xs->umem);
		if (!umem)
			return -EINVAL;

		if (offset == XDP_UMEM_PGOFF_FILL_RING)
			q = READ_ONCE(umem->fq);
		else if (offset == XDP_UMEM_PGOFF_COMPLETION_RING)
			q = READ_ONCE(umem->cq);
	}

	if (!q)
		return -EINVAL;

	qpg = virt_to_head_page(q->ring);
	if (size > (PAGE_SIZE << compound_order(qpg)))
		return -EINVAL;

	pfn = virt_to_phys(q->ring) >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn,
			       size, vma->vm_page_prot);
}

static struct proto xsk_proto = {
	.name =		"XDP",
	.owner =	THIS_MODULE,
	.obj_size =	sizeof(struct xdp_sock),
};

static const struct proto_ops xsk_proto_ops = {
	.family		= PF_XDP,
	.owner		= THIS_MODULE,
	.release	= xsk_release,
	.bind		= xsk_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= xsk_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= xsk_setsockopt,
	.getsockopt	= xsk_getsockopt,
	.sendmsg	= xsk_sendmsg,
	.recvmsg	= sock_no_recvmsg,
	.mmap		= xsk_mmap,
	.sendpage	= sock_no_sendpage,
};

static void xsk_destruct(struct sock *sk)
{
	struct xdp_sock *xs = xdp_sk(sk);

	if (!sock_flag(sk, SOCK_DEAD))
		return;

	xdp_put_umem(xs->umem);

	sk_refcnt_debug_dec(sk);
}

static int xsk_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	struct sock *sk;
	struct xdp_sock *xs;

	if (!ns_capable(net->user_ns, CAP_NET_RAW))
		return -EPERM;
	if (sock->type != SOCK_RAW)
		return -ESOCKTNOSUPPORT;

	if (protocol)
		return -EPROTONOSUPPORT;

	sock->state = SS_UNCONNECTED;

	sk = sk_alloc(net, PF_XDP, GFP_KERNEL, &xsk_proto, kern);
	if (!sk)
		return -ENOBUFS;

	sock->ops = &xsk_proto_ops;

	sock_init_data(sock, sk);

	sk->sk_family = PF_XDP;

	sk->sk_destruct = xsk_destruct;
	sk_refcnt_debug_inc(sk);

	xs = xdp_sk(sk);
	mutex_init(&xs->mutex);
	spin_lock_init(&xs->tx_completion_lock);

	local_bh_disable();
	sock_prot_inuse_add(net, &xsk_proto, 1);
	local_bh_enable();

	return 0;
}

static const struct net_proto_family xsk_family_ops = {
	.family = PF_XDP,
	.create = xsk_create,
	.owner	= THIS_MODULE,
};

static int __init xsk_init(void)
{
	int err;

	err = proto_register(&xsk_proto, 0 /* no slab */);
	if (err)
		goto out;

	err = sock_register(&xsk_family_ops);
	if (err)
		goto out_proto;

	return 0;

out_proto:
	proto_unregister(&xsk_proto);
out:
	return err;
}

fs_initcall(xsk_init);
