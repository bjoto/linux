// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2019 Intel Corporation. */
#include <linux/bpf.h>
#include <linux/filter.h>

/* The BPF dispatcher is a multiway branch code generator. A user
 * registers a slot (id) and can then update the BPF program for that
 * slot. The dispatcher is jited, and will be rejited every time a
 * slot is allocated/deallocated for performance reasons. An example:
 * A module provides code for multiple netdevs. Each netdev can have
 * one XDP program. The module code will allocate a dispatcher, and
 * when the netdev enables XDP it allocates a new slot.
 *
 * Nothing like STATIC_CALL_INLINE is supported yet, so an explicit
 * trampoline is needed:
 *
 *   unsigned int dispatcher_trampoline(void *ctx, void *insn, int id)
 */

static DEFINE_MUTEX(dispatcher_mutex);

struct bpf_dispatcher *bpf_dispatcher_alloc(void *func)
{
	struct bpf_dispatcher *d;
	void *image;

	mutex_lock(&dispatcher_mutex);
	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		goto out;

	image = bpf_jit_alloc_exec(PAGE_SIZE);
	if (!image) {
		kfree(d);
		d = NULL;
		goto out;
	}
	set_vm_flush_reset_perms(image);
	set_memory_x((long)image, 1);
	d->image = image;
	d->func = func; /* XXX Validate with BTF. Only allow one
			 * dispatcher per trampoline, and store them
			 * in a hash similar to what BPF trampoline
			 * does?
			 */

out:
	mutex_unlock(&dispatcher_mutex);
	return d;
}

void bpf_dispatcher_free(struct bpf_dispatcher *d)
{
	mutex_lock(&dispatcher_mutex);
	if (!d)
		return;
	bpf_jit_free_exec(d->image);
	kfree(d);
	mutex_unlock(&dispatcher_mutex);
}

int __weak arch_prepare_bpf_dispatcher(void *image, struct bpf_prog **progs,
				       int num_ids)
{
	return -ENOTSUPP;
}

int bpf_dispatcher_update(struct bpf_dispatcher *d)
{
	void *old_image = d->image + ((d->selector + 1) & 1) * PAGE_SIZE / 2;
	void *new_image = d->image + (d->selector & 1) * PAGE_SIZE / 2;
	int err;

	if (d->num_ids == 0) {
		err = bpf_arch_text_poke(d->func, BPF_MOD_JMP_TO_NOP,
					 old_image, NULL);
		d->selector = 0;
		goto out;
	}

	err = arch_prepare_bpf_dispatcher(new_image, &d->progs[0], d->num_ids);
	if (err)
		goto out;

	if (d->selector)
		/* progs already running at this address */
		err = bpf_arch_text_poke(d->func, BPF_MOD_JMP_TO_JMP,
					 old_image, new_image);
	else
		/* first time registering */
		err = bpf_arch_text_poke(d->func, BPF_MOD_NOP_TO_JMP,
					 NULL, new_image);

	if (err)
		goto out;
	d->selector++;

out:
	return err;
}

int bpf_dispatcher_get_slot(struct bpf_dispatcher *d, int *id,
			    struct bpf_prog *prog)
{
	int i, err;

	if (!prog)
		return -EINVAL;

	mutex_lock(&dispatcher_mutex);
	if (d->num_ids == BPF_DISPATCHER_MAX) {
		err = -EINVAL;
		goto out;
	}

	for (i = 0; i < BPF_DISPATCHER_MAX; i++) {
		if (!d->progs[i]) {
			*id = i;
			break;
		}
	}

	d->num_ids++;
	if (*id + 1 > d->max_ids)
		d->max_ids = *id + 1;

	d->progs[*id] = prog; /* XXX refcount? */

	err = bpf_dispatcher_update(d);
	if (err)
		goto out; /* XXX rollback on error? */

out:
	mutex_unlock(&dispatcher_mutex);
	return err;
}

int bpf_dispatcher_update_slot(struct bpf_dispatcher *d, int id,
			       struct bpf_prog *prog)
{
	int err;

	if (!prog)
		return -EINVAL;

	mutex_lock(&dispatcher_mutex);
	d->progs[id] = prog; /* XXX refcount? */
	err = bpf_dispatcher_update(d);
	if (err)
		goto out; /* XXX rollback on error? */

out:
	mutex_unlock(&dispatcher_mutex);
	return err;
}

int bpf_dispatcher_remove_slot(struct bpf_dispatcher *d, int id)
{
	int err;

	mutex_lock(&dispatcher_mutex);

	d->progs[id] = NULL;

	if (id + 1 == d->max_ids)
		d->max_ids--;
	d->num_ids--;

	err = bpf_dispatcher_update(d);
	if (err)
		goto out; /* XXX rollback on error? */

out:
	mutex_unlock(&dispatcher_mutex);
	return err;
}
