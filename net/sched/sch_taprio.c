/*
 * net/sched/sch_taprio.c	 Time Aware Priority Scheduler
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Vinicius Costa Gomes <vinicius.gomes@intel.com>
 *
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/sch_generic.h>

struct sched_entry {
	struct list_head list;
	int index;
	u32 gate_mask;
	u32 interval;
	u8 command;
};

struct taprio_sched {
	struct Qdisc **qdiscs;
	struct Qdisc *root;
	s64 base_time;
	s64 cycle_time;
	s64 extension_time;
	u32 preempt_mask;
	size_t num_entries;
	ktime_t current_expires;
	ktime_t next_cycle_start;
	int picos_per_byte;
	spinlock_t current_entry_lock;
	struct sched_entry __rcu *current_entry;
	atomic_t budget;
	struct list_head entries;
	struct hrtimer advance_timer;
	int clockid;
	ktime_t (*get_time)(void);
};

static int taprio_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	int prio = skb->priority;
	struct Qdisc *child;
	u8 tc;

	tc = netdev_get_prio_tc_map(dev, prio);

	if (unlikely(tc >= netdev_get_num_tc(dev)))
		return qdisc_drop(skb, sch, to_free);

	child = q->qdiscs[tc];
	if (unlikely(!child))
		return qdisc_drop(skb, sch, to_free);

	qdisc_qstats_backlog_inc(sch, skb);
	sch->q.qlen++;

	return child->ops->enqueue(skb, child, to_free);
}

static struct sk_buff *taprio_peek(struct Qdisc *sch)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct sched_entry *entry;
	struct sk_buff *skb;
	u32 gate_mask;
	int i;

	rcu_read_lock();
	entry = rcu_dereference(q->current_entry);
	gate_mask = entry ? entry->gate_mask : -1;
	rcu_read_unlock();

	if (!gate_mask)
		return NULL;

	for (i = 0; i < netdev_get_num_tc(dev); i++) {
		struct Qdisc *child = q->qdiscs[i];

		if (!(gate_mask & BIT(i)))
			continue;

		if (unlikely(!child))
			return NULL;

		skb = child->ops->peek(child);
		if (skb)
			return skb;
	}

	return NULL;
}

static inline int length_to_duration(struct taprio_sched *q, int len)
{
	return (len * q->picos_per_byte) / 1000;
}

static struct sk_buff *taprio_dequeue(struct Qdisc *sch)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct sched_entry *entry;
	struct sk_buff *skb;
	u32 gate_mask;
	int i;

	rcu_read_lock();
	entry = rcu_dereference(q->current_entry);
	gate_mask = entry ? entry->gate_mask : -1;
	rcu_read_unlock();

	if (!gate_mask)
		return NULL;

	for (i = 0; i < netdev_get_num_tc(dev); i++) {
		struct Qdisc *child = q->qdiscs[i];
		ktime_t now;
		int len;

		if (!(gate_mask & BIT(i)))
			continue;

		if (unlikely(!child))
			continue;

		skb = child->ops->peek(child);
		if (!skb)
			continue;

		len = qdisc_pkt_len(skb);
		now = q->get_time();

		/* In the case that there's no gate entry, there's no
		 * guard band ...
		 */
		if (entry &&
		    ktime_after(now + length_to_duration(q, len), q->current_expires))
			return NULL;

		/* ... and no budget. */
		if (entry && atomic_sub_return(len, &q->budget) < 0)
			return NULL;

		skb = child->ops->dequeue(child);
		if (unlikely(skb == NULL))
			return NULL;

		qdisc_bstats_update(sch, skb);
		qdisc_qstats_backlog_dec(sch, skb);
		sch->q.qlen--;

		return skb;
	}

	return NULL;
}

static bool restart_cycle(struct taprio_sched *q, struct sched_entry *entry)
{
	if (list_is_last(&entry->list, &q->entries))
		return true;

	if (q->current_expires == q->next_cycle_start)
		return true;

	return false;
}

static enum hrtimer_restart advance_sched(struct hrtimer *timer)
{
	struct taprio_sched *q = container_of(timer, struct taprio_sched,
					      advance_timer);
	struct Qdisc *sch = q->root;
	struct sched_entry *entry, *next;
	ktime_t expires;

	spin_lock(&q->current_entry_lock);
	entry = rcu_dereference_protected(q->current_entry,
					  lockdep_is_held(&q->current_entry_lock));

	if (!entry || restart_cycle(q, entry)) {
		next = list_first_entry(&q->entries, struct sched_entry, list);

		/* If we come to the end of a cycle, update the start
		 * of a next cycle
		 */
		if (q->current_expires <= q->next_cycle_start)
			q->next_cycle_start += q->cycle_time;
	} else {
		next = list_next_entry(entry, list);
	}

	expires = ktime_add_ns(q->current_expires, next->interval);
	expires = min_t(ktime_t, q->next_cycle_start, expires);

	rcu_assign_pointer(q->current_entry, next);
	q->current_expires = expires;
	atomic_set(&q->budget, (next->interval * 1000) / q->picos_per_byte);

	spin_unlock(&q->current_entry_lock);

	hrtimer_set_expires(&q->advance_timer, expires);

	rcu_read_lock();
	__netif_schedule(sch);
	rcu_read_unlock();

	return HRTIMER_RESTART;
}

static const struct nla_policy entry_policy[TCA_TAPRIO_SCHED_ENTRY_MAX + 1] = {
	[TCA_TAPRIO_SCHED_ENTRY_INDEX]	   = { .type = NLA_U32 },
	[TCA_TAPRIO_SCHED_ENTRY_CMD]	   = { .type = NLA_U8 },
	[TCA_TAPRIO_SCHED_ENTRY_GATE_MASK] = { .type = NLA_U32 },
	[TCA_TAPRIO_SCHED_ENTRY_INTERVAL]  = { .type = NLA_U32 },
};

static const struct nla_policy entry_list_policy[TCA_TAPRIO_SCHED_MAX + 1] = {
	[TCA_TAPRIO_SCHED_ENTRY] = { .type = NLA_NESTED },
};

static const struct nla_policy taprio_policy[TCA_TAPRIO_ATTR_MAX + 1] = {
	[TCA_TAPRIO_ATTR_PRIOMAP]	       = {
		.len = sizeof(struct tc_mqprio_qopt)
	},
	[TCA_TAPRIO_ATTR_PREEMPT_MASK]	       = { .type = NLA_U32 },
	[TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST]     = { .type = NLA_NESTED },
	[TCA_TAPRIO_ATTR_SCHED_BASE_TIME]      = { .type = NLA_S64 },
	[TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME]     = { .type = NLA_S64 },
	[TCA_TAPRIO_ATTR_SCHED_EXTENSION_TIME] = { .type = NLA_S64 },
	[TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY]   = { .type = NLA_NESTED },
	[TCA_TAPRIO_ATTR_SCHED_CLOCKID]        = { .type = NLA_S32 },
};

static int parse_sched_entry(struct nlattr *n, struct sched_entry *entry,
			     int index)
{
	struct nlattr *tb[TCA_TAPRIO_SCHED_ENTRY_MAX + 1] = { };
	int err;

	err = nla_parse_nested(tb, TCA_TAPRIO_SCHED_ENTRY_MAX, n,
			       entry_policy, NULL);
	if (err < 0) {
		pr_err("Could not parse nested entry");
		return -EINVAL;
	}

	entry->index = index;

	if (tb[TCA_TAPRIO_SCHED_ENTRY_CMD])
		entry->command = nla_get_u8(tb[TCA_TAPRIO_SCHED_ENTRY_CMD]);

	if (tb[TCA_TAPRIO_SCHED_ENTRY_GATE_MASK])
		entry->gate_mask = nla_get_u32(
			tb[TCA_TAPRIO_SCHED_ENTRY_GATE_MASK]);

	if (tb[TCA_TAPRIO_SCHED_ENTRY_INTERVAL])
		entry->interval = nla_get_u32(
			tb[TCA_TAPRIO_SCHED_ENTRY_INTERVAL]);

	return 0;
}

static int parse_sched_single_entry(struct nlattr *n,
				    struct taprio_sched *q)
{
	struct nlattr *tb_entry[TCA_TAPRIO_SCHED_ENTRY_MAX + 1] = { };
	struct nlattr *tb_list[TCA_TAPRIO_SCHED_MAX + 1] = { };
	struct sched_entry *entry;
	bool found = false;
	u32 index;
	int err;

	err = nla_parse_nested(tb_list, TCA_TAPRIO_SCHED_MAX,
			       n, entry_list_policy, NULL);
	if (err < 0) {
		pr_err("Could not parse nested entry");
		return -EINVAL;
	}

	if (!tb_list[TCA_TAPRIO_SCHED_ENTRY]) {
		pr_err("Single-entry must include an entry\n");
		return -EINVAL;
	}

	err = nla_parse_nested(tb_entry, TCA_TAPRIO_SCHED_ENTRY_MAX,
			       tb_list[TCA_TAPRIO_SCHED_ENTRY],
			       entry_policy, NULL);
	if (err < 0) {
		pr_err("Could not parse nested entry");
		return -EINVAL;
	}

	if (!tb_entry[TCA_TAPRIO_SCHED_ENTRY_INDEX]) {
		pr_err("Entry must specify an index\n");
		return -EINVAL;
	}

	index = nla_get_u32(tb_entry[TCA_TAPRIO_SCHED_ENTRY_INDEX]);
	if (index >= q->num_entries) {
		pr_err("Invalid index for single entry %d (max %zu)\n",
		       index, q->num_entries);
		return -EINVAL;
	}

	list_for_each_entry(entry, &q->entries, list) {
		if (entry->index == index) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_err("Could not find entry with index '%d'\n", index);
		return -ENOENT;
	}

	if (tb_entry[TCA_TAPRIO_SCHED_ENTRY_CMD])
		entry->command = nla_get_u8(
			tb_entry[TCA_TAPRIO_SCHED_ENTRY_CMD]);

	if (tb_entry[TCA_TAPRIO_SCHED_ENTRY_GATE_MASK])
		entry->gate_mask = nla_get_u32(
			tb_entry[TCA_TAPRIO_SCHED_ENTRY_GATE_MASK]);

	if (tb_entry[TCA_TAPRIO_SCHED_ENTRY_INTERVAL])
		entry->interval = nla_get_u32(
			tb_entry[TCA_TAPRIO_SCHED_ENTRY_INTERVAL]);

	return 0;
}

static int parse_sched_list(struct nlattr *list,
			    struct taprio_sched *q)
{
	struct nlattr *n;
	int err, rem;
	int i = 0;

	if (!list)
		return -EINVAL;

	nla_for_each_nested(n, list, rem) {
		struct sched_entry *entry;

		if (nla_type(n) != TCA_TAPRIO_SCHED_ENTRY) {
			pr_err("Invalid type parsing sched entries %x",
			       nla_type(n));
			continue;
		}

		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			return -ENOMEM;

		err = parse_sched_entry(n, entry, i);
		if (err < 0) {
			kfree(entry);
			return err;
		}

		list_add_tail(&entry->list, &q->entries);
		i++;
	}

	q->num_entries = i;

	return i;
}

static int parse_taprio_opt(struct nlattr **tb, struct taprio_sched *q,
			    struct netlink_ext_ack *extack)
{
	int err = 0;
	int clockid;

	if (tb[TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST] &&
	    tb[TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY])
		return -EINVAL;

	if (tb[TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY] && q->num_entries == 0)
		return -EINVAL;

	if (q->clockid == -1 && !tb[TCA_TAPRIO_ATTR_SCHED_CLOCKID])
		return -EINVAL;

	if (tb[TCA_TAPRIO_ATTR_PREEMPT_MASK])
		q->preempt_mask = nla_get_u32(
			tb[TCA_TAPRIO_ATTR_PREEMPT_MASK]);

	if (tb[TCA_TAPRIO_ATTR_SCHED_BASE_TIME])
		q->base_time = nla_get_s64(
			tb[TCA_TAPRIO_ATTR_SCHED_BASE_TIME]);

	if (tb[TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME])
		q->cycle_time = nla_get_s64(
			tb[TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME]);

	if (tb[TCA_TAPRIO_ATTR_SCHED_EXTENSION_TIME])
		q->extension_time = nla_get_s64(
			tb[TCA_TAPRIO_ATTR_SCHED_EXTENSION_TIME]);

	if (tb[TCA_TAPRIO_ATTR_SCHED_CLOCKID]) {
		clockid = nla_get_s32(tb[TCA_TAPRIO_ATTR_SCHED_CLOCKID]);

		/* We only support static clockids and we don't allow for it to
		 * be modified after the first init.
		 */
		if (clockid < 0 || (q->clockid != -1 && q->clockid != clockid))
			return -EINVAL;

		q->clockid = clockid;
	}

	if (tb[TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST])
		err = parse_sched_list(
			tb[TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST], q);
	else if (tb[TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY])
		err = parse_sched_single_entry(
			tb[TCA_TAPRIO_ATTR_SCHED_SINGLE_ENTRY], q);

	if (err < 0)
		return err;

	return 0;
}

static int taprio_parse_mqprio_opt(struct net_device *dev,
				   struct tc_mqprio_qopt *qopt,
				   struct netlink_ext_ack *extack)
{
	int i;

	if (!qopt)
		return -EINVAL;

	/* Verify num_tc is not out of max range */
	if (qopt->num_tc > TC_MAX_QUEUE) {
		return -EINVAL;
	}

	/* taprio imposes that traffic classes map 1:1 to tx queues */
	if (qopt->num_tc > dev->real_num_tx_queues)
		return -EINVAL;

	/* Verify priority mapping uses valid tcs */
	for (i = 0; i < TC_BITMASK + 1; i++) {
		if (qopt->prio_tc_map[i] >= qopt->num_tc)
			return -EINVAL;
	}

	for (i = 0; i < qopt->num_tc; i++) {
		if (qopt->count[i] != 1)
			return -EINVAL;

		/* Verify the queue count is in tx range being equal to the
		 * real_num_tx_queues indicates the last queue is in use.
		 */
		if (qopt->offset[i] >= dev->real_num_tx_queues)
			return -EINVAL;
	}

	return 0;
}

static ktime_t taprio_get_first_expires(struct Qdisc *sch)
{
	struct taprio_sched *q = qdisc_priv(sch);
	ktime_t now, base, cycle, expires;
	struct sched_entry *entry;
	s64 n;

	now = q->get_time();
	base = ns_to_ktime(q->base_time);

	cycle = q->cycle_time;

	/* If we don't have a cycle_time, we calculate one, by summing
	 * all the intervals.
	 */
	if (!cycle) {
		list_for_each_entry(entry, &q->entries, list) {
			cycle += entry->interval;
		}
		q->cycle_time = cycle;
	}

	if (!cycle)
		return base;

	if (ktime_after(base, now))
		return base;

	/* Schedule the next expiration for the beginning of the next
	 * cycle.
	 */
	n = div64_s64(now - base, cycle);
	expires = base;
	expires += (n + 1) * cycle;

	return expires;
}

static int taprio_change(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack)
{
	struct nlattr *tb[TCA_TAPRIO_ATTR_MAX + 1] = { };
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct tc_mqprio_qopt *mqprio = NULL;
	struct ethtool_link_ksettings ecmd;
	s64 link_speed;
	int i, err, size;
	ktime_t expires;

	err = nla_parse_nested(tb, TCA_TAPRIO_ATTR_MAX, opt,
			       taprio_policy, extack);
	if (err < 0)
		return err;

	err = -EINVAL;
	if (tb[TCA_TAPRIO_ATTR_PRIOMAP])
		mqprio = nla_data(tb[TCA_TAPRIO_ATTR_PRIOMAP]);

	err = taprio_parse_mqprio_opt(dev, mqprio, extack);
	if (err < 0)
		return err;

	size = parse_taprio_opt(tb, q, extack);
	if (size < 0)
		return size;

	hrtimer_init(&q->advance_timer, q->clockid, HRTIMER_MODE_ABS);
	q->advance_timer.function = advance_sched;
	switch (q->clockid) {
	case CLOCK_REALTIME:
		q->get_time = ktime_get_real;
		break;
	case CLOCK_MONOTONIC:
		q->get_time = ktime_get;
		break;
	case CLOCK_BOOTTIME:
		q->get_time = ktime_get_boottime;
		break;
	case CLOCK_TAI:
		q->get_time = ktime_get_clocktai;
		break;
	default:
		return -ENOTSUPP;
	}

	for (i = 0; i < mqprio->num_tc; i++) {
		struct netdev_queue *dev_queue;
		struct Qdisc *qdisc;

		dev_queue = netdev_get_tx_queue(dev, mqprio->offset[i]);
		qdisc = qdisc_create_dflt(dev_queue,
					  get_default_qdisc_ops(dev, i),
					  TC_H_MAKE(TC_H_MAJ(sch->handle),
						    TC_H_MIN(i + 1)),
					  extack);
		if (!qdisc)
			return -ENOMEM;

		q->qdiscs[i] = dev_graft_qdisc(dev_queue, sch);
		qdisc_refcount_inc(sch);

		qdisc->flags |= TCQ_F_ONETXQUEUE | TCQ_F_NOPARENT;
	}

	if (mqprio) {
		netdev_set_num_tc(dev, mqprio->num_tc);
		for (i = 0; i < mqprio->num_tc; i++)
			netdev_set_tc_queue(dev, i,
					    mqprio->count[i],
					    mqprio->offset[i]);

		/* Always use supplied priority mappings */
		for (i = 0; i < TC_BITMASK + 1; i++)
			netdev_set_prio_tc_map(dev, i,
					       mqprio->prio_tc_map[i]);
	}

	if (!__ethtool_get_link_ksettings(dev, &ecmd))
		link_speed = ecmd.base.speed;
	else
		link_speed = SPEED_1000;

	q->picos_per_byte = ((NSEC_PER_SEC * 1000) / (link_speed * 1000 * 1000)) * 8;

	pr_debug("picos_per_byte %d\n", q->picos_per_byte);

	sch->flags |= TCQ_F_MQROOT;

	expires = taprio_get_first_expires(sch);
	if (!expires)
		return 0;

	q->current_expires = expires;
	q->next_cycle_start = expires + q->cycle_time;
	hrtimer_start(&q->advance_timer, expires, HRTIMER_MODE_ABS);

	return 0;
}

static void taprio_destroy(struct Qdisc *sch)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct sched_entry *entry, *n;
	unsigned int i;

	/* Only cancel hrtimer if it's been initialized. */
	if (q->clockid != -1)
		hrtimer_cancel(&q->advance_timer);

	if (q->qdiscs) {
		for (i = 0; i < netdev_get_num_tc(dev) && q->qdiscs[i]; i++) {
			qdisc_destroy(q->qdiscs[i]);
			qdisc_destroy(sch);
		}
		kfree(q->qdiscs);
	}
	q->qdiscs = NULL;

	netdev_set_num_tc(dev, 0);

	list_for_each_entry_safe(entry, n, &q->entries, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static int taprio_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	INIT_LIST_HEAD(&q->entries);
	RCU_INIT_POINTER(q->current_entry, NULL);
	spin_lock_init(&q->current_entry_lock);
	q->root = sch;

	/* We only support static clockids. Use an invalid value as default
	 * and get the valid one on taprio_change().
	 */
	q->clockid = -1;

	if (sch->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	if (!netif_is_multiqueue(dev))
		return -EOPNOTSUPP;

	/* pre-allocate qdisc, attachment can't fail */
	q->qdiscs = kcalloc(dev->real_num_tx_queues,
			    sizeof(q->qdiscs[0]),
			    GFP_KERNEL);
	if (!q->qdiscs)
		return -ENOMEM;

	if (!opt)
		return -EINVAL;

	return taprio_change(sch, opt, extack);
}

static struct netdev_queue *taprio_queue_get(struct Qdisc *sch,
					     unsigned long cl)
{
	struct net_device *dev = qdisc_dev(sch);
	unsigned long ntx = cl - 1;

	if (ntx >= netdev_get_num_tc(dev))
		return NULL;

	return netdev_get_tx_queue(dev, dev->tc_to_txq[ntx].offset);
}

static int taprio_graft(struct Qdisc *sch, unsigned long cl,
			struct Qdisc *new, struct Qdisc **old,
			struct netlink_ext_ack *extack)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct netdev_queue *dev_queue = taprio_queue_get(sch, cl);

	if (!dev_queue)
		return -EINVAL;

	if (dev->flags & IFF_UP)
		dev_deactivate(dev);

	*old = q->qdiscs[cl - 1];
	q->qdiscs[cl - 1] = new;

	if (new)
		new->flags |= TCQ_F_ONETXQUEUE | TCQ_F_NOPARENT;

	if (dev->flags & IFF_UP)
		dev_activate(dev);

	return 0;
}

static int dump_entry(struct sk_buff *msg,
		      const struct sched_entry *entry)
{
	struct nlattr *item;

	item = nla_nest_start(msg, TCA_TAPRIO_SCHED_ENTRY);
	if (!item)
		return -ENOSPC;

	if (nla_put_u32(msg, TCA_TAPRIO_SCHED_ENTRY_INDEX, entry->index))
		goto nla_put_failure;

	if (nla_put_u8(msg, TCA_TAPRIO_SCHED_ENTRY_CMD, entry->command))
		goto nla_put_failure;

	if (nla_put_u32(msg, TCA_TAPRIO_SCHED_ENTRY_GATE_MASK, entry->gate_mask))
		goto nla_put_failure;

	if (nla_put_u32(msg, TCA_TAPRIO_SCHED_ENTRY_INTERVAL, entry->interval))
		goto nla_put_failure;

	return nla_nest_end(msg, item);

nla_put_failure:
	nla_nest_cancel(msg, item);
	return -1;
}

static int taprio_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct taprio_sched *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct tc_mqprio_qopt opt = { 0 };
	struct nlattr *nest, *entry_list;
	struct sched_entry *entry;
	struct Qdisc *qdisc;
	unsigned int i;

	sch->q.qlen = 0;
	memset(&sch->bstats, 0, sizeof(sch->bstats));
	memset(&sch->qstats, 0, sizeof(sch->qstats));

	for (i = 0; i < netdev_get_num_tc(dev); i++) {
		qdisc = rtnl_dereference(netdev_get_tx_queue(dev, i)->qdisc);
		spin_lock_bh(qdisc_lock(qdisc));
		sch->q.qlen		+= qdisc->q.qlen;
		sch->bstats.bytes	+= qdisc->bstats.bytes;
		sch->bstats.packets	+= qdisc->bstats.packets;
		sch->qstats.backlog	+= qdisc->qstats.backlog;
		sch->qstats.drops	+= qdisc->qstats.drops;
		sch->qstats.requeues	+= qdisc->qstats.requeues;
		sch->qstats.overlimits	+= qdisc->qstats.overlimits;
		spin_unlock_bh(qdisc_lock(qdisc));
	}

	opt.num_tc = netdev_get_num_tc(dev);
	memcpy(opt.prio_tc_map, dev->prio_tc_map, sizeof(opt.prio_tc_map));

	for (i = 0; i < netdev_get_num_tc(dev); i++) {
		opt.count[i] = dev->tc_to_txq[i].count;
		opt.offset[i] = dev->tc_to_txq[i].offset;
	}

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (!nest)
		return -ENOSPC;

	if (nla_put(skb, TCA_TAPRIO_ATTR_PRIOMAP, sizeof(opt), &opt))
		goto options_error;

	if (nla_put_u32(skb, TCA_TAPRIO_ATTR_PREEMPT_MASK, q->preempt_mask))
		goto options_error;

	if (nla_put_s64(skb, TCA_TAPRIO_ATTR_SCHED_BASE_TIME,
			q->base_time, TCA_TAPRIO_PAD))
		goto options_error;

	if (nla_put_s64(skb, TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME,
			q->cycle_time, TCA_TAPRIO_PAD))
		goto options_error;

	if (nla_put_s64(skb, TCA_TAPRIO_ATTR_SCHED_EXTENSION_TIME,
			q->extension_time, TCA_TAPRIO_PAD))
		goto options_error;

	if (nla_put_s32(skb, TCA_TAPRIO_ATTR_SCHED_CLOCKID, q->clockid))
		goto options_error;

	entry_list = nla_nest_start(skb, TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST);
	if (!entry_list)
		goto options_error;

	list_for_each_entry(entry, &q->entries, list) {
		if (dump_entry(skb, entry) < 0)
			goto options_error;
	}

	nla_nest_end(skb, entry_list);

	return nla_nest_end(skb, nest);

options_error:
	nla_nest_cancel(skb, nest);
	return -1;
}

static struct Qdisc *taprio_leaf(struct Qdisc *sch, unsigned long cl)
{
	struct netdev_queue *dev_queue = taprio_queue_get(sch, cl);

	if (!dev_queue)
		return NULL;

	return dev_queue->qdisc_sleeping;
}

static unsigned long taprio_find(struct Qdisc *sch, u32 classid)
{
	unsigned int ntx = TC_H_MIN(classid);

	if (!taprio_queue_get(sch, ntx))
		return 0;
	return ntx;
}

static int taprio_dump_class(struct Qdisc *sch, unsigned long cl,
			 struct sk_buff *skb, struct tcmsg *tcm)
{
	struct netdev_queue *dev_queue = taprio_queue_get(sch, cl);

	tcm->tcm_parent = TC_H_ROOT;
	tcm->tcm_handle |= TC_H_MIN(cl);
	tcm->tcm_info = dev_queue->qdisc_sleeping->handle;

	return 0;
}

static int taprio_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				   struct gnet_dump *d)
	__releases(d->lock)
	__acquires(d->lock)
{
	struct netdev_queue *dev_queue = taprio_queue_get(sch, cl);

	sch = dev_queue->qdisc_sleeping;
	if (gnet_stats_copy_basic(&sch->running, d, NULL, &sch->bstats) < 0 ||
	    gnet_stats_copy_queue(d, NULL, &sch->qstats, sch->q.qlen) < 0)
		return -1;
	return 0;
}

static void taprio_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct net_device *dev = qdisc_dev(sch);
	unsigned long ntx;

	if (arg->stop)
		return;

	arg->count = arg->skip;
	for (ntx = arg->skip; ntx < netdev_get_num_tc(dev); ntx++) {
		if (arg->fn(sch, ntx + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static struct netdev_queue *taprio_select_queue(struct Qdisc *sch,
					    struct tcmsg *tcm)
{
	return taprio_queue_get(sch, TC_H_MIN(tcm->tcm_parent));
}

static const struct Qdisc_class_ops taprio_class_ops = {
	.graft		= taprio_graft,
	.leaf		= taprio_leaf,
	.find		= taprio_find,
	.walk		= taprio_walk,
	.dump		= taprio_dump_class,
	.dump_stats	= taprio_dump_class_stats,
	.select_queue	= taprio_select_queue,
};

static struct Qdisc_ops taprio_qdisc_ops __read_mostly = {
	.cl_ops		= &taprio_class_ops,
	.id		= "taprio",
	.priv_size	= sizeof(struct taprio_sched),
	.init		= taprio_init,
	.change		= taprio_change,
	.destroy	= taprio_destroy,
	.peek		= taprio_peek,
	.dequeue	= taprio_dequeue,
	.enqueue	= taprio_enqueue,
	.dump		= taprio_dump,
	.owner		= THIS_MODULE,
};

static int __init taprio_module_init(void)
{
	return register_qdisc(&taprio_qdisc_ops);
}

static void __exit taprio_module_exit(void)
{
	unregister_qdisc(&taprio_qdisc_ops);
}

module_init(taprio_module_init);
module_exit(taprio_module_exit);
MODULE_LICENSE("GPL");
