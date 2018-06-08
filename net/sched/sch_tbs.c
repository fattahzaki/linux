// SPDX-License-Identifier: GPL-2.0

/* net/sched/sch_tbs.c	Time-Based Scheduler
 *
 * Authors:	Jesus Sanchez-Palencia <jesus.sanchez-palencia@intel.com>
 *		Vinicius Costa Gomes <vinicius.gomes@intel.com>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <linux/posix-timers.h>
#include <net/netlink.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/sock.h>

#define SORTING_IS_ON(x) (x->flags & TC_TBS_SORTING_ON)
#define DEADLINE_MODE_IS_ON(x) (x->flags & TC_TBS_DEADLINE_MODE_ON)

struct tbs_sched_data {
	bool sorting;
	bool deadline_mode;
	int clockid;
	int queue;
	s32 delta; /* in ns */
	ktime_t last; /* The txtime of the last skb sent to the netdevice. */
	struct rb_root head;
	struct qdisc_watchdog watchdog;
	int (*enqueue)(struct sk_buff *skb, struct Qdisc *sch);
	struct sk_buff *(*dequeue)(struct Qdisc *sch);
	struct sk_buff *(*peek)(struct Qdisc *sch);
	ktime_t (*get_time)(void);
};

static const struct nla_policy tbs_policy[TCA_TBS_MAX + 1] = {
	[TCA_TBS_PARMS]	= { .len = sizeof(struct tc_tbs_qopt) },
};

static inline int validate_input_params(struct tc_tbs_qopt *qopt,
					struct netlink_ext_ack *extack)
{
	/* Check if params comply to the following rules:
	 *	* If SW best-effort, then sorting must be ON.
	 *
	 *	* If sorting is ON, then clockid and delta must be valid.
	 *
	 *	* Dynamic clockids are not supported.
	 *	* Delta must be a positive integer.
	 */
	if (qopt->clockid >= MAX_CLOCKS) {
		NL_SET_ERR_MSG(extack, "Invalid clockid");
		return -EINVAL;
	} else if (qopt->clockid < 0) {
		NL_SET_ERR_MSG(extack, "Clockid is not supported");
		return -ENOTSUPP;
	}

	if (qopt->delta < 0) {
		NL_SET_ERR_MSG(extack, "Delta must be positive");
		return -EINVAL;
	}

	return 0;
}

static bool is_packet_valid(struct Qdisc *sch, struct sk_buff *nskb)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	ktime_t txtime = nskb->tstamp;
	struct sock *sk = nskb->sk;
	ktime_t now;

	if (!sk)
		return false;

	if (!sock_flag(sk, SOCK_TXTIME))
		return false;

	/* We don't perform crosstimestamping.
	 * Drop if packet's clockid differs from qdisc's.
	 */
	if (sk->sk_clockid != q->clockid)
		return false;

	if ((sk->sk_txtime_flags & SK_TXTIME_DEADLINE_MASK) !=
	    q->deadline_mode)
		return false;

	now = q->get_time();
	if (ktime_before(txtime, now) || ktime_before(txtime, q->last))
		return false;

	return true;
}

static struct sk_buff *tbs_peek(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);

	return q->peek(sch);
}

static struct sk_buff *tbs_peek_timesortedlist(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	struct rb_node *p;

	p = rb_first(&q->head);
	if (!p)
		return NULL;

	return rb_to_skb(p);
}

static void reset_watchdog(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = tbs_peek(sch);
	ktime_t next;

	if (!skb)
		return;

	next = ktime_sub_ns(skb->tstamp, q->delta);
	qdisc_watchdog_schedule_ns(&q->watchdog, ktime_to_ns(next));
}

static int tbs_enqueue(struct sk_buff *nskb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	struct tbs_sched_data *q = qdisc_priv(sch);

	if (!is_packet_valid(sch, nskb))
		return qdisc_drop(nskb, sch, to_free);

	return q->enqueue(nskb, sch);
}

static int tbs_enqueue_timesortedlist(struct sk_buff *nskb, struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	struct rb_node **p = &q->head.rb_node, *parent = NULL;
	ktime_t txtime = nskb->tstamp;

	while (*p) {
		struct sk_buff *skb;

		parent = *p;
		skb = rb_to_skb(parent);
		if (ktime_after(txtime, skb->tstamp))
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
	rb_link_node(&nskb->rbnode, parent, p);
	rb_insert_color(&nskb->rbnode, &q->head);

	qdisc_qstats_backlog_inc(sch, nskb);
	sch->q.qlen++;

	/* Now we may need to re-arm the qdisc watchdog for the next packet. */
	reset_watchdog(sch);

	return NET_XMIT_SUCCESS;
}

static void timesortedlist_erase(struct Qdisc *sch, struct sk_buff *skb,
				 bool drop)
{
	struct tbs_sched_data *q = qdisc_priv(sch);

	rb_erase(&skb->rbnode, &q->head);

	/* The rbnode field in the skb re-uses these fields, now that
	 * we are done with the rbnode, reset them.
	 */
	skb->next = NULL;
	skb->prev = NULL;
	skb->dev = qdisc_dev(sch);

	qdisc_qstats_backlog_dec(sch, skb);

	if (drop) {
		struct sk_buff *to_free = NULL;

		qdisc_drop(skb, sch, &to_free);
		kfree_skb_list(to_free);
		qdisc_qstats_overlimit(sch);
	} else {
		qdisc_bstats_update(sch, skb);

		q->last = skb->tstamp;
	}

	sch->q.qlen--;
}

static struct sk_buff *tbs_dequeue(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);

	return q->dequeue(sch);
}

static struct sk_buff *tbs_dequeue_timesortedlist(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	ktime_t now, next;

	skb = tbs_peek(sch);
	if (!skb)
		return NULL;

	now = q->get_time();

	/* Drop if packet has expired while in queue. */
	/* FIXME: Must return error on the socket's error queue */
	if (ktime_before(skb->tstamp, now)) {
		timesortedlist_erase(sch, skb, true);
		skb = NULL;
		goto out;
	}

	/* When in deadline mode, dequeue as soon as possible and change the
	 * txtime from deadline to (now + delta).
	 */
	if (q->deadline_mode) {
		timesortedlist_erase(sch, skb, false);
		skb->tstamp = now;
		goto out;
	}

	next = ktime_sub_ns(skb->tstamp, q->delta);

	/* Dequeue only if now is within the [txtime - delta, txtime] range. */
	if (ktime_after(now, next))
		timesortedlist_erase(sch, skb, false);
	else
		skb = NULL;

out:
	/* Now we may need to re-arm the qdisc watchdog for the next packet. */
	reset_watchdog(sch);

	return skb;
}

static inline void setup_queueing_mode(struct tbs_sched_data *q)
{
	if (q->sorting) {
		q->enqueue = tbs_enqueue_timesortedlist;
		q->dequeue = tbs_dequeue_timesortedlist;
		q->peek = tbs_peek_timesortedlist;
	}
}

static int tbs_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct nlattr *tb[TCA_TBS_MAX + 1];
	struct tc_tbs_qopt *qopt;
	int err;

	if (!opt) {
		NL_SET_ERR_MSG(extack,
			       "Missing TBS qdisc options which are mandatory");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_TBS_MAX, opt, tbs_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_TBS_PARMS]) {
		NL_SET_ERR_MSG(extack, "Missing mandatory TBS parameters");
		return -EINVAL;
	}

	qopt = nla_data(tb[TCA_TBS_PARMS]);

	pr_debug("delta %d clockid %d sorting %s deadline %s\n",
		 qopt->delta, qopt->clockid,
		 SORTING_IS_ON(qopt) ? "on" : "off",
		 DEADLINE_MODE_IS_ON(qopt) ? "on" : "off");

	err = validate_input_params(qopt, extack);
	if (err < 0)
		return err;

	q->queue = sch->dev_queue - netdev_get_tx_queue(dev, 0);

	/* Everything went OK, save the parameters used. */
	q->delta = qopt->delta;
	q->clockid = qopt->clockid;
	q->sorting = SORTING_IS_ON(qopt);
	q->deadline_mode = DEADLINE_MODE_IS_ON(qopt);

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
		NL_SET_ERR_MSG(extack, "Clockid is not supported");
		return -ENOTSUPP;
	}

	/* Select queueing mode based on parameters. */
	setup_queueing_mode(q);

	qdisc_watchdog_init_clockid(&q->watchdog, sch, q->clockid);

	return 0;
}

static void timesortedlist_clear(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	struct rb_node *p = rb_first(&q->head);

	while (p) {
		struct sk_buff *skb = rb_to_skb(p);

		p = rb_next(p);

		rb_erase(&skb->rbnode, &q->head);
		rtnl_kfree_skbs(skb, skb);
		sch->q.qlen--;
	}
}

static void tbs_reset(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);

	/* No matter which mode we are on, it's safe to clear both lists. */
	timesortedlist_clear(sch);
	__qdisc_reset_queue(&sch->q);

	sch->qstats.backlog = 0;
	sch->q.qlen = 0;

	q->last = 0;
}

static void tbs_destroy(struct Qdisc *sch)
{
	struct tbs_sched_data *q = qdisc_priv(sch);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);
}

static int tbs_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tbs_sched_data *q = qdisc_priv(sch);
	struct tc_tbs_qopt opt = { };
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	opt.delta = q->delta;
	opt.clockid = q->clockid;
	if (q->sorting)
		opt.flags |= TC_TBS_SORTING_ON;

	if (q->deadline_mode)
		opt.flags |= TC_TBS_DEADLINE_MODE_ON;

	if (nla_put(skb, TCA_TBS_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static struct Qdisc_ops tbs_qdisc_ops __read_mostly = {
	.id		=	"tbs",
	.priv_size	=	sizeof(struct tbs_sched_data),
	.enqueue	=	tbs_enqueue,
	.dequeue	=	tbs_dequeue,
	.peek		=	tbs_peek,
	.init		=	tbs_init,
	.reset		=	tbs_reset,
	.destroy	=	tbs_destroy,
	.dump		=	tbs_dump,
	.owner		=	THIS_MODULE,
};

static int __init tbs_module_init(void)
{
	return register_qdisc(&tbs_qdisc_ops);
}

static void __exit tbs_module_exit(void)
{
	unregister_qdisc(&tbs_qdisc_ops);
}
module_init(tbs_module_init)
module_exit(tbs_module_exit)
MODULE_LICENSE("GPL");
