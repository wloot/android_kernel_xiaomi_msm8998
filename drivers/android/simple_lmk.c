// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#define pr_fmt(fmt) "simple_lmk: " fmt

#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/sort.h>

/* The minimum number of pages to free per memory reclaim event */
#define MIN_FREE_PAGES (CONFIG_ANDROID_SIMPLE_LMK_MINFREE * SZ_1M / PAGE_SIZE)

/* SEND_SIG_FORCED is not present in newer kernel versions */
#ifdef SEND_SIG_FORCED
#define KILL_SIG_TYPE SEND_SIG_FORCED
#else
#define KILL_SIG_TYPE SEND_SIG_PRIV
#endif

struct oom_alloc_req {
	struct page *page;
	struct completion done;
	struct list_head lh;
	unsigned int order;
	int migratetype;
};

struct victim_info {
	struct task_struct *tsk;
	unsigned long size;
};

enum {
	DISABLED,
	STARTING,
	READY,
	KILLING
};

/* Pulled from the Android framework */
static const short int adj_prio[] = {
	906, /* CACHED_APP_MAX_ADJ */
	905, /* Cached app */
	904, /* Cached app */
	903, /* Cached app */
	902, /* Cached app */
	901, /* Cached app */
	900, /* CACHED_APP_MIN_ADJ */
	800, /* SERVICE_B_ADJ */
	700, /* PREVIOUS_APP_ADJ */
	600, /* HOME_APP_ADJ */
	500, /* SERVICE_ADJ */
	400, /* HEAVY_WEIGHT_APP_ADJ */
	300, /* BACKUP_APP_ADJ */
	200, /* PERCEPTIBLE_APP_ADJ */
	100, /* VISIBLE_APP_ADJ */
	0    /* FOREGROUND_APP_ADJ */
};

/* Make sure that PID_MAX_DEFAULT isn't too big, or these arrays will be huge */
static struct victim_info victim_array[PID_MAX_DEFAULT];
static struct victim_info *victim_ptr_array[ARRAY_SIZE(victim_array)];
static atomic_t simple_lmk_state = ATOMIC_INIT(DISABLED);
static atomic_t oom_alloc_count = ATOMIC_INIT(0);
static unsigned long last_kill_expires;
static unsigned long kill_expires;
static DEFINE_SPINLOCK(oom_queue_lock);
static LIST_HEAD(oom_alloc_queue);

static int victim_info_cmp(const void *lhs, const void *rhs)
{
	const struct victim_info **lhs_ptr = (typeof(lhs_ptr))lhs;
	const struct victim_info **rhs_ptr = (typeof(rhs_ptr))rhs;

	if ((*lhs_ptr)->size > (*rhs_ptr)->size)
		return -1;

	if ((*lhs_ptr)->size < (*rhs_ptr)->size)
		return 1;

	return 0;
}

static unsigned long scan_and_kill(int min_adj, int max_adj,
				   unsigned long pages_needed)
{
	static const struct sched_param rt_sched_param = {
		.sched_priority = MAX_RT_PRIO - 1
	};
	unsigned long pages_freed = 0;
	unsigned int i, vcount = 0;
	struct task_struct *tsk;

	rcu_read_lock();
	for_each_process(tsk) {
		struct task_struct *vtsk;
		unsigned long tasksize;
		short oom_score_adj;

		/* Don't commit suicide or kill kthreads */
		if (same_thread_group(tsk, current) || tsk->flags & PF_KTHREAD)
			continue;

		vtsk = find_lock_task_mm(tsk);
		if (!vtsk)
			continue;

		/* Don't kill tasks that have been killed or lack memory */
		if (vtsk->slmk_sigkill_sent ||
		    test_tsk_thread_flag(vtsk, TIF_MEMDIE)) {
			task_unlock(vtsk);
			continue;
		}

		oom_score_adj = vtsk->signal->oom_score_adj;
		if (oom_score_adj < min_adj || oom_score_adj > max_adj) {
			task_unlock(vtsk);
			continue;
		}

		tasksize = get_mm_rss(vtsk->mm);
		task_unlock(vtsk);
		if (!tasksize)
			continue;

		/* Store this potential victim away for later */
		get_task_struct(vtsk);
		victim_array[vcount].tsk = vtsk;
		victim_array[vcount].size = tasksize;
		victim_ptr_array[vcount] = &victim_array[vcount];
		vcount++;

		/* The victim array is so big that this should never happen */
		if (unlikely(vcount == ARRAY_SIZE(victim_array)))
			break;
	}
	rcu_read_unlock();

	/* No potential victims for this adj range means no pages freed */
	if (!vcount)
		return 0;

	/*
	 * Sort the victims in descending order of size in order to target the
	 * largest ones first.
	 */
	sort(victim_ptr_array, vcount, sizeof(victim_ptr_array[0]),
	     victim_info_cmp, NULL);

	/*
	 * Don't let the scheduler interrupt the kill process while victims are
	 * getting boosted to max realtime priority.
	 */
	preempt_disable();
	for (i = 0; i < vcount; i++) {
		struct victim_info *victim = victim_ptr_array[i];
		struct task_struct *vtsk = victim->tsk;

		if (pages_freed >= pages_needed) {
			put_task_struct(vtsk);
			continue;
		}

		pr_info("killing %s with adj %d to free %lu MiB\n",
			vtsk->comm, vtsk->signal->oom_score_adj,
			victim->size * PAGE_SIZE / SZ_1M);

		/* Boost priority of victim tasks so they can die quickly */
		sched_setscheduler_nocheck(vtsk, SCHED_FIFO, &rt_sched_param);
		do_send_sig_info(SIGKILL, KILL_SIG_TYPE, vtsk, true);
		vtsk->slmk_sigkill_sent = true;
		put_task_struct(vtsk);
		pages_freed += victim->size;
	}
	preempt_enable();

	return pages_freed;
}

static void kill_processes(unsigned long pages_needed)
{
	unsigned long pages_freed = 0;
	int i;

	for (i = 1; i < ARRAY_SIZE(adj_prio); i++) {
		pages_freed += scan_and_kill(adj_prio[i], adj_prio[i - 1],
					     pages_needed - pages_freed);
		if (pages_freed >= pages_needed)
			break;
	}
}

static void do_memory_reclaim(void)
{
	/* Only one reclaim can occur at a time */
	if (atomic_cmpxchg(&simple_lmk_state, READY, KILLING) != READY)
		return;

	if (time_after_eq(jiffies, last_kill_expires)) {
		kill_processes(MIN_FREE_PAGES);
		last_kill_expires = jiffies + kill_expires;
	}

	atomic_set(&simple_lmk_state, READY);
}

static long reclaim_once_or_more(struct completion *done, unsigned int order)
{
	long ret;

	/* Don't allow costly allocations to do memory reclaim more than once */
	if (order > PAGE_ALLOC_COSTLY_ORDER) {
		do_memory_reclaim();
		return wait_for_completion_killable(done);
	}

	do {
		do_memory_reclaim();
		ret = wait_for_completion_killable_timeout(done, kill_expires);
	} while (!ret);

	return ret;
}

struct page *simple_lmk_oom_alloc(unsigned int order, int migratetype)
{
	struct oom_alloc_req page_req = {
		.done = COMPLETION_INITIALIZER_ONSTACK(page_req.done),
		.order = order,
		.migratetype = migratetype
	};
	long ret;

	if (atomic_read(&simple_lmk_state) <= STARTING)
		return NULL;

	spin_lock(&oom_queue_lock);
	list_add_tail(&page_req.lh, &oom_alloc_queue);
	spin_unlock(&oom_queue_lock);

	atomic_inc(&oom_alloc_count);

	/* Do memory reclaim and wait */
	ret = reclaim_once_or_more(&page_req.done, order);
	if (ret == -ERESTARTSYS) {
		/* Give up since this process is dying */
		spin_lock(&oom_queue_lock);
		if (!page_req.page)
			list_del(&page_req.lh);
		spin_unlock(&oom_queue_lock);
	}

	atomic_dec(&oom_alloc_count);

	return page_req.page;
}

bool simple_lmk_page_in(struct page *page, unsigned int order, int migratetype)
{
	struct oom_alloc_req *page_req;
	bool matched = false;
	int try_order;

	if (atomic_read(&simple_lmk_state) <= STARTING ||
	    !atomic_read(&oom_alloc_count))
		return false;

	/* Try to match this free page with an OOM allocation request */
	spin_lock(&oom_queue_lock);
	for (try_order = order; try_order >= 0; try_order--) {
		list_for_each_entry(page_req, &oom_alloc_queue, lh) {
			if (page_req->order == try_order &&
			    page_req->migratetype == migratetype) {
				matched = true;
				break;
			}
		}

		if (matched)
			break;
	}

	if (matched) {
		__ClearPageBuddy(page);
		page_req->page = page;
		list_del(&page_req->lh);
		complete(&page_req->done);
	}
	spin_unlock(&oom_queue_lock);

	return matched;
}

/* Enable Simple LMK when LMKD in Android writes to the minfree parameter */
static int simple_lmk_init_set(const char *val, const struct kernel_param *kp)
{
	if (atomic_cmpxchg(&simple_lmk_state, DISABLED, STARTING) != DISABLED)
		return 0;

	/* Store the calculated kill timeout jiffies for frequent reuse */
	kill_expires = msecs_to_jiffies(CONFIG_ANDROID_SIMPLE_LMK_KILL_TIMEOUT);
	atomic_set(&simple_lmk_state, READY);
	return 0;
}

static const struct kernel_param_ops simple_lmk_init_ops = {
	.set = simple_lmk_init_set
};

/* Needed to prevent Android from thinking there's no LMK and thus rebooting */
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "lowmemorykiller."
module_param_cb(minfree, &simple_lmk_init_ops, NULL, 0200);
