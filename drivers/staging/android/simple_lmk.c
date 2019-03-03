// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018-2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#define pr_fmt(fmt) "simple_lmk: " fmt

#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/simple_lmk.h>
#include <linux/sort.h>

#define MIN_FREE_PAGES (CONFIG_ANDROID_SIMPLE_LMK_MINFREE * SZ_1M / PAGE_SIZE)

#define KSWAPD_LMK_EXPIRES \
	msecs_to_jiffies(CONFIG_ANDROID_SIMPLE_LMK_KSWAPD_TIMEOUT)
#define OOM_LMK_EXPIRES \
	msecs_to_jiffies(CONFIG_ANDROID_SIMPLE_LMK_OOM_TIMEOUT)

enum {
	DISABLED,
	STARTING,
	READY
};

struct victim_info {
	struct task_struct *victim;
	unsigned long size;
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

static void simple_lmk_reclaim_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(reclaim_work, simple_lmk_reclaim_work);
static DEFINE_MUTEX(reclaim_lock);
static struct workqueue_struct *simple_lmk_wq;
static unsigned long last_reclaim_jiffies;
static atomic_t simple_lmk_state = ATOMIC_INIT(DISABLED);
static cputime_t kswapd_start_time;

/* Make sure that PID_MAX_DEFAULT isn't too big, or these arrays will be huge */
static struct victim_info victim_array[PID_MAX_DEFAULT];
static struct victim_info *victim_ptr_array[ARRAY_SIZE(victim_array)];

#define simple_lmk_is_ready() (atomic_read(&simple_lmk_state) == READY)

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
	unsigned long pages_freed = 0;
	unsigned int i, vcount = 0;
	struct task_struct *tsk;

	rcu_read_lock();
	for_each_process(tsk) {
		struct task_struct *victim;
		unsigned long tasksize;
		short oom_score_adj;

		/* Don't commit suicide or kill kthreads */
		if (same_thread_group(tsk, current) || tsk->flags & PF_KTHREAD)
			continue;

		victim = find_lock_task_mm(tsk);
		if (!victim)
			continue;

		/* Don't kill tasks that have been killed or lack memory */
		if (victim->lmk_sigkill_sent ||
			test_tsk_thread_flag(victim, TIF_MEMDIE)) {
			task_unlock(victim);
			continue;
		}

		oom_score_adj = victim->signal->oom_score_adj;
		if (oom_score_adj < min_adj || oom_score_adj > max_adj) {
			task_unlock(victim);
			continue;
		}

		tasksize = get_mm_rss(victim->mm);
		task_unlock(victim);
		if (!tasksize)
			continue;

		/* Store this potential victim away for later */
		get_task_struct(victim);
		victim_array[vcount].victim = victim;
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
	 * Sort the victims in descending order of size in order to kill as few
	 * processes as possible while satisfying memory needs.
	 */
	sort(victim_ptr_array, vcount, sizeof(victim_ptr_array[0]),
	     victim_info_cmp, NULL);

	for (i = 0; i < vcount; i++) {
		struct victim_info *vinfo = victim_ptr_array[i];
		struct task_struct *victim = vinfo->victim;

		if (pages_freed >= pages_needed) {
			put_task_struct(victim);
			continue;
		}

		if (!do_send_sig_info(SIGKILL, SEND_SIG_FORCED, victim, true))
			victim->lmk_sigkill_sent = true;

		put_task_struct(victim);
		pages_freed += vinfo->size;
	}

	return pages_freed;
}

static unsigned long do_lmk_reclaim(unsigned long pages_needed)
{
	unsigned long pages_freed = 0;
	int i;

	for (i = 1; i < ARRAY_SIZE(adj_prio); i++) {
		pages_freed += scan_and_kill(adj_prio[i], adj_prio[i - 1],
					     pages_needed - pages_freed);
		if (pages_freed >= pages_needed)
			break;
	}

	last_reclaim_jiffies = jiffies;
	return pages_freed * PAGE_SIZE / SZ_1M;
}

static cputime_t get_kswapd_cputime(void)
{
	struct task_struct *kswapd = NODE_DATA(0)->kswapd;
	cputime_t stime, unused;

	task_cputime_adjusted(kswapd, &unused, &stime);
	return stime;
}

static void simple_lmk_reclaim_work(struct work_struct *work)
{
	unsigned long mib_freed, resched_delay_jiffies = 1;
	cputime_t kswapd_time_now;
	u64 delta_us;

	/* Check kswapd's actual system run-time */
	kswapd_time_now = get_kswapd_cputime();
	delta_us = cputime_to_usecs(kswapd_time_now - kswapd_start_time);
	if (delta_us / USEC_PER_MSEC < CONFIG_ANDROID_SIMPLE_LMK_KSWAPD_TIMEOUT)
		goto reschedule;
	kswapd_start_time = kswapd_time_now;

	mutex_lock(&reclaim_lock);
	mib_freed = do_lmk_reclaim(MIN_FREE_PAGES);
	mutex_unlock(&reclaim_lock);

	if (mib_freed)
		pr_info("kswapd: freed %lu MiB\n", mib_freed);

	resched_delay_jiffies = KSWAPD_LMK_EXPIRES;
reschedule:
	queue_delayed_work(simple_lmk_wq, &reclaim_work, resched_delay_jiffies);
}

void simple_lmk_one_reclaim(void)
{
	unsigned long mib_freed = 0;

	if (!simple_lmk_is_ready())
		return;

	/* Only one memory reclaim event can occur at a time */
	if (!mutex_trylock(&reclaim_lock))
		return;

	if (time_after_eq(jiffies, last_reclaim_jiffies + OOM_LMK_EXPIRES))
		mib_freed = do_lmk_reclaim(MIN_FREE_PAGES);
	mutex_unlock(&reclaim_lock);

	if (mib_freed)
		pr_info("oom: freed %lu MiB\n", mib_freed);
}

void simple_lmk_start_reclaim(void)
{
	if (!simple_lmk_is_ready())
		return;

	kswapd_start_time = get_kswapd_cputime();
	queue_delayed_work(simple_lmk_wq, &reclaim_work, KSWAPD_LMK_EXPIRES);
}

void simple_lmk_stop_reclaim(void)
{
	if (!simple_lmk_is_ready())
		return;

	cancel_delayed_work_sync(&reclaim_work);
}

/* Initialize Simple LMK when LMKD in Android writes to the minfree parameter */
static int simple_lmk_init_set(const char *val, const struct kernel_param *kp)
{
	if (atomic_cmpxchg(&simple_lmk_state, DISABLED, STARTING) != DISABLED)
		return 0;

	simple_lmk_wq = alloc_workqueue("simple_lmk",
					WQ_HIGHPRI | WQ_FREEZABLE |
					WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	BUG_ON(!simple_lmk_wq);

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
