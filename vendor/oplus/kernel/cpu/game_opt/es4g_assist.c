// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Oplus. All rights reserved.
 */

#include <trace/events/sched.h>
#include <trace/hooks/sched.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/stdarg.h>
#if IS_ENABLED(CONFIG_OPLUS_SYSTEM_KERNEL_QCOM) && IS_ENABLED(CONFIG_SCHED_WALT)
#include <linux/sched/walt.h>
#include <linux/qcom-cpufreq-hw.h>
#endif

#ifdef CONFIG_HMBIRD_SCHED
#include "../../../drivers/cpuidle/governors/trace-qcom-lpm.h"
#endif

#include "game_ctrl.h"
#include "es4g_assist.h"

#define ES4G_ALLOW_PROC_WR_OPS

unsigned int es4g_assist_debug = 0;

#define DECLARE_DEBUG_TRACE(name, proto, data)		\
	void __maybe_unused debug_##name(proto) {		\
		if (es4g_assist_debug & DEBUG_SYSTRACE) {	\
			name(data);								\
		}											\
	}
#include "debug_common.h"
#undef DECLARE_DEBUG_TRACE

struct proc_dir_entry *es4g_dir = NULL;

struct key_thread_struct {
	pid_t pid;
	struct task_struct *task;
	s32 prio; /* smaller is more critical, range from 0 to 8 */
	u32 slot;
	s32 cpu;
	s32 util;
} critical_thread_list[MAX_KEY_THREAD_RECORD];

static int heavy_task_index = -1;
static int __maybe_unused heavy_task_count = 0;

atomic_t es4g_select_cpu_mask = ATOMIC_INIT(0);
atomic_t es4g_isolate_cpus = ATOMIC_INIT(0);
atomic_t es4g_low_isolate_cpus = ATOMIC_INIT(0);

static int select_cpu_list[MAX_NR_CPUS] = {7, 4, 3, 2, 6, 5, -1, -1};

static DEFINE_RWLOCK(critical_task_list_rwlock);
static DEFINE_RWLOCK(select_cpu_list_rwlock);

/**
 * task prop: 0~7, for specific thread, 8~15, for critical thread
 *
 * 0: common thread
 * 1: debug or logging thread, which is the least critical
 * 2: temporary thread but high-load
 * 3: io related, such as preload
 * 4: network related, such as XXX_NETWORK
 * 5: periodic thread, not waken by critical thread
 * 6: periodic thread, waken by critical thread, such as core thread
 * 7: the most critical but transient thread, such as gc
 *
 */
static inline __maybe_unused int prop_to_index(int prop)
{
	return (~prop & 0xf);
}

static inline __maybe_unused int index_to_prop(int index)
{
	return (~index & 0xf);
}

static inline int sched_prop_get_task_index(struct task_struct *p __maybe_unused)
{
#if defined(CONFIG_HMBIRD_SCHED) || defined(CONFIG_HMBIRD_SCHED_GKI)
	return prop_to_index(sched_prop_get_top_thread_id(p));
#else
	return 0;
#endif
}

static void remove_slot_of_index(struct key_thread_struct *list, size_t index)
{
#if defined(CONFIG_HMBIRD_SCHED) || defined(CONFIG_HMBIRD_SCHED_GKI)
	unsigned long dsq_id;
#endif /* CONFIG_HMBIRD_SCHED */
	if (list[index].slot > 0 && likely(list[index].task != NULL)) {
#if defined(CONFIG_HMBIRD_SCHED) || defined(CONFIG_HMBIRD_SCHED_GKI)
		dsq_id = sched_get_sched_prop(list[index].task) & SCHED_PROP_DEADLINE_MASK;
		sched_set_sched_prop(list[index].task, dsq_id);
#endif /* CONFIG_HMBIRD_SCHED */
		put_task_struct(list[index].task);
	}
	list[index].pid = -1;
	list[index].task = NULL;
	list[index].prio = -1;
	list[index].slot = 0;
	list[index].cpu = -1;
	list[index].util = -1;
	if (heavy_task_index == index) {
		heavy_task_index = -1;
	}
}

static bool clear_key_thread(struct key_thread_struct *list, size_t len)
{
	write_lock(&critical_task_list_rwlock);
	for (int i = 0; i < len; i++) {
		remove_slot_of_index(list, i);
	}
	write_unlock(&critical_task_list_rwlock);
	atomic_set(&es4g_select_cpu_mask, 0);
	return true;
}

static bool init_key_thread(struct key_thread_struct *list, size_t len)
{
	return clear_key_thread(list, len);
}

static void update_key_thread_cpu(struct key_thread_struct *list, size_t len)
{
	int prio_count[KEY_THREAD_PRIORITY_COUNT + 1] = {0};
	int online_cpumask = (1 << MAX_NR_CPUS) - 1;
	int task_cpumask = online_cpumask;

	/**
	 * clear key task prop if no cpu online
	 */
	if (unlikely(task_cpumask <= 0)) {
		clear_key_thread(list, len);
		return;
	}

	/* boost priority of heavy task */
	if (heavy_task_index >= 0) {
		list[heavy_task_index].prio--;
	}

	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0) {
			prio_count[list[i].prio + 1]++;
		}
	}
	/* 1st and the last slot is not necessary to count */
	for (int i = 2; i < KEY_THREAD_PRIORITY_COUNT; i++) {
		prio_count[i] += prio_count[i - 1];
	}

	read_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < len && task_cpumask > 0; i++) {
		if (list[i].slot <= 0) {
			continue;
		}
		for (int cpu_index = prio_count[list[i].prio]; cpu_index < MAX_NR_CPUS; cpu_index++) {
			if (select_cpu_list[cpu_index] < 0) {
				list[i].cpu = -1;
				break;
			}
			if (1 << select_cpu_list[cpu_index] & task_cpumask) {
				list[i].cpu = select_cpu_list[cpu_index];
				task_cpumask &= ~(1 << select_cpu_list[cpu_index]);
				break;
			}
		}
	}
	read_unlock(&select_cpu_list_rwlock);

	if (heavy_task_index >= 0) {
		list[heavy_task_index].prio++;
	}

	atomic_set(&es4g_select_cpu_mask, online_cpumask & (~task_cpumask));
}

static bool add_key_thread(struct key_thread_struct *list, size_t len, pid_t pid, s32 prio)
{
	int first_slot = -1;
	bool update = false;

	if (prio > MIN_KEY_THREAD_PRIORITY) {
		prio = MIN_KEY_THREAD_PRIORITY;
	}
	if (prio < MAX_KEY_THREAD_PRIORITY_US) {
		prio = MAX_KEY_THREAD_PRIORITY_US;
	}

	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0) {
			if (list[i].pid == pid) {
				if (list[i].prio != prio) {
					list[i].prio = prio;
					update = true;
				}
				goto out;
			}
		} else {
			if (first_slot < 0) {
				first_slot = i;
			}
		}
	}
	if (first_slot >= 0) {
		rcu_read_lock();
		list[first_slot].task = find_task_by_vpid(pid);
		if (list[first_slot].task) {
			get_task_struct(list[first_slot].task);
			list[first_slot].pid = pid;
			list[first_slot].prio = prio;
			list[first_slot].slot = 1;
			list[first_slot].util = -1;
#if defined(CONFIG_HMBIRD_SCHED) || defined(CONFIG_HMBIRD_SCHED_GKI)
			sched_set_sched_prop(list[first_slot].task,
									SCHED_PROP_DEADLINE_LEVEL3 |
									index_to_prop(first_slot) << SCHED_PROP_TOP_THREAD_SHIFT);
#endif /* CONFIG_HMBIRD_SCHED */
			update = true;
		}
		rcu_read_unlock();
	}

out:
	if (update) {
		heavy_task_index = -1;
	}

	return update;
}

static bool remove_key_thread(struct key_thread_struct *list, size_t len, pid_t pid)
{
	for (int i = 0; i < len; i++) {
		if (list[i].slot > 0 && list[i].pid == pid) {
			remove_slot_of_index(list, i);
			return true;
		}
	}
	return false;
}
#ifdef CONFIG_HMBIRD_SCHED
static void scx_select_cpu_dfl_hook(void *unused, struct task_struct *p, s32 *cpu)
{
	int index = sched_prop_get_task_index(p);

	if (index >= MAX_KEY_THREAD_RECORD) {
		return;
	}

	if (read_trylock(&critical_task_list_rwlock)) {
		*cpu = critical_thread_list[index].cpu;
		read_unlock(&critical_task_list_rwlock);
	}
}

static void scx_sched_lpm_disallowed_time_hook(void *unused, int cpu, int *timeout_allowed)
{
	*timeout_allowed = !!(atomic_read(&es4g_select_cpu_mask) & (1 << cpu));
}

/*
 * cpu cycles per instruction may be incomparable because of different cpu microarchitectures where taskload is counted,
 * so that realtime cpu-selecting is abandoned
 *
 */
static void __maybe_unused scx_update_task_scale_time_hook(void *unused, struct task_struct *p, u16 *demand_scale)
{
	/* update selected cpu if tasks with the same priority take on obvious different workload counted by demand_scale */
	int index = sched_prop_get_task_index(p);
#if IS_ENABLED(CONFIG_OPLUS_SYSTEM_KERNEL_QCOM) && IS_ENABLED(CONFIG_SCHED_WALT)
	u64 cpu_cycles;
#endif

	if (index >= MAX_KEY_THREAD_RECORD) {
		return;
	}

	if (write_trylock(&critical_task_list_rwlock)) {
		critical_thread_list[index].util = *demand_scale;
		if (unlikely(heavy_task_index < 0) && select_cpu_list[0] >= 0) {
			for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
				if (critical_thread_list[i].slot > 0 && critical_thread_list[i].cpu == select_cpu_list[0]) {
					heavy_task_index = i;
					break;
				}
			}
		}

		debug_trace_pr_val_uint(critical_thread_list[index].pid, critical_thread_list[index].util);

#if IS_ENABLED(CONFIG_OPLUS_SYSTEM_KERNEL_QCOM) && IS_ENABLED(CONFIG_SCHED_WALT)
		cpu_cycles = ((struct walt_task_struct *) critical_thread_list[index].task->android_vendor_data1)->cpu_cycles;
		debug_trace_pr_val_uint(~critical_thread_list[index].pid, cpu_cycles);
#endif

		if (likely(heavy_task_index >= 0) &&
			index != heavy_task_index &&
			critical_thread_list[index].prio == critical_thread_list[heavy_task_index].prio) {
			s32 heavy_task_util = critical_thread_list[heavy_task_index].util;
			if (heavy_task_util > 0) {
				if (*demand_scale <= heavy_task_util) {
					heavy_task_count = 0;
				} else if (*demand_scale <= (heavy_task_util + (heavy_task_util >> 2))) {
					/* pass */
				} else if (heavy_task_count > 0 || *demand_scale > (heavy_task_util + (heavy_task_util >> 1))) {
					heavy_task_count++;
				}
				if (heavy_task_count > 5) {
					heavy_task_index = index;
					update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
					heavy_task_count = 0;
				}
			}
		} else {
			heavy_task_count = 0;
		}

		debug_trace_pr_val_str("count", heavy_task_count);

		write_unlock(&critical_task_list_rwlock);
	}
}

static void check_preempt_curr_scx_hook(
	void *unused,
	struct rq *rq __maybe_unused,
	struct task_struct *p __maybe_unused,
	int wake_flags __maybe_unused,
	int *check_result)
{
	int index = sched_prop_get_task_index(p);
	int cpu = cpu_of(rq);

	if (slim_for_app & SLIM_FOR_GENSHIN) {
		if (index >= MAX_KEY_THREAD_RECORD) {
			return;
		}
		if (atomic_read(&es4g_select_cpu_mask) & (1 << cpu)) {
			*check_result = 1;
		}
	} else if (slim_for_app & SLIM_FOR_SGAME) {
		*check_result = !strcmp(p->comm, "CoreThread");
	} else {}
}

static void task_fits_cpu_scx_hook(void *unused, struct task_struct *p, int cpu, int *fitable)
{
	/**
	 * TODO
	 *
	 * struct scx_sched_task_stats *sts = &p->scx.sts;
	 *
	 */
	int index = sched_prop_get_task_index(p);

	if (index >= MAX_KEY_THREAD_RECORD) {
		return;
	}

	if (atomic_read(&es4g_select_cpu_mask) & (1 << cpu)) {
		*fitable = 1;
	}
}

static void __maybe_unused scx_cpu_exclusive_hook(void *unused, int cpu, int *exclusive)
{
	int exclusive_mask = atomic_read(&es4g_select_cpu_mask) & atomic_read(&es4g_isolate_cpus);
	*exclusive = !!(exclusive_mask & (1 << cpu));
}

static void scx_consume_dsq_allowed_hook(void *unused, struct rq *rq, struct rq_flags *rf __maybe_unused, int dsq_type, int *allowed)
{
	int cpu = cpu_of(rq);
	int select_cpus = atomic_read(&es4g_select_cpu_mask);
	int isolate_cpus = select_cpus & atomic_read(&es4g_isolate_cpus);
	int low_isolate_cpus = select_cpus & atomic_read(&es4g_low_isolate_cpus);

	switch (dsq_type) {
	case SCHED_EXT_DSQ_TYPE_PERIOD:
		if ((isolate_cpus & (1 << cpu)) ||
				(low_isolate_cpus & (1 << cpu))) {
			*allowed = 0;
		}
		break;

	case SCHED_EXT_DSQ_TYPE_NON_PERIOD:
		if (isolate_cpus & (1 << cpu)) {
			*allowed = 0;
		}
		break;

	default:
		break;
	}
}
#endif
static int es4g_assist_proc_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int es4g_assist_proc_release(struct inode *inode, struct file *file)
{
	return 0;
}

static void set_es4g_assist_debug(int debug)
{
	es4g_assist_debug = debug < 0 ? 0 : debug;
}

static ssize_t es4g_assist_debug_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret, debug;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%d", &debug);
	if (ret < 1) {
		return -EINVAL;
	}

	set_es4g_assist_debug(debug);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_assist_debug_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int len;

	len = snprintf(page, ONE_PAGE_SIZE - 1, "%d\n", es4g_assist_debug);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_assist_debug_proc_ops = {
	.proc_write		= es4g_assist_debug_proc_write,
	.proc_read		= es4g_assist_debug_proc_read,
	.proc_lseek		= default_llseek,
};

static bool __maybe_unused set_critical_task(int tid, int prio)
{
	bool ret;

	if (tid < 0 && prio < 0) {
		return clear_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
	}

	if (tid < 0)
		return false;

	write_lock(&critical_task_list_rwlock);
	if (prio < 0) {
		ret = remove_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD, tid);
	} else {
		ret = add_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD, tid, prio);
	}
	if (ret) {
		update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
	}
	write_unlock(&critical_task_list_rwlock);

	return ret;
}

static bool batch_set_critical_task(struct es4g_ctrl_info *data, struct key_thread_struct *list, size_t len)
{
	int pair;
	int tid;
	int prio;
	bool update;

	if (data->size <= 0 || (data->size & 1)) {
		return false;
	}

	if (data->data[0] < 0 && data->data[1] < 0) {
		return clear_key_thread(list, len);
	}

	pair = data->size / 2;
	update = false;

	write_lock(&critical_task_list_rwlock);
	for (int i = 0; i < pair; i++) {
		tid = data->data[i * 2];
		prio = data->data[i * 2 + 1];
		if (prio >= 0) {
			continue;
		}
		if (remove_key_thread(list, len, tid)) {
			update = true;
		}
	}
	for (int i = 0; i < pair; i++) {
		tid = data->data[i * 2];
		prio = data->data[i * 2 + 1];
		if (prio < 0) {
			continue;
		}
		if (add_key_thread(list, len, tid, prio)) {
			update = true;
		}
	}
	if (update) {
		update_key_thread_cpu(list, len);
	}
	write_unlock(&critical_task_list_rwlock);

	return update;
}

static ssize_t es4g_critical_task_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret;
	int tid, prio;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(page, "%d %d", &tid, &prio);
	if (ret != 2)
		return -EINVAL;

	if (!set_critical_task(tid, prio)) {
		return -EINVAL;
	}

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_critical_task_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD] = {0};
	int len = 0;

	read_lock(&critical_task_list_rwlock);
	for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
		if (critical_thread_list[i].slot > 0) {
			len += snprintf(page + len, ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD - len,
								"tid=%d, prio=%d, cpu=%d\n",
								critical_thread_list[i].pid, critical_thread_list[i].prio, critical_thread_list[i].cpu);
		}
	}
	if (heavy_task_index >= 0) {
		len += snprintf(page + len, ONE_PAGE_SIZE * MAX_KEY_THREAD_RECORD - len,
								"heavy task is %d\n", critical_thread_list[heavy_task_index].pid);
	}
	read_unlock(&critical_task_list_rwlock);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_critical_task_proc_ops = {
	.proc_write		= es4g_critical_task_proc_write,
	.proc_read		= es4g_critical_task_proc_read,
	.proc_lseek		= default_llseek,
};

static void update_select_cpu_list(s64 *data, size_t len)
{
	if (len > MAX_NR_CPUS) {
		len = MAX_NR_CPUS;
	}

	write_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < len; i++) {
		select_cpu_list[i] = data[i];
	}
	for (int i = len; i < MAX_NR_CPUS; i++) {
		select_cpu_list[i] = -1;
	}
	write_unlock(&select_cpu_list_rwlock);

	write_lock(&critical_task_list_rwlock);
	update_key_thread_cpu(critical_thread_list, MAX_KEY_THREAD_RECORD);
	write_unlock(&critical_task_list_rwlock);
}

static ssize_t es4g_select_cpu_list_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int ret;
	s64 cpu_list[MAX_KEY_THREAD_RECORD] = {0};

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%lld %lld %lld %lld %lld %lld %lld %lld",
					&cpu_list[0],
					&cpu_list[1],
					&cpu_list[2],
					&cpu_list[3],
					&cpu_list[4],
					&cpu_list[5],
					&cpu_list[6],
					&cpu_list[7]);
	if (ret <= 0) {
		return -EINVAL;
	}

	update_select_cpu_list(cpu_list, ret);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_select_cpu_list_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE << 1] = {0};
	int len = 0;

	read_lock(&select_cpu_list_rwlock);
	for (int i = 0; i < MAX_KEY_THREAD_RECORD; i++) {
		if (select_cpu_list[i] >= 0) {
			len += snprintf(page + len, (ONE_PAGE_SIZE << 1) - len, "%d: %d\n", i, select_cpu_list[i]);
		} else {
			break;
		}
	}
	read_unlock(&select_cpu_list_rwlock);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_select_cpu_list_proc_ops = {
	.proc_write		= es4g_select_cpu_list_proc_write,
	.proc_read		= es4g_select_cpu_list_proc_read,
	.proc_lseek		= default_llseek,
};

static void set_isolate_cpus(int isolate_cpus)
{
	atomic_set(&es4g_isolate_cpus, isolate_cpus);
}

static void set_low_isolate_cpus(int isolate_cpus)
{
	atomic_set(&es4g_low_isolate_cpus, isolate_cpus);
}

static ssize_t es4g_isolate_cpus_proc_write(
	struct file *file,
	const char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int isolate_cpus, low_isolate_cpus;
	int ret;

	ret = simple_write_to_buffer(page, ONE_PAGE_SIZE - 1, ppos, buf, count);
	if (ret <= 0) {
		return ret;
	}

	ret = sscanf(page, "%d:%d", &isolate_cpus, &low_isolate_cpus);
	if (ret != 2) {
		return -EINVAL;
	}

	set_isolate_cpus(isolate_cpus);
	set_low_isolate_cpus(low_isolate_cpus);

	return count;
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static ssize_t es4g_isolate_cpus_proc_read(
	struct file *file,
	char __user *buf, size_t count, loff_t *ppos)
{
#ifdef ES4G_ALLOW_PROC_WR_OPS
	char page[ONE_PAGE_SIZE] = {0};
	int len = 0;
	int isolate_cpus = atomic_read(&es4g_isolate_cpus);
	int low_isolate_cpus = atomic_read(&es4g_low_isolate_cpus);

	len = snprintf(page, ONE_PAGE_SIZE - 1, "%d:%d\n", isolate_cpus, low_isolate_cpus);

	return simple_read_from_buffer(buf, count, ppos, page, len);
#else
	return 0;
#endif /* ES4G_ALLOW_PROC_WR_OPS */
}

static const struct proc_ops es4g_isolate_cpus_proc_ops = {
	.proc_write		= es4g_isolate_cpus_proc_write,
	.proc_read		= es4g_isolate_cpus_proc_read,
	.proc_lseek		= default_llseek,
};

static long es4g_assist_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct es4g_ctrl_info data;
	void __user *uarg = (void __user *)arg;
	long ret = 0;

	if ((_IOC_TYPE(cmd) != ES4G_MAGIC) || (_IOC_NR(cmd) >= ES4G_MAX_ID)) {
		return -EINVAL;
	}

	if (copy_from_user(&data, uarg, sizeof(data))) {
		return -EFAULT;
	}

	switch (cmd) {
	case CMD_ID_ES4G_DEBUG_LEVEL:
		if (data.size > 0) {
			set_es4g_assist_debug(data.data[0]);
		}
		break;

	case CMD_ID_ES4G_SET_CRITICAL_TASK:
		batch_set_critical_task(&data, critical_thread_list, MAX_KEY_THREAD_RECORD);
		break;

	case CMD_ID_ES4G_SELECT_CPU_LIST:
		update_select_cpu_list(data.data, data.size);
		break;

	case CMD_ID_ES4G_SET_ISOLATE_CPUS:
		if (data.size > 0) {
			set_isolate_cpus(data.data[0]);
		}
		if (data.size > 1) {
			set_low_isolate_cpus(data.data[1]);
		}
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

#if IS_ENABLED(CONFIG_COMPAT)
static long compat_es4g_assist_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return es4g_assist_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif /* CONFIG_COMPAT */

static const struct proc_ops es4g_assist_sys_ctrl_proc_ops = {
	.proc_ioctl			= es4g_assist_ioctl,
	.proc_open			= es4g_assist_proc_open,
	.proc_release		= es4g_assist_proc_release,
#if IS_ENABLED(CONFIG_COMPAT)
	.proc_compat_ioctl	= compat_es4g_assist_ioctl,
#endif /* CONFIG_COMPAT */
	.proc_lseek			= default_llseek,
};

static void register_es4g_assist_vendor_hooks(void)
{
#ifdef CONFIG_HMBIRD_SCHED
	register_trace_android_vh_scx_select_cpu_dfl(scx_select_cpu_dfl_hook, NULL);
	register_trace_android_vh_scx_sched_lpm_disallowed_time(scx_sched_lpm_disallowed_time_hook, NULL);
	/* register_trace_android_vh_scx_update_task_scale_time(scx_update_task_scale_time_hook, NULL); */
	register_trace_android_vh_check_preempt_curr_scx(check_preempt_curr_scx_hook, NULL);
	register_trace_android_vh_task_fits_cpu_scx(task_fits_cpu_scx_hook, NULL);
	register_trace_android_vh_scx_cpu_exclusive(scx_cpu_exclusive_hook, NULL);
	register_trace_android_vh_scx_consume_dsq_allowed(scx_consume_dsq_allowed_hook, NULL);
#endif /* CONFIG_HMBIRD_SCHED */
}

static void unregister_es4g_assist_vendor_hooks(void)
{
#ifdef CONFIG_HMBIRD_SCHED
	unregister_trace_android_vh_scx_select_cpu_dfl(scx_select_cpu_dfl_hook, NULL);
	unregister_trace_android_vh_scx_sched_lpm_disallowed_time(scx_sched_lpm_disallowed_time_hook, NULL);
	/* unregister_trace_android_vh_scx_update_task_scale_time(scx_update_task_scale_time_hook, NULL); */
	unregister_trace_android_vh_check_preempt_curr_scx(check_preempt_curr_scx_hook, NULL);
	unregister_trace_android_vh_task_fits_cpu_scx(task_fits_cpu_scx_hook, NULL);
	unregister_trace_android_vh_scx_cpu_exclusive(scx_cpu_exclusive_hook, NULL);
	unregister_trace_android_vh_scx_consume_dsq_allowed(scx_consume_dsq_allowed_hook, NULL);
#endif /* CONFIG_HMBIRD_SCHED */
}

int es4g_assist_init(void)
{
	if (unlikely(!game_opt_dir))
		return -ENOTDIR;

	es4g_dir = proc_mkdir("es4g", game_opt_dir);

	register_es4g_assist_vendor_hooks();

	proc_create_data("es4ga_ctrl", 0664, es4g_dir, &es4g_assist_sys_ctrl_proc_ops, NULL);
	proc_create_data("es4ga_debug", 0664, es4g_dir, &es4g_assist_debug_proc_ops, NULL);
#ifdef CONFIG_HMBIRD_SCHED
	proc_create_data("critical_task", 0664, es4g_dir, &es4g_critical_task_proc_ops, NULL);
	proc_create_data("select_cpu_list", 0664, es4g_dir, &es4g_select_cpu_list_proc_ops, NULL);
	proc_create_data("isolate_cpus", 0664, es4g_dir, &es4g_isolate_cpus_proc_ops, NULL);
#endif /* CONFIG_HMBIRD_SCHED */

	init_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);

	return 0;
}

void es4g_assist_exit(void)
{
	if (unlikely(!game_opt_dir))
		return;

	unregister_es4g_assist_vendor_hooks();

	clear_key_thread(critical_thread_list, MAX_KEY_THREAD_RECORD);
}
