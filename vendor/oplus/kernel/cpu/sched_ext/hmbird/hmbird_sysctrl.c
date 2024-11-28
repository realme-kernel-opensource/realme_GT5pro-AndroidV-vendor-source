#include "hmbird_sched.h"

#define HMBIRD_SCHED_DIR        "hmbird_cfg"
#define HIGHRES_TICK_CTRL       "scx_shadow_tick_enable"
#define HIGHRES_TICK_CTRL_DBG   "highres_tick_ctrl_dbg"
#define LOAD_TRACK_DIR          "slim_walt"
#define SLIM_WALT_CTRL          "slim_walt_ctrl"
#define SLIM_WALT_DUMP          "slim_walt_dump"
#define SLIM_WALT_POLICY        "slim_walt_policy"
#define SLIM_RAVG_WINDOW        "frame_per_sec"
#define SLIM_FREQ_GOV_DEBUG     "slim_gov_debug"
#define SLIM_FREQ_GOV_DIR       "slim_freq_gov"
#define CPU7_TL                 "cpu7_tl"

#define SCX_GOV_CTRL		"scx_gov_ctrl"

unsigned int highres_tick_ctrl;
unsigned int highres_tick_ctrl_dbg;

int slim_walt_ctrl;
int slim_walt_dump;
int slim_walt_policy;
int sched_ravg_window_frame_per_sec = 125;
int slim_gov_debug;
int cpu7_tl = 70;

int scx_gov_ctrl = 1;

static char *slim_walt_config[] = {
	SLIM_WALT_CTRL,
	SLIM_WALT_DUMP,
	SLIM_WALT_POLICY,
	SLIM_RAVG_WINDOW,
};

static char *slim_freq_gov_config[] = {
	SLIM_FREQ_GOV_DEBUG,
	SCX_GOV_CTRL,
};

static int *slim_freq_gov_data[] = {
	&slim_gov_debug,
	&scx_gov_ctrl,
};

static int *slim_walt_data[] = {
	&slim_walt_ctrl,
	&slim_walt_dump,
	&slim_walt_policy,
	&sched_ravg_window_frame_per_sec,
};

static char *files_name[] = {
	HIGHRES_TICK_CTRL,
	HIGHRES_TICK_CTRL_DBG,
	CPU7_TL,
};

static int *file_data[] = {
	&highres_tick_ctrl,
	&highres_tick_ctrl_dbg,
	&cpu7_tl,
};

static ssize_t hmbird_common_write(struct file *file,
				   const char __user *buf,
				   size_t count, loff_t *ppos)
{
	int *pval = (int *)pde_data(file_inode(file));
	char kbuf[5] = {0};
	int err;

	if (count >= 5)
		return -EFAULT;

	if (copy_from_user(kbuf, buf, count)) {
		pr_err("hmbird_sched : Failed to copy_from_user\n");
		return -EFAULT;
	}
	err = kstrtoint(strstrip(kbuf), 0, pval);
	if (err < 0) {
		pr_err("hmbird_sched: Failed to exec kstrtoint\n");
		return -EFAULT;
	}

	if (pval == &sched_ravg_window_frame_per_sec) {
#ifdef CONFIG_SCX_USE_UTIL_TRACK
		sched_ravg_window_change(*pval);
#endif
	}

	return count;
}

static int hmbird_common_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", *(int*) m->private);
	return 0;
}

static int hmbird_common_open(struct inode *inode, struct file *file)
{
	return single_open(file, hmbird_common_show, pde_data(inode));
}

static const struct proc_ops common_proc_ops = {
	.proc_open              = hmbird_common_open,
	.proc_write             = hmbird_common_write,
	.proc_read              = seq_read,
	.proc_lseek             = seq_lseek,
	.proc_release           = single_release,
};

extern struct proc_dir_entry *hmbird_dir;
struct proc_dir_entry *load_track_dir;
struct proc_dir_entry *freq_gov_dir;

static void create_procs(void)
{
	int i;

	if (hmbird_dir) {
		for (i = 0; i < ARRAY_SIZE(files_name); i++) {
			proc_create_data(files_name[i],
					 S_IRUGO | S_IWUGO,
					 hmbird_dir,
					 &common_proc_ops,
					 file_data[i]);
		}
		load_track_dir = proc_mkdir(LOAD_TRACK_DIR, hmbird_dir);
		if (load_track_dir) {
			for (i = 0; i < ARRAY_SIZE(slim_walt_config); i++) {
				proc_create_data(slim_walt_config[i],
						 S_IRUGO | S_IWUGO,
						 load_track_dir,
						 &common_proc_ops,
						 slim_walt_data[i]);
			}
		}
		freq_gov_dir = proc_mkdir(SLIM_FREQ_GOV_DIR, hmbird_dir);
		if (freq_gov_dir) {
			for (i = 0; i < ARRAY_SIZE(slim_freq_gov_config); i++) {
				proc_create_data(slim_freq_gov_config[i],
						 S_IRUGO | S_IWUGO,
						 freq_gov_dir,
						 &common_proc_ops,
						 slim_freq_gov_data[i]);
			}
		}
	}
}


void hmbird_sysctrl_init(void)
{
	create_procs();
}

