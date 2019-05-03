#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int cpumaxfreq_show(struct seq_file *m, void *v)
{
	/* C1, C2 and D5 all use msm8998 with maxfreq 2.45 */
	seq_printf(m, "2.45\n");

	return 0;
}

static int cpumaxfreq_open(struct inode *inode, struct file *file)
{
	return single_open(file, &cpumaxfreq_show, NULL);
}

static const struct file_operations proc_cpumaxfreq_operations = {
	.open       = cpumaxfreq_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = seq_release,
};

static int __init proc_cpumaxfreq_init(void)
{
	proc_create("cpumaxfreq", 0, NULL, &proc_cpumaxfreq_operations);
	return 0;
}
fs_initcall(proc_cpumaxfreq_init);