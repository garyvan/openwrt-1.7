#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>

static int version_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		utsname()->release,
		utsname()->version);
	return 0;
}

static int version_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, version_proc_show, NULL);
}

static const struct file_operations version_proc_fops = {
	.open		= version_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_version_init(void)
{
	proc_create("version", 0, NULL, &version_proc_fops);
	return 0;
}
module_init(proc_version_init);

//liteon add+
#include "liteon_config.h"

static int liteon_revision_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s",
		SYS_REVISION);
	return 0;
}

static int liteon_revision_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, liteon_revision_proc_show, NULL);
}

static const struct file_operations liteon_revision_proc_fops = {
	.open		= liteon_revision_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init liteon_proc_revision_init(void)
{
	printk("sys_revision: %s\r\n",SYS_REVISION);
	proc_create("sys_revision", 0, NULL, &liteon_revision_proc_fops);
	return 0;
}

module_init(liteon_proc_revision_init);


static int liteon_fw_version_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s",
		FW_VERSION);
	return 0;
}

static int liteon_fw_version_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, liteon_fw_version_proc_show, NULL);
}

static const struct file_operations liteon_fw_version_proc_fops = {
	.open		= liteon_fw_version_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init liteon_proc_fw_version_init(void)
{
	printk("sys_fw_version: %s\r\n",FW_VERSION);
	proc_create("sys_fw_version", 0, NULL, &liteon_fw_version_proc_fops);
	return 0;
}

module_init(liteon_proc_fw_version_init);

//liteon add-
