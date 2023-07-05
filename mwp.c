/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/mmap_lock.h>
#include <linux/proc_fs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/mm.h>

#include "mwp.h"

/* A user provided input through insmod */
static int pid;
module_param(pid, int, 0);

/* Global structure defined in external header. */
struct process_info p_info;

/* Initalize all fields of our global process_info struct @p_info */
static int __init initalize_process_info(struct task_struct *tsk)
{
    rwlock_init(&p_info.mwp_rwlock);

    p_info.usage = 0; p_info.nrdwr = 0;
    p_info.p_tsk = tsk;
    p_info.p_mm = p_info.p_tsk->mm;
    spin_lock(&p_info.p_mm->arg_lock);
    p_info.p_vps.arg_start = (u64 __user)p_info.p_mm->arg_start;
    p_info.p_vps.env_end = (u64 __user)p_info.p_mm->env_end;
    spin_unlock(&p_info.p_mm->arg_lock);

    return 0;
}

/* This function overwrites the specificed string memory
 * NOTE: We overwrite all occurrences, at least until I find a workaround. */
static int do_write_process_argv(const char *src, const char *dest)
{
    int ret, i;
    int length;
    void *kvbuffer;
    struct page *p;
    struct mm_struct *p_mm;
    unsigned long start_address;

    /* Protect from multiple accesses */
    read_lock(&p_info.mwp_rwlock);
    length = p_info.p_vps.env_end - p_info.p_vps.arg_start;
    start_address = p_info.p_vps.arg_start;
    p_mm = p_info.p_mm;
    read_unlock(&p_info.mwp_rwlock);

    if (!mmap_write_trylock(p_mm))
        return -EBUSY; /* Can't take lock */

    ret = get_user_pages_remote(p_mm, p_info.p_vps.arg_start, NR_PAGES,
                 FOLL_FORCE, &p, NULL, NULL);
    if (ret != NR_PAGES)
        return -EFAULT;

    mmap_write_unlock(p_mm);

    /* FIXME: Can kmap fail? */
    kvbuffer = kmap(p);

    /* I believe we might run into problems here - we only take 1 page
     * while @length _could_ be larger than page size, and we could overwrite
     * much over kvbuffer location, so we currently use PAGE_SIZE,
     * until I look into it.
    */
    for (i = 0; i < PAGE_SIZE; i++)
    {
        if (strncmp((char *)kvbuffer + i, src, strlen(src)) == 0)
        {
            memmove(kvbuffer + i, dest, strlen(dest));
            set_page_dirty(p);
            break;
        }
    }

    kunmap(p);
    put_page(p);

	return 0;
}

/* Simply increment the usage count */
static int mwp_open(struct inode *inode, struct file *file)
{
    __increment(usage);
    return 0;
}

/* Echo out process information stored in struct process_info */
static ssize_t
mwp_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    int ret;
    char buffer[BUF_SIZE];

    read_lock(&p_info.mwp_rwlock);
    snprintf(buffer, BUF_SIZE, "PID: %u: Usage count: %u, I/O Operations: %u\n",
                pid, p_info.usage, p_info.nrdwr);
    read_unlock(&p_info.mwp_rwlock);

    /* FIXME: Not a really good check
     * @simple_read_from_buffer returns the number of bytes,
     * yet this if statement only checks for errors. It's not that important rn.
     */
    if ((ret = simple_read_from_buffer(buf, len, offset, buffer, strlen(buffer))) < 0)
        return ret;

    /* 0 Bytes may have been read */
    if (ret > 0)
        __increment(nrdwr);
    return ret;
}

static ssize_t
mwp_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    char *input;
    char *dest = NULL, *src = NULL;

    /* Allocate enough memory for the user-length buffer */
    if ((input = kmalloc(len, GFP_KERNEL)) == NULL)
        return -ENOMEM;

    /* Copy user-space buffer to our local kernel one */
    if (copy_from_user(input, buf, len)) {
        kfree(input);
        return -EFAULT;
    }

    /* Ugly and a nice way to extract both of the arguments \
        one after one where each one is seperated with a whitespace */
    while ((src = strsep(&input, "\r\t\n "))) {
        dest = strsep(&input, "\r\t\n "); break; }
    kfree(input); /* We don't need the allocated buffer anymore */

    /* Make sure we successfully extraced */
    if (src == NULL || dest == NULL)
        return -EINVAL;

    if (do_write_process_argv(src, dest) < 0)
        return -EFAULT;
    __increment(nrdwr);

    return len;
}

static const struct proc_ops mwp_proc_ops = {
    .proc_open      = mwp_open,
    .proc_write     = mwp_write,
    .proc_read      = mwp_read,
};

static int __init mwp_init_mod(void)
{
    static struct task_struct *tsk;

    if (!(tsk = pid_task(find_vpid(pid), PIDTYPE_PID)))
        return -ESRCH;

    if (!proc_create("mwpk", S_IWUSR | S_IRUSR, NULL, &mwp_proc_ops))
        return -EFAULT;

    initalize_process_info(tsk);

#ifdef DEBUG_MODULE
    pr_info("module registered, /proc/mwpk entry created.\n");
#endif

    return 0;
}

static void __exit mwp_exit_mod(void)
{
    remove_proc_entry("mwpk", NULL);

#ifdef DEBUG_MODULE
    pr_info("module unregistered\n");
#endif
}

MODULE_LICENSE("GPL");
MODULE_VERSION("1.1.3");

module_init(mwp_init_mod);
module_exit(mwp_exit_mod);