/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pid.h>

#include "mwp.h"
#include "io.h"

/* A user provided input through insmod */
static unsigned int pid;
module_param(pid, uint, 0);

/* Global structure defined in external header. */
struct process_info p_info;

/*
 * The argument to @inc (@which) must be either @nrdwr or @usage
*/
#ifdef DEBUG_MODULE
    #define inc(which) do {                             \
        write_lock(&p_info.mwp_rwlock);                 \
        (p_info).which++;                               \
        write_unlock(&p_info.mwp_rwlock); } while (0)
#else /* NOP */
    #define inc(which) do { } while (0)
#endif /* DEBUG_MODULE */

/* Initalize all fields of our global process_info struct @p_info */
static int __init
initalize_p_info(struct task_struct *tsk)
{
    if (!tsk)
        return -EINVAL;
#ifdef DEBUG_MODULE
    rwlock_init(&p_info.mwp_rwlock);
    p_info.usage = 0; p_info.nrdwr = 0;
#endif
    p_info.p_tsk = tsk;
    p_info.p_mm = p_info.p_tsk->mm;

    /*
     * @arg_lock is a builtin @mm_struct lock that protects the fields below
    */
    spin_lock(&p_info.p_mm->arg_lock);
    p_info.p_vps.start_args = p_info.p_mm->arg_start;
    p_info.p_vps.end_args = p_info.p_mm->arg_end;
    spin_unlock(&p_info.p_mm->arg_lock);

    return 0;
}

/* Simply increment the usage count, nothing else */
static int mwp_open(struct inode *inode, struct file *file)
{
    inc(usage);
    return 0;
}

/* Echo out process information stored in struct process_info */
static ssize_t
mwp_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    int ret = 0;
    char buffer[BUF_SIZE];

#ifdef DEBUG_MODULE
    read_lock(&p_info.mwp_rwlock);
    snprintf(buffer, BUF_SIZE, "PID: %u: Usage count: %u, I/O Operations: %u\n",
                pid, p_info.usage, p_info.nrdwr);
    read_unlock(&p_info.mwp_rwlock);
#endif

    /* FIXME: Not a really good check
     * @simple_read_from_buffer returns the number of bytes,
     * yet this if statement only checks for errors. It's not that important rn.
     */
    if ((ret = simple_read_from_buffer(buf, len, offset, buffer, strlen(buffer))) < 0)
        return ret;

    /* 0 Bytes may have been read */
    if (ret > 0)
        inc(nrdwr);
    return ret;
}

static ssize_t
mwp_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    u64 vkaddr;
    char *input;
    char *dest, *src;

    /* Allocate enough memory for the user-length buffer */
    if ((input = kmalloc(len, GFP_KERNEL)) == NULL)
        goto out_err;

    /* Copy user-space buffer to our local kernel one */
    if (copy_from_user(input, buf, len))
        goto out_err;

    /* Ugly and a nice way to extract both of the arguments \
        one after one where each one is seperated with a whitespace */
    while ((src = strsep(&input, "\r\t\n "))) {
        dest = strsep(&input, "\r\t\n "); break; }
    kfree(input); /* We don't need the allocated buffer anymore */

    /* Make sure we successfully extraced */
    if (src == NULL || dest == NULL)
        return -EINVAL;

    /* Fetch the address of src and execute the memory writing */
    if ((vkaddr = vp_fetch_addr(src)) == 0)
        return -EAGAIN;
    if (vp_ow(vkaddr, dest, src) == 0)
        return -EFAULT;

    inc(nrdwr);
    return len;

out_err:
    kfree(input);
    return -EFAULT;
}

static const struct proc_ops mwp_proc_ops = {
    .proc_open      = mwp_open,
    .proc_write     = mwp_write,
    .proc_read      = mwp_read
};

static int __init mwp_init_mod(void)
{
    static struct task_struct *tsk;

    if (!(tsk = pid_task(find_vpid(pid), PIDTYPE_PID)))
        return -ESRCH; /* No such process */
    if (!proc_create("p_mwpk", S_IWUSR | S_IRUSR, NULL, &mwp_proc_ops))
        return -EFAULT;

    initalize_p_info(tsk);

#ifdef DEBUG_MODULE
    pr_info("Registered successfully, see the /proc/p_mwpk entry.\n");
#endif

    return 0;
}

static void __exit mwp_exit_mod(void)
{
    remove_proc_entry("p_mwpk", NULL);
}

MODULE_LICENSE("GPL");
MODULE_VERSION("1.1.2");

module_init(mwp_init_mod);
module_exit(mwp_exit_mod);