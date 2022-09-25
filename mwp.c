/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/pid.h>

#include "mwp.h"

struct task_struct *pid_task_struct;
struct vp_sections_struct vps;
struct proc_dir_entry *pde; /* Proc directory */
struct mm_struct *pid_mm;
struct process_info pinfo;

static int PID;

module_param(PID, int, 0);
MODULE_PARM_DESC(PID, "The ID of the process you want to mess with.");

/* Set up the unique global struct */
inline void __init init_pinfo_struct(void)
{
    spin_lock_init(&pinfo.pwlock);
    pinfo.pid = PID;
    pinfo.usage_count = 0;
    pinfo.nrdwr = 0;
}

/* Simply increment the usage count, nothing else */
int mwp_p_open(struct inode *inode, struct file *file)
{
    incusage();
    return 0;
}

/* Echo out process information stored in struct process_info */
ssize_t mwp_p_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    int ret = 0;
    char buffer[BUF_SIZE];

    snprintf(buffer, BUF_SIZE, "PID: %u: Usage count: %u, I/O Operations: %u\n",
                pinfo.pid, pinfo.usage_count, pinfo.nrdwr);

    /* FIXME: Not a really good check */
    if ((ret = simple_read_from_buffer(buf, len, offset, buffer, strlen(buffer))) < 0)
        return -EAGAIN;
    if (ret > 0)
        incrdwr();

    return ret;
}

ssize_t mwp_p_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    u64 vkaddr;
    char *input = NULL;
    char *dest = NULL, *src = NULL;

    /* Allocate enough memory for the user-length buffer */
    if ((input = kmalloc(len, GFP_KERNEL)) == NULL)
        goto out_err;

    /* Copy user-space buffer to our local kernel one */
    if (copy_from_user(input, buf, len))
        goto out_err;

    /* Ugly and a nice way to extract both of the arguments \ 
        one after one where each one is seperated with a whitespace */
    while ((src = strtok_km(input, "\r\t\n "))) {
        dest = strtok_km(NULL, "\r\t\n "); break; }
    kfree(input); /* We don't need the allocated buffer anymore */

    /* Make sure we successfully extraced */
    if (src == NULL || dest == NULL)
        return -EINVAL;

    /* Fetch the address of src */
    if ((vkaddr = vp_fetch_addr(pid_mm, pid_task_struct, vps, src)) == 0)
        return -EAGAIN;

    /* Perform writing of dest to src */
    if (vp_ow(pid_mm, vkaddr, dest, src) == 0)
        return -EFAULT;

    /* Finally increment R/W counter and return (: */
    incrdwr();
    return len;

out_err:
    kfree(input);
    return -EFAULT;
}

/* Copy the user-space program addresses into our struct's fields */
static void vp_copy(struct mm_struct *mm, struct vp_sections_struct *vps)
{
    spin_lock(&mm->arg_lock);
    vps->args.start_args = mm->arg_start;
    vps->args.end_args = mm->arg_end;
    spin_unlock(&mm->arg_lock);
}

static int __init init_mod(void)
{
    if (!(pid_task_struct = pid_task(find_vpid(PID), PIDTYPE_PID)))
        return -EINVAL; /* Cannot find/attach process information by ID */
    if ((pde = proc_mkdir("mwp", NULL)) == NULL)
        return -EFAULT;
    if (proc_create("mwpk", 0, pde, &mwp_proc_ops) == NULL)
        return -EFAULT;
    
    init_pinfo_struct();
    pid_mm = pid_task_struct->mm;
    vp_copy(pid_mm, &vps);

    return 0;
}

static void __exit exit_mod(void) 
{
    proc_remove(pde);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Roi L");
MODULE_VERSION("1.0.2");

module_init(init_mod);
module_exit(exit_mod);