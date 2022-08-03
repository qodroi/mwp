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

/* Set up the unique global struct for use */
inline void init_pinfo_struct(void)
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

    snprintf(buffer, BUF_SIZE, "PID: %d: Usage count: %d, I/O Operations: %d\n",
                pinfo.pid, pinfo.usage_count, pinfo.nrdwr);

    /* Not a really good check; the number of bytes read is returned, or negative for error \ 
        As you see I'd rather check only for errors */
    if ((ret = simple_read_from_buffer(buf, len, offset, buffer, strlen(buffer) + 1)) < 0)
        return -EAGAIN;

    incrdwr();   
    return ret;
}

/* Write dest to src, the user should echo to the proc entry following this pattern \
    e.g. echo "./main ./nomain" > /proc/proc_entry */
ssize_t mwp_p_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
    u64 vkaddr;
    char *input;
    char *dest = NULL, *src = NULL;

    /* Allocate enough memory for the user-length buffer */
    if ((input = kmalloc(len, GFP_KERNEL)) == NULL)
        return -EFAULT;
    /* Copy user-space buffer to our local kernel one */
    if (copy_from_user(input, buf, len))
        goto out_free_err;

    /* Ugly and a nice way to extract both of the arguments \ 
        one after one when each one is seperated with whitespace */
    while ((src = strtok_km(input, " "))) {
        dest = strtok_km(NULL, " "); break; }
    kfree(input); /* We don't need the allocate buffer anymore */

    /* Verify we extraced successfully */
    if (src == NULL || dest == NULL)
        return -EINVAL;

    /* Trim the possible whitespaces */
    src = strtok_km(src, "\r\t\n ");
    dest = strtok_km(dest, "\r\t\n ");

    /* Fetch the address of src */
    if ((vkaddr = vp_fetch_addr(pid_mm, pid_task_struct, vps, src)) == 0)
        return -EAGAIN;

    /* Perform writing of dest to src */
    if (vp_ow(pid_mm, vkaddr, dest, src) == 0)
        return -EFAULT;

    /* Finally increment RD/WR operations counter and return (: */
    incrdwr();
    return len;

out_free_err:
    kfree(input);
    return -EFAULT;
}

/* This just verifes that the user didn't output an invalid PID */
static inline int verify_module_args(void)
{
    if (PID <= 0 || PID > PID_MAX_LIMIT)
        return 1;
    return 0;
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
    if (verify_module_args())
        return -EINVAL;
    if (!(pid_task_struct = pid_task(find_vpid(PID), PIDTYPE_PID)))
        return -EAGAIN; /* Cannot find/attach process information by ID */
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