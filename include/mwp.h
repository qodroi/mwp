#ifndef _MWP_H
#define _MWP_H

#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>

/* Constants */
#define MWP_BLOCK_SIZE  (1024)
#define NR_PAGES        (1)
#define BUF_SIZE        (256) /* IDK why */

/* proc entry operations, release and open is uneeded, since we don't set up anything. */
ssize_t mwp_p_write(struct file *file, const char __user *buf, size_t len, loff_t *offset);
ssize_t mwp_p_read(struct file *file, char __user *buf, size_t len, loff_t *offset);
int mwp_p_open(struct inode *inode, struct file *file);

static const struct proc_ops mwp_proc_ops = {
    .proc_open      = mwp_p_open,
    .proc_write     = mwp_p_write,
    .proc_read      = mwp_p_read
};

/* A struct with 64bit fields that holds the process addresses of args */
struct vp_sections_struct {
    struct args { /* process arguments, located on the stack */
        u64 start_args;
        u64 end_args; } args;
};

/* A struct that will help us identify the process, it will hold the pid \ 
 * and other useful information so we will verify the owner */
struct process_info {
    pid_t pid;
    spinlock_t pwlock; /* Protect the fields below and to prevent writing simultaneously */
    unsigned int usage_count; /* Number of times the proc entry has been opened */
    unsigned int nrdwr; /* N times the user read/wrote to the process memory space */
};

extern struct process_info pinfo; /* Global struct, we only need it once :) */

#include "ctype.h"
#include "stack.h"

#endif /* _MWP_H */