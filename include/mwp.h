/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _MWP_H
#define _MWP_H

#define BUF_SIZE        (56) /* Random */
#define NR_PAGES        (1)

/*
 * (@which) must be either @nrdwr or @usage
*/
#define __increment(which) do {                     \
    write_lock(&p_info.mwp_rwlock);                 \
    (p_info).which++;                               \
    write_unlock(&p_info.mwp_rwlock);               \
} while (0)

/* A structure to hold various process memory sections of our target process */
struct vp_sections_struct {
    u64 __user arg_start,
        __user env_end;
};

/* A struct that will help us identify the process and some of its
 * task_struct fields
 */
struct process_info {
    /* read-write lock (rwlock) to protect the shared fields below */
    rwlock_t mwp_rwlock;
    unsigned int usage, /* Number of times the proc entry has been opened */
                 nrdwr; /* N times the user read/wrote to the process memory space */
    struct vp_sections_struct p_vps;
    struct task_struct *p_tsk;
    struct mm_struct *p_mm;
};

/* Global structure, since we only attach to one process. */
extern struct process_info p_info;

#endif /* _MWP_H */