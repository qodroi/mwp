/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _MWP_H
#define _MWP_H

/* A structure to hold various process memory sections of our target process */
struct vp_sections_struct {
    u64 start_args;
    u64 end_args;
};

/* A struct that will help us identify the process, it will hold
 * useful information */
struct process_info {
#ifdef DEBUG_MODULE
    /* read-write lock (rwlock) to protect the shared fields below */
    rwlock_t mwp_rwlock;
    unsigned int usage, /* Number of times the proc entry has been opened */
                 nrdwr; /* N times the user read/wrote to the process memory space */
#endif
    struct vp_sections_struct p_vps;
    struct task_struct *p_tsk;
    struct mm_struct *p_mm;
};

/* Global structure, since we only attach to one process. */
extern struct process_info p_info;

#endif /* _MWP_H */