#ifndef _DATA_H
#define _DATA_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/slab.h>

u64 vp_fetch_addr(struct mm_struct *mm, struct task_struct *ts, struct vp_sections_struct vps, const char *name);
int vp_ow_args(struct mm_struct *mm, u64 dest_addr, const char *dest, const char *src);
size_t vp_ow(struct mm_struct *mm, u64 dest_addr, const char *dest, const char *src);
void incusage(void);
void incrdwr(void);

#endif /* _DATA_H */