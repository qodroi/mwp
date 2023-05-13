/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "io.h"
#include "mwp.h"

/* Overwrite dest with src, we loop MWP_BLOCK_SIZE over the stack, \
  * starting from dest_addr. */
size_t
vp_ow(u64 dest_addr, const char *dest, const char *src)
{
    int i;
    int ret;
    void *kvaddr;
    struct page *p = NULL;
    bool is_success = false;
    struct mm_struct *p_mm = p_info.p_mm;

    if (!mmap_read_trylock(p_mm))
        return is_success; /* Can't take lock */

    /* Pin the pages into memory, unlikely to fail (only 1 page) */
    ret = get_user_pages_remote(p_mm, dest_addr, NR_PAGES, FOLL_FORCE,
										&p, NULL, NULL);
    if (unlikely(ret <= 0))
        goto unlock_mmap;

    kvaddr = kmap(p); /* Map the page, and return a kernel-space virtual address of the mapping */
    if (!kvaddr)
        goto unlock_mmap_put;

    for (i = 0; i < MWP_BLOCK_SIZE; i++)
    {
        if (strcmp((char *)kvaddr + i, src) == 0)
        {
            memcpy(kvaddr + i, dest, strlen(dest));
            is_success = true;
            break;
        }
    }

    kunmap(p);

unlock_mmap_put:
	put_page(p); /* Put back the page */

unlock_mmap:
	mmap_read_unlock(p_mm);
	return is_success;
}

/* Return the exact address of name within the process address space */
u64
vp_fetch_addr(const char *name)
{
    int i = 0;
    char *kvbuf;
    int fetched = 0;

    if (!(kvbuf = kmalloc(BUF_SIZE, GFP_KERNEL)))
        return 0;

    /* Loop until the desired string is found */
    while (fetched == 0) {
        if (i == MWP_BLOCK_SIZE)
            break; /* We reached the limit, break */
        access_process_vm(p_info.p_tsk, p_info.p_vps.start_args + i, kvbuf, BUF_SIZE,
								FOLL_FORCE);
        i++;
        if (strcmp(kvbuf, name) == 0)
            fetched = 1; /* Stop if we found the string in memory */
    }

    kfree(kvbuf);
    return fetched == 0 ? 0 : p_info.p_vps.start_args + i;
}