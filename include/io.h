/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _IO_H
#define _IO_H

#define NR_PAGES        (1)
#define BUF_SIZE        (256) /* Random */
#define MWP_BLOCK_SIZE  (1024) /* Random as well */

u64 vp_fetch_addr(const char *name);
size_t vp_ow(u64 dest_addr, const char *dest, const char *src);

#endif /* _IO_H */