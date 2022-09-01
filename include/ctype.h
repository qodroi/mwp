/**
 * Copyright 2022 Roi L.
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _CTYPE_H
#define _CTYPE_H

int *create_delim_dict(unsigned char *delim);
char *strtok_km(char *str, char *delim);

#endif /* _H_CTYPE */