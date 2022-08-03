/* Header file mainly used for string operations that are not \
    exported to the linux kernel (or just LKM) */

#ifndef _CTYPE_H
#define _CTYPE_H

int *create_delim_dict(unsigned char *delim);
char *strtok_km(char *str, char *delim);

#endif /* _H_CTYPE */