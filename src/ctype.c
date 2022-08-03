#include <linux/slab.h>
#include <linux/string.h>

int *create_delim_dict(unsigned char *delim)
{
    int i;
    int *d = kmalloc(sizeof(int) * 256, GFP_KERNEL);
    memset((void*)d, 0, sizeof(int) * 256);

    for(i = 0; i < strlen(delim); i++)
        d[delim[i]] = 1;
    return d;
}

char *strtok_km(char *str, char *delim)
{

    static unsigned char *last, *to_free;
    int *deli_dict = create_delim_dict(delim);

    if(!deli_dict)
        return NULL;

    if(str) {
        last = kmalloc(strlen(str) + 1, GFP_KERNEL);
        if(!last) {
            kfree(deli_dict);
        }
        to_free = last;
        strcpy(last, str);
    }

    while(deli_dict[*last] && *last != '\0')
        last++;

    str = last;
    if(*last == '\0') 
    {
        kfree(deli_dict);
        kfree(to_free);
        return NULL;
    }

    while (*last != '\0' && !deli_dict[*last])
        last++;

    *last = '\0';
    last++;

    kfree(deli_dict);
    return str;
}