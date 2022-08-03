obj-m := mwpk.o
mwpk-y := mwp.o src/stack.o src/ctype.o
ERRNO = -Wno-error=unused-function
EXTRA_CFLAGS += -I$(M)/include -Werror -Wall -O2 $(ERRNO) -c -D__KERNEL__ -DMODULE

all:
	$(MAKE) -C /lib/modules/$$(uname -r)/build M=$(CURDIR) modules

clean:
	$(MAKE) -C /lib/modules/$$(uname -r)/build M=$(CURDIR) clean
