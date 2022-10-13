obj-m := mwpk.o
mwpk-y := mwp.o src/mem.o src/ctype.o
ERRNO = -Wno-error=unused-function
ccflags-y += -I$(M)/include -Werror -Wall -O2 $(ERRNO) -c -D__KERNEL__ -DMODULE

all:
	$(MAKE) -C /lib/modules/$$(uname -r)/build M=$(CURDIR) modules

clean:
	$(MAKE) -C /lib/modules/$$(uname -r)/build M=$(CURDIR) clean
