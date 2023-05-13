obj-m := mwpk.o
mwpk-y := mwp.o src/io.o
ccflags-y += -I$(M)/include -Werror -Wall -O2 -c -D__KERNEL__ -DMODULE
debug = 0

ifeq ($(debug), 1)
	ccflags-y += -DDEBUG -DDEBUG_MODULE
endif

all:
	$(MAKE) -C /lib/modules/$$(uname -r)/build M=$(CURDIR) modules

clean:
	$(MAKE) -C /lib/modules/$$(uname -r)/build M=$(CURDIR) clean