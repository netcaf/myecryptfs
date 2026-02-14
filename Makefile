obj-m := ecryptfs.o

ecryptfs-y := super.o file.o inode.o crypto.o debug.o dentry.o \
               keystore.o kthread.o main.o messaging.o miscdev.o \
               mmap.o read_write.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
