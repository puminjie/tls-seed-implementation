obj-m += edge.o

edge-objs	:= filter.o rdns.o checksum.o

PWD := $(shell pwd)
KDIR := /home/hwlee/devel/rpi/linux

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
