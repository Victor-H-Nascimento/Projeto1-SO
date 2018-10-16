ifneq ($(KERNELRELEASE),)
ifeq ($(DO_DEBUG_CRYPROC),y)
EXTRA_CFLAGS	+= -DCRYPROC_DEBUG
endif
obj-m		+= cryproc.o
cryproc-y	:= file.o stringops.o
else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD		:= $(shell pwd)
default: module cryproc-tool
	@echo "Done."
debug: module-debug cryproc-tool
	@echo "Done."
module:
	@echo "Building the kernel module..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
module-debug:
	@echo "Building the kernel module with extra debugging output..."
	$(MAKE) -C $(KDIR) M=$(PWD) DO_DEBUG_CRYPROC=y modules
cryproc-tool: cryproc-tool.c
	@echo "Building the helper application cryproc-tool..."
	$(CC) -o cryproc-tool cryproc-tool.c
clean:
	rm *.mod.c *.o *.ko .*.cmd cryproc-tool
	rm -rf .tmp_versions
endif
