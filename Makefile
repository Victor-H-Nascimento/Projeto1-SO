obj-m += cryptomodule.o
obj-m += exemplo_crypto.o
obj-m += exemplo_hash.o

all:
	make -C /lib/modules/4.15.0-29-generic/build M=$(PWD) modules

clean:
	make -C /lib/modules/4.15.0-29-generic/build M=$(PWD) clean
