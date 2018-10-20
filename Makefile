obj-m += cryptoapi.o
obj-m += cryptomodule.o

all:
	make -C /lib/modules/4.15.0-36-generic/build M=$(PWD) modules
	gcc usuario.c -o usuario
clean:
	make -C /lib/modules/4.15.0-36-generic/build M=$(PWD) clean
