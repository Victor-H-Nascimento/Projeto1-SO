obj-m += new_cryptomodule.o

all:
	make -C /lib/modules/4.15.0-36-generic/build M=$(PWD) modules
	gcc usuario.c -o usuario
	gcc teste.c -o teste
clean:
	make -C /lib/modules/4.15.0-36-generic/build M=$(PWD) clean
