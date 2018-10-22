#João Pedro Favara - RA: 16061921	
#Murilo Martus Mendoça - RA: 16063497
#Victor Hugo do Nascimento - RA: 16100588 

obj-m += cryptomodule.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc usuario.c -o usuario
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
