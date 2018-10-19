# 	Leonardo Carbonari        	13126578
#	Matheus Franceschini        	13129788
#	Pedro Tortella            	13035555
#	Tales Falcão            	13146394
#	Diogo Esteves Furtado     	15153927
#	Kaíque Ferreira Fávero    	15118698
obj-m += crypsob.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
