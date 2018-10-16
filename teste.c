/* 	Leonardo Carbonari        	13126578
#	Matheus Franceschini        	13129788
#	Pedro Tortella            	13035555
#	Tales Falcão            	13146394
#	Diogo Esteves Furtado     	15153927
#	Kaíque Ferreira Fávero    	15118698
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_LENGTH 256           ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH]; ///< The receive buffer from the LKM

int main()
{
    int ret, fd;
    char stringToSend[BUFFER_LENGTH];
    printf("Abrindo o dispositivo do crypto...\n");
    fd = open("/dev/crypto", O_RDWR); // Open the device with read/write access
    if (fd < 0)
    {
        perror("Falha ao abrir dispositivo! Provavelmente não foi iniciado o módulo...");
        return errno;
    }
    printf("Escreva um comando para o módulo do kernel:\nExemplos:");
    printf("\n\"c dado\" para criptografar");
    printf("\n\"d\" para decriptografar um dado que já foi criptografado");
    printf("\n\"h dado\" para calcular o SHA1 de um dado\n");
    scanf("%[^\n]%*c", stringToSend); // Read in a string (with spaces)
    printf("Escrevendo mensagem no dispositivo [%s].\n", stringToSend);
    ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
    if (ret < 0)
    {
        perror("Falha ao escrever no dispositivo");
        return errno;
    }
    printf("Aperte ENTER para ler o resultado do dispositivo\n");
    getchar();

    printf("Lendo do dispositivo...\n");
    ret = read(fd, receive, BUFFER_LENGTH); // Read the response from the LKM
    if (ret < 0)
    {
        perror("Falha ao ler resultado do dispotivo");
        return errno;
    }
    if (*stringToSend == 'c' || *stringToSend == 'h')
    {
        printf("A mensagem recebida foi: [ ");
        for (int k = 0; k < strlen(receive); k++)
        {
            printf("%x ", (unsigned char)receive[k]);
        }
        printf("]\n");
    }
    else
    {
        printf("A mensagem recebida foi: [ %s ]\n", receive);
    }
    printf("Fim do programa\n");
    return 0;
}