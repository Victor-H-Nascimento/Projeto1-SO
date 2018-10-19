#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_LENGTH 256           ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH]; ///< The receive buffer from the LKM

int main(int argc, char *argv[])
{
    char opcao[BUFFER_LENGTH+1];
    int fd = open("/dev/crypto", O_RDWR); // Open the device with read/write access
    if (fd < 0)
    {
        perror("ERRO AO ABRIR O DISPOSITIVO.\n");
        return errno;
    }
	
	strcpy(opcao,argv[1]);//minha opcao de entrada ta aqui 

    if (argc > 1 && argc < 4)
    {
        if (strcmp(opcao, "c") == 0)
        {
            /*printf("VOCE ESCOLHEU CRIPTOGRAFAR A MENSAGEM: [%s].\n", argv[2]);
            char stringToSend[BUFFER_LENGTH];
            strcpy(stringToSend, argv[2]);
            printf("ESCREVENDO A MENSAGEM: [%s].\n", stringToSend);
            int ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
            if (ret < 0)
            {
                perror("ERRO AO ESCREVER A MENSAGEM NO DISPOSITIVO\n.");
                return errno;
            }*/
        }
        else
        {
            if (strcmp(opcao, "d") == 0)
            {
                /*printf("VOCE ESCOLHEU DESCRIPTOGRAFAR.\n");
                int ret = read(fd, receive, BUFFER_LENGTH); // Read the response from the LKM
                if (ret < 0)
                {
                    perror("ERRO AO LER DO DISPOSITIVO.\n");
                    return errno;
                }
                if (receive == NULL || strcmp(receive, "") == 0)
                {
                    printf("NAO EXISTE MENSAGEM PARA DESCRIPTOGRAFAR.\n");
                }
                else
                {
                    printf("MENSAGEM DESCRIPTOGRAFADA: [%s].\n", receive);
                }*/
            }
            else
            {
                if (strcmp(opcao, "h") == 0)
                {
		printf("VOCE ESCOLHEU RESUMO CRIPTOGRAFICO\n");
		char stringToSend[BUFFER_LENGTH];
		strcpy(stringToSend, argv[2]);
		printf("ESCREVENDO A MENSAGEM: [%s]\n", stringToSend);
		strcat(opcao, stringToSend);//para a opcao ficar na primeira posicao
		int ret = write(fd, opcao, strlen(opcao)); // Send the string to the LKM
		    if (ret < 0)
		    {
		        perror("ERRO AO ESCREVER A MENSAGEM NO DISPOSITIVO\n.");
		        return errno;
		    }


		ret = read(fd, receive, BUFFER_LENGTH); // Read the response from the LKM
		        if (ret < 0)
		        {
		            perror("ERRO AO LER DO DISPOSITIVO.\n");
		            return errno;
		        }
		        if (receive == NULL || strcmp(receive, "") == 0)
		        {
		            printf("NAO EXISTE MENSAGEM PARA DESCRIPTOGRAFAR.\n");
		        }
		        else
		        {
		            printf("MENSAGEM CRIPTOGRAFADA: [%s] - %i\n", receive, strlen(receive));
		        }

		printf("Fim de execucao do programa\n");		

		}
            }
        }
    }
    else
    {
        printf("FAVOR ESCOLHER ALGUMA OPCAO!\n");
    }

    return 0;
}