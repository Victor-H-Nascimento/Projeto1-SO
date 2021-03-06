/*João Pedro Favara - RA: 16061921  
Murilo Martus Mendoça - RA: 16063497
Victor Hugo do Nascimento - RA: 16100588*/
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
    char opcao[BUFFER_LENGTH + 1];
    int fd = open("/dev/crypto", O_RDWR); // Open the device with read/write access
    if (fd < 0)
    {
        perror("ERRO AO ABRIR O DISPOSITIVO.\n");
        return errno;
    }

    strcpy(opcao, argv[1]); //minha opcao de entrada ta aqui

    if (argc > 1 && argc < 4)
    {
        if (strcmp(opcao, "c") == 0)
        {
            printf("VOCE ESCOLHEU CRIPTOGRAFAR A MENSAGEM: [%s].\n", argv[2]);
            char stringToSend[BUFFER_LENGTH];
            strcpy(stringToSend, opcao);
            printf("ESCREVENDO A MENSAGEM: [%s].\n", argv[2]);
            strcat(stringToSend, argv[2]);
            int ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
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

            printf("MENSAGEM CRIPTOGRAFADA:[");
            for (int k = 0; k < strlen(receive); k++)
            {
                printf("%x ", (unsigned char)receive[k]);
            }
            printf("]\n");
        }
        else
        {
            if (strcmp(opcao, "d") == 0)
            {
                printf("VOCE ESCOLHEU DESCRIPTOGRAFAR A MENSAGEM: [%s].\n", argv[2]); //tratar a entrada
                char stringToSend[BUFFER_LENGTH];
                strcpy(stringToSend, opcao);
                printf("ESCREVENDO A MENSAGEM: [%s].\n", argv[2]);

                strcat(stringToSend, argv[2]);                           //concatena a sring com a função solicitada
                int ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
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

                printf("MENSAGEM DESCRIPTOGRAFADA:[%s]\n", receive);
            }
            else
            {
                if (strcmp(argv[1], "h") == 0)
                {
                    printf("VOCE ESCOLHEU RESUMO CRIPTOGRAFICO DA MENSAGEM: [%s].\n", argv[2]);
                    char stringToSend[BUFFER_LENGTH];
                    strcpy(stringToSend, opcao);
                    printf("ESCREVENDO A MENSAGEM: [%s].\n", argv[2]);
                    strcat(stringToSend, argv[2]);                           //concatena a sring com a função solicitada
                    int ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
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

                    printf("HASH DA MENSAGEM :[");
                    for (int i = 0; i < strlen(receive) - 1; i = i + 2)
                    {
                        printf("%c", receive[i]);
                        printf("%c ", receive[i + 1]);
                    }
                    printf("]\n");
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