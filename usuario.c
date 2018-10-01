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
    int fd = open("/dev/crypto", O_RDWR); // Open the device with read/write access
    if (fd < 0)
    {
        perror("ERRO AO ABRIR O DISPOSITIVO.\n");
        return errno;
    }
    if (argc > 1 && argc < 4)
    {
        if (strcmp(argv[1], "c") == 0)
        {
            printf("VOCE ESCOLHEU CRIPTOGRAFAR A MENSAGEM: %s.\n", argv[2]);
            char stringToSend[BUFFER_LENGTH];
            strcpy(stringToSend, argv[2]);
            printf("ESCREVENDO A MENSAGEM: %s.\n", stringToSend);
            int ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
            if (ret < 0)
            {
                perror("ERRO AO ESCREVER A MENSAGEM NO DISPOSITIVO\n.");
                return errno;
            }
        }
        else
        {
            if (strcmp(argv[1], "d") == 0)
            {
                printf("VOCE ESCOLHEU DESCRIPTOGRAFAR.\n");
                int ret = read(fd, receive, BUFFER_LENGTH); // Read the response from the LKM
                if (ret < 0)
                {
                    perror("ERRO AO LER DO DISPOSITIVO.\n");
                    return errno;
                }
                printf("MENSAGEM DESCRIPTOGRAFADA : %s.\n", receive);
            }
            else
            {
                if (strcmp(argv[1], "h") == 0)
                {
                    printf("VOCE ESCOLHEU RESUMO CRIPTOGRAFICO\n");
                }
                else
                {
                    printf("OPCAO: %s INDISPONIVEL\n", argv[1]);
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