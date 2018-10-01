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
    //talvez seja a posição 1 para a letra e a 2 para o texto de criptografia
    if (argc > 1)
    {
        if (strcmp(argv[1], "c") == 0)
        {
            printf("VOCE ESCOLHEU CRIPTOGRAFAR A MENSAGEM: %s\n", argv[2]);
        }
        else
        {
            if (strcmp(argv[1], "d") == 0)
            {
                printf("VOCE ESCOLHEU DESCRIPTOGRAFAR\n");
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