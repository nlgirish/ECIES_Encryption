/**
 * @file /cryptron/example.c
 *
 * @brief Example code for using the provided ECIES functions to encrypt data.
 *
 * $Author: Ladar Levison $
 * $Website: http://lavabit.com $
 * $Date: 2010/08/06 06:03:04 $
 * $Revision: ccd79bf03e3e68a3cce213890129aec55a76d301 $
 *
 */

#include "ecies.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> /* close() */
#include <string.h> /* memset() */
#include <stdlib.h> /* exit() */

#define LOCAL_SERVER_PORT 1500
#define MAX_MSG 1000

void processor_cleanup(EC_KEY *key, secure_t *ciphered, char *hex_pub, char *hex_priv, unsigned char *text, unsigned char *copy, unsigned char *original)
{

    if (key)
    {
        ecies_key_free(key);
    }

    if (ciphered)
    {
        secure_free(ciphered);
    }

    if (hex_pub)
    {
        OPENSSL_free(hex_pub);
    }

    if (hex_priv)
    {
        OPENSSL_free(hex_priv);
    }

    if (text)
    {
        free(text);
    }

    if (copy)
    {
        free(copy);
    }

    if (original)
    {
        free(original);
    }

    return;
}

int processor(int iteration)
{

    int tlen;
    size_t olen;
    EC_KEY *key = NULL;
    secure_t *ciphered = NULL;
    char *hex_pub = NULL, *hex_priv = NULL;
    unsigned char *text = NULL, *copy = NULL, *original = NULL;
    uint64_t j = 0;

    // Generate random size for the block of data were going to encrypt.  Use a min value of 1 KB and a max of 1 MB.
    do
    {
        tlen = (rand() % (1024 * 1024));
    }
    while (tlen < 1024);
    tlen = 16;

    if (!(text = malloc(tlen + 1)) || !(copy = malloc(tlen + 1)))
    {
        printf("Memory error.\n");
        processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
        return -1;
    }

    // Wipe and then fill the data blocks with random data.
    memset(copy, 0, tlen + 1);
    memset(text, 0, tlen + 1);
    char a[16] = "Hello World.3412";
    for (j = 0; j < tlen; j++)
    {
        *(copy + j) = *(text + j) = a[j];
    }

    // Generate a key for our theoretical user.
#if 0
    if (!(key = ecies_key_create()))
    {
        printf("Key creation failed.\n");
        processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
        return -1;
    }
#endif
    //-------------------TEST------------------TODO

    EVP_PKEY *skey = NULL;
    FILE* fp = fopen ("eckey.pem", "r");
    BIO               *outbio = NULL;

    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);


    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //Read Private Key and Store
    PEM_read_PrivateKey( fp, &skey, NULL, NULL);
    fclose(fp);
    if(!PEM_write_bio_PrivateKey(outbio, skey, NULL,NULL,0,NULL,NULL))
        BIO_printf(outbio, "Error writing public key data in PEM format");
    if(!PEM_write_bio_PUBKEY(outbio, skey))
        BIO_printf(outbio, "Error writing public key data in PEM format");

    //-------------------TEST END--------------TODO

    // Since we'll store the keys as hex values in reali life, extract the appropriate hex values and release the original key structure.
    //if (!(hex_pub = ecies_key_public_get_hex(key)) || !(hex_priv = ecies_key_private_get_hex(key))) {
    if (!(hex_priv = ecies_key_private_get_hex(skey->pkey.ec)))
    {
        printf("Serialization of the key to a pair of hex strings failed.\n");
        processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
        return -1;
    }
    //---------------TEST------------------TODO
    printf("Pri Key Print:\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("%s\n", hex_priv);
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    //---------------TEST END------------------TODO

#if 0
    int ctlen;
    if (!(ciphered = ecies_encrypt(hex_pub, text, tlen, &ctlen)))
    {
        printf("The encryption process failed!\n");
        processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
        return -1;
    }
    printf("Ciphered text Length:%d\n", ctlen);

    printf("Original Text:Start\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    for(j = 0; j < tlen; j++)
    {
        printf("%c", *(copy+j));
    }
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("Original Text:End\n");
    printf("Ciphered Text:Start\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    for(j = 0; j < ctlen; j++)
    {
        printf("%x", (int)*(ciphered+j));
    }
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("Ciphered Text:End\n");
    //---------------TEST----------------------
    secure_t *cryptex = malloc(ctlen);
    memcpy(cryptex, ciphered, ctlen);
#endif

    int sd, rc, n;
    socklen_t cliLen;
    struct sockaddr_in cliAddr, servAddr;
    char msg[MAX_MSG];

    /* socket creation */
    sd=socket(AF_INET, SOCK_DGRAM, 0);
    if(sd<0)
    {
        printf("cannot open socket \n");
        exit(1);
    }

    /* bind local server port */
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(LOCAL_SERVER_PORT);
    rc = bind (sd, (struct sockaddr *) &servAddr,sizeof(servAddr));
    if(rc<0)
    {
        printf("cannot bind port number %d \n", LOCAL_SERVER_PORT);
        exit(1);
    }

    printf("waiting for data on port UDP %u\n", LOCAL_SERVER_PORT);

    /* server infinite loop */
    while(1)
    {
        printf("\n\n\n\n\n\n");

        /* init buffer */
        memset(msg,0x0,MAX_MSG);


        /* receive message */
        cliLen = sizeof(cliAddr);
        n = recvfrom(sd, (void*)msg, MAX_MSG, 0,
                     (struct sockaddr *) &cliAddr, &cliLen);

        if(n<0)
        {
            printf("cannot receive data \n");
            continue;
        }

        /* print received message */
        //printf("Received from %s:UDP%u : %s \n", inet_ntoa(cliAddr.sin_addr),
        // ntohs(cliAddr.sin_port),msg);
        printf("Received from %s: UDP Port:%u :\n", inet_ntoa(cliAddr.sin_addr),ntohs(cliAddr.sin_port));

        // ntohs(cliAddr.sin_port),msg);

        //---------------TEST END------------------

        //if (!(original = ecies_decrypt(hex_priv, ciphered, &olen))) {
        if (!(original = ecies_decrypt(hex_priv, (secure_t *)msg, &olen)))
        {
            printf("The decryption process failed!\n");
            processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
            return -1;
        }
        printf("Original Text:Start\n");
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        for(j = 0; j < tlen; j++)
        {
            printf("%c", *(original+j));
        }
        printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        printf("Original Text:End\n");

        if (olen != tlen || memcmp(original, copy, tlen))
        {
            printf("Comparison failure.\n");
            processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
            return -1;
        }

    }/* end of server infinite loop */
    processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
    //printf(" ... %i ... %i\n", iteration + 1, tlen);

    return 0;
}

void main_cleanup(void)
{

    ecies_group_free();

    // As a child I was taught that your done eating until your plate is completely clean.
    // The following should release _all_ of the memory allocated by the OpenSSL functions used.
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    sk_pop_free((_STACK *)SSL_COMP_get_compression_methods(), CRYPTO_free);

    return;
}

int main()
{

    uint64_t i = 0;

    SSL_library_init();
    SSL_load_error_strings();

    // Initializing the group once up front cut execution time in half!  However the code should function without a reusable group.
    ecies_group_init();

    // Comment this line out if you want the program to execute consistently each time.
#if 0
    srand(time(NULL));

    for (i = 0; i < 100; i++)
    {
        if (processor(i))
        {
            main_cleanup();
            return 1;
        }
    }
#endif
    if (processor(i))
    {
        main_cleanup();
        return 1;
    }

    printf("Finished.\n");
    main_cleanup();

    return 0;
}
