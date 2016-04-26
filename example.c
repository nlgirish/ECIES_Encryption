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
    tlen = 40;

    if (!(text = malloc(tlen + 1)) || !(copy = malloc(tlen + 1)))
    {
        printf("Memory error.\n");
        processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
        return -1;
    }

    // Wipe and then fill the data blocks with random data.
    memset(copy, 0, tlen + 1);
    memset(text, 0, tlen + 1);
    char a[40] = "Hello World.Hello World.123456789012345";
    for (j = 0; j < tlen; j++)
    {
        *(copy + j) = *(text + j) = a[j];
    }

    // Generate a key for our theoretical user.
    if (!(key = ecies_key_create()))
    {
        printf("Key creation failed.\n");
        processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
        return -1;
    }
    //-------------------TEST------------------TODO

    EVP_PKEY *skey = NULL;
    EVP_PKEY *vkey = NULL;
    FILE* fp = fopen ("eckey.pem", "r");
    const char cert_filestr[] = "./cert.pem";

    BIO              *certbio = NULL;
    BIO               *outbio = NULL;
    X509                *cert = NULL;

    certbio = BIO_new(BIO_s_file());
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

    /* ---------------------------------------------------------- *
     * Load the certificate from file (PEM).                      *
     * ---------------------------------------------------------- */
    BIO_read_filename(certbio, cert_filestr);
    if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
    {
        BIO_printf(outbio, "Error loading cert into memory\n");
        exit(-1);
    }

    /* ---------------------------------------------------------- *
     * Extract the certificate's public key data.                 *
     * ---------------------------------------------------------- */
    if ((vkey = X509_get_pubkey(cert)) == NULL)
        BIO_printf(outbio, "Error getting public key from certificate");

    if(!PEM_write_bio_PUBKEY(outbio, vkey))
        BIO_printf(outbio, "Error writing public key data in PEM format");

    //-------------------TEST END--------------TODO

    // Since we'll store the keys as hex values in reali life, extract the appropriate hex values and release the original key structure.
    //if (!(hex_pub = ecies_key_public_get_hex(key)) || !(hex_priv = ecies_key_private_get_hex(key))) {
    if (!(hex_pub = ecies_key_public_get_hex(vkey->pkey.ec)) || !(hex_priv = ecies_key_private_get_hex(skey->pkey.ec)))
    {
        printf("Serialization of the key to a pair of hex strings failed.\n");
        processor_cleanup(key, ciphered, hex_pub, hex_priv, text, copy, original);
        return -1;
    }
    //---------------TEST------------------TODO
    printf("Pub Key Print:\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("%s\n", hex_pub);
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    j = 0;
    while(hex_pub[j] != '\0')
    {
        printf("%c", hex_pub[j]);
        j++;
    }
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("Pri Key Print:\n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("%s\n", hex_priv);
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    //---------------TEST END------------------TODO

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
    //---------------TEST END------------------

    //if (!(original = ecies_decrypt(hex_priv, ciphered, &olen))) {
    if (!(original = ecies_decrypt(hex_priv, cryptex, &olen)))
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
