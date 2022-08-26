#include <openssl/evp.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

/*
    TODO: Look through the gLitCHY part and find why pointers don't work. Dynamic memory?

    Expected experience:
        user inputs the correct password --> It works

        Confirm with hash.
        Crypt with raw password.

    Custom Return codes:
        0 = OK
        1 = Unknown (printed out)
        20 = Cipher failure

*/
struct data{
    uint64_t main;
    uint64_t extra;
    char last_date[20];
    uint64_t last_contribution;
};

int parse_args(int argc, char **argv, int verb){
    for(int i=1; i<argc; i++){
        if(!(strcmp("-h", argv[i]) && strcmp("--help", argv[i]))){
            printf("HELP:\n\t-h (--help) : shows all flags\n\t-d          : outputs function debug info for range 0-100\n\t-v          : verbose operation\n");
            return 0;
        } else if(!strcmp(argv[i], "-d")){
            // TODO: Open file, calculate values, write them down
            printf("Will output files here\n");
            return 0;
        } else if(!strcmp(argv[i], "-v")){
            printf("Programme running in VERBOSE mode\n");
            verb = 1;
            return 1;
        }
    }

    return 1;
}

// The difference from digest_crypt_pass is that Ciphers are used here, not Digests
int crypt(uint8_t *input, int inputlen, uint8_t *keyptr, const EVP_CIPHER *alg, int direction, uint8_t **output){

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!ctx) return 20;

    uint8_t *value = (uint8_t*) calloc(1, EVP_MAX_MD_SIZE + EVP_MAX_BLOCK_LENGTH);
    int len = 0;

    EVP_CipherInit_ex2(ctx, alg, NULL, NULL, direction, NULL);

    OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(ctx) == 16);

    uint8_t *key = (uint8_t*) malloc(17);
    memcpy(key, keyptr, 16);

    if(!EVP_CipherInit_ex2(ctx, alg, key, NULL, direction, NULL)) goto err;
    if(!EVP_CipherUpdate(ctx, value, &len, input, inputlen)) goto err;
    if(!EVP_CipherFinal_ex(ctx, value + len, &len)) goto err;

    EVP_CIPHER_CTX_free(ctx);
    free(key);

    *output = value;

    return 0;

    err:
        printf("Cipher error\n");
        EVP_CIPHER_CTX_free(ctx);
        free(value);
        free(key);
        return 20;
}

// The difference from crypt is that Digests are used here, not Ciphers
int digest_crypt_pass(unsigned char *pass, const EVP_MD *alg, uint8_t **output){

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if(!mdctx) return 20;

    uint8_t *md_value = (uint8_t* ) calloc(1, EVP_MAX_MD_SIZE);
    unsigned int md_len = 0;

    if(!EVP_DigestInit_ex2(mdctx, alg, NULL)) goto err;
    if(!EVP_DigestUpdate(mdctx, pass, 16)) goto err;
    if(!EVP_DigestFinal_ex(mdctx, md_value, &md_len)) goto err;

    EVP_MD_CTX_free(mdctx);

    *output = md_value;

    return 0;

    err:
        printf("Digest error\n");
        EVP_MD_CTX_free(mdctx);
        free(md_value);
        return 20;
}

int read_pass(char *output, char *add){
    while(1){
        printf("Enter password %s (max length 16): ", add);

        if(!fgets(output, 17, stdin))
            return 1;
        else
            if(strlen(output) > 1)
                return 0;
    }
}

int gen_file(){
    //TODO: add date here------------v
    struct data sample_data = {0, 0, "", 0};

    uint8_t pass[17];

    while(read_pass((char*) pass, "for file encryption"))
        perror("Couldn't read password (try again or fix the underlying problem)");

    return 0;

    writerr:
        perror("Couldn't interact with 'data.bin'");
        return 1;
}

int main(int argc, char **argv){
    int VERBOSE = 0;

    // Temporary int to store return values from functions
    int result = 0;

    if(!parse_args(argc, argv, VERBOSE))
        return 1;

    FILE *fileptr = fopen("data.bin", "rb");

    if(!fileptr){
        perror("Error on read 'data.bin' ");
        printf("Generating file\n");

        result = gen_file();
        if(result) return result;

        printf("Data file has been successfully created. Exiting.\n");
    } else {

    }

    return 0;
}

