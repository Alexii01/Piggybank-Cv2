
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

struct data{
    uint64_t main;
    uint64_t extra;
    uint64_t last_contribution;
    char last_date[20];
};

// Uses openssl Ciphers to encrypt or decrypt input
uint64_t crypt(uint8_t *input, int inputlen, const uint8_t *keyptr, const EVP_CIPHER *alg, int direction, uint8_t **output, uint8_t *outlen){

    int len = 0;
    uint8_t *value = (uint8_t*) calloc(1, ((inputlen/16) + 1) * 16);
    if(!value) goto err;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) goto err;

    if(!EVP_CipherInit_ex2(ctx, alg, NULL, NULL, direction, NULL)) goto err;

    OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_get_iv_length(ctx) == 16);

    if(!EVP_CipherInit_ex2(ctx, alg, keyptr, keyptr, direction, NULL)) goto err;
    if(!EVP_CipherUpdate(ctx, value, &len, input, inputlen)) goto err;
    *outlen += len;

    if(!EVP_CipherFinal_ex(ctx, value + len, &len)) goto err;
    *outlen += len;

    EVP_CIPHER_CTX_free(ctx);

    *output = value;

    return 0;

    err:
        if(ctx) EVP_CIPHER_CTX_free(ctx);
        if(value) free(value);

        return ERR_get_error();
}

// Uses openssl Digests to encrypt input
uint64_t digest_crypt(const void *input, int inlen, const EVP_MD *alg, uint8_t **output){

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(!mdctx) goto err;

    uint8_t *md_value = (uint8_t* ) calloc(1, EVP_MAX_MD_SIZE);
    if(!md_value) goto err;

    unsigned int md_len = 0;

    if(!EVP_DigestInit_ex2(mdctx, alg, NULL)) goto err;
    if(!EVP_DigestUpdate(mdctx, input, inlen)) goto err;
    if(!EVP_DigestFinal_ex(mdctx, md_value, &md_len)) goto err;

    EVP_MD_CTX_free(mdctx);

    *output = md_value;

    return 0;

    err:
        if(mdctx) EVP_MD_CTX_free(mdctx);
        if(md_value) free(md_value);
        return ERR_get_error();
}

int read_pass(char *output, char *add){
    while(1){
        printf("Enter password %s (max length 16): ", add);

        if(!fgets(output, 17, stdin)){
            perror("Couldn't read password");
            return 1;
        }

        if(strlen(output) > 1)
            return 0;
    }
}

// Encrypts data and writes it
int file_write(struct data *sample_data, uint8_t *pass){
    uint8_t *hash = NULL, *encdata = NULL, outlen = 0;

    uint64_t result = digest_crypt(sample_data, sizeof(struct data), EVP_sha256(), &hash);
    if(result) goto cipherr;

    result = crypt(sample_data, sizeof(struct data), pass, EVP_aes_128_cbc(), 1, &encdata, &outlen);
    if(result) goto cipherr;

    FILE *fileptr = fopen("data.bin", "wb");
    if(!fileptr) goto writerr;

    if(!fwrite(hash, 32, 1, fileptr)) goto writerr;
    if(!fwrite(encdata, outlen, 1, fileptr)) goto writerr;

    fclose(fileptr);
    free(hash);

    return 0;

    cipherr:
        printf("Cipher error : %s\n", ERR_error_string(result, NULL));
        if(encdata) free(encdata);
        if(hash) free(hash);

        return result;

    writerr:
        perror("Couldn't interact with 'data.bin'");

        if(fileptr) fclose(fileptr);
        if(encdata) free(encdata);
        if(hash) free(hash);

        return 1;
}

// Reads data and decrypts it (if the pass is correct). Returns -1 if the password's wrong
int file_read(struct data *output, uint8_t *pass){

    uint8_t hash[32], encdata[64], *genhash = NULL, *data = NULL, outlen = 0;
    FILE *fileptr = fopen("data.bin", "rb");

    if(!fileptr) goto readerr;

    if(!fread(hash, 32, 1, fileptr)) goto readerr;
    if(!fread(encdata, 64, 1, fileptr)) goto readerr;
    if(ferror(fileptr)) goto readerr;

    fclose(fileptr);

    uint64_t result = crypt(encdata, 64, pass, EVP_aes_128_cbc(), 0, &data, &outlen);
    if(result) goto cipherr;

    result = digest_crypt(data, sizeof(struct data), EVP_sha256(), &genhash);
    if(result) goto cipherr;

    if(!strcmp((char *) hash, (char*) genhash)){
        memcpy(output, data, outlen);
        result = 0;
    } else result = -1;

    free(genhash);
    free(data);

    return result;

    cipherr:
        printf("Cipher error (most likely wrong password): %s\n", ERR_error_string(result, NULL));

        if(data) free(data);
        if(genhash) free(genhash);

        return 20;

    readerr:
        perror("Couldn't read file 'data.bin'");

        return 1;
}

int file_gen(){
    //TODO: add date here------------v
    struct data sample_data = {12, 34, 56, "78"};
    uint8_t pass[17] = "";

    while(read_pass((char*) pass, "for file encryption"))
        perror("Couldn't read password (try again or fix the underlying problem)");

    int result = file_write(&sample_data, pass);

    return result;
}

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

/*
  * Current:
        TODO: DEBUG
        * reading the file (file_read) -- Returns Error 20.
        * Add file read and basic data output (for debugging). On read make sure to check the date stuff

    Add functions for:

        Expected balance (with start-end dates)

    In main:

        Add withdraw/deposit money
        Add clear data (overwrite with random and then remove file, basically)
*/

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

        result = file_gen();
        if(result) return result;

        printf("Data file has been successfully created. Exiting.\n");
    } else {
        unsigned char pass[17] = "";
        if(read_pass((char*) pass, "for login")) return 1;

        struct data currdata = {1, 1, 1, "a"};
        result = file_read(&currdata, pass);
        if(result) return result;

        printf("Success!\n");
    }

    return 0;
}