#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

void print_hex(uint8_t * string, uint8_t len, uint8_t blocksize, uint8_t sep, char *blocksep, uint8_t last){
    int iter;

    for(iter=0; iter<len; iter++){
        printf("%02x%c", string[iter], sep);
        if((((iter + 1) % blocksize) == 0) || (iter == (len - 1)))
            printf("%s", blocksep);
    }
    printf("%c", last);
}

// Uses openssl Ciphers to encrypt or decrypt input
uint64_t crypt(uint8_t *input, int inputlen, const uint8_t *keyptr, const EVP_CIPHER *alg, int direction, uint8_t **output, uint8_t *outlen){

    printf("Initialising cipher context and value. ");
    int len = 0;
    uint8_t *value = (uint8_t*) calloc(1, ((inputlen/16) + 1) * 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if((!ctx) || (!value)) goto err;
    printf("Success\n");

    if(!EVP_CipherInit_ex2(ctx, alg, NULL, NULL, direction, NULL)) goto err;
    printf("Cipher: pre-initialised\n");

    OPENSSL_assert(EVP_CIPHER_CTX_get_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_get_iv_length(ctx) == 16);
    printf("Cipher: Key and IV lengths are 16. Finishing intialisation. ");

    if(!EVP_CipherInit_ex2(ctx, alg, keyptr, keyptr, direction, NULL)) goto err;
    printf("Success.\nCipher: initialised\n");
    if(!EVP_CipherUpdate(ctx, value, &len, input, inputlen)) goto err;
    printf("Cipher: successfully updated\n");
    *outlen += len;

    if(!EVP_CipherFinal_ex(ctx, value + len, &len)) goto err;
    printf("Cipher: successfully finalised\n");
    *outlen += len;

    EVP_CIPHER_CTX_free(ctx);
    printf("Freed context\n");

    *output = value;

    return 0;

    err:
        if(ctx) EVP_CIPHER_CTX_free(ctx);
        if(value) free(value);
        printf("Cipher context and value have been freed.\n");

        return ERR_get_error();
}

// Uses openssl Digests to encrypt input
uint64_t digest_crypt(const void *input, int inlen, const EVP_MD *alg, uint8_t **output){

    printf("Initialising digest context and value. ");
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    uint8_t *md_value = (uint8_t* ) calloc(1, EVP_MAX_MD_SIZE);
    unsigned int md_len = 0;

    if((!md_value) || (!mdctx)) goto err;
    printf("Success\n");

    if(!EVP_DigestInit_ex2(mdctx, alg, NULL)) goto err;
    printf("Digest: successfully initialised\n");
    if(!EVP_DigestUpdate(mdctx, input, inlen)) goto err;
    printf("Digest: successfully updated\n");
    if(!EVP_DigestFinal_ex(mdctx, md_value, &md_len)) goto err;
    printf("Digest: successfully finalised\n");

    EVP_MD_CTX_free(mdctx);
    printf("Freed context\n");

    *output = md_value;

    return 0;

    err:
        if(mdctx) EVP_MD_CTX_free(mdctx);
        if(md_value) free(md_value);
        printf("Digest context and value have been freed.\n");
        return ERR_get_error();
}

// Encrypts data and writes it
int file_write(struct data *sample_data, uint8_t *pass){
    uint8_t *hash = NULL, *encdata = NULL, outlen = 0;
    FILE *fileptr;

    printf("Calculating data hash\n");
    uint64_t result = digest_crypt(sample_data, sizeof(struct data), EVP_sha256(), &hash);
    if(result) goto cipherr;

    printf("Encoding the data\n");
    result = crypt((uint8_t*) sample_data, sizeof(struct data), pass, EVP_aes_128_cbc(), 1, &encdata, &outlen);
    if(result) goto cipherr;


    fileptr = fopen("data.bin", "wb");
    if(!fileptr) goto writerr;
    printf("Opened 'data.bin'\n");

    if(!fwrite(hash, 32, 1, fileptr)) goto writerr;
    if(!fwrite(encdata, outlen, 1, fileptr)) goto writerr;
    printf("Data + hash have been written succesfully\n");

    fclose(fileptr);
    free(encdata);
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

    printf("Instruction given: read a file\n");

    uint8_t hash[32], encdata[144], *genhash = NULL, *data = NULL, outlen = 0;
    FILE *fileptr = fopen("data.bin", "rb");
    uint64_t result;

    if(!fileptr) goto readerr;

    printf("Opened the file. ");

    if(!fread(hash, 32, 1, fileptr)) goto readerr;
    printf("Read hash\n");

    if(!fread(encdata, 144, 1, fileptr)) goto readerr;
    printf("Read encoded data:\n\t");
    print_hex(encdata, 144, 16, ' ',  "\n\t", '\r');

    fclose(fileptr);

    result = crypt(encdata, 144, pass, EVP_aes_128_cbc(), 0, &data, &outlen);
    if(result) goto cipherr;

    printf("\rDecoded data:\n\t");
    print_hex(data, 144, 16, ' ',  "\n\t", '\r');

    result = digest_crypt(data, sizeof(struct data), EVP_sha256(), &genhash);
    if(result) goto cipherr;

    printf("\rComparing hashes. Expected hash:\n\t");
    print_hex(hash, 32, 16, ' ', "\n\t", '\r');
    printf("\t\t\t      VS\n\t");
    print_hex(genhash, 32, 16, ' ', "\n\t", '\r');

    if(!memcmp(genhash, hash, 32)){
        printf("\rHashes are equal. Decoding is complete!\nCopying data from a temporary buffer.\n");
        memcpy(output, data, outlen);
        result = 0;
        printf("Finished. File was read correctly!\n");
    } else{
        result = -1;
        printf("Finished. File was not read correctly!\n");
    }

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
    struct data sample_data = {0, 0, 0, {}, {}};

    printf("Enter start of saving date in YYYY m d, (i.e. 1992 1 2 for 2 Jan 1992)\n");

    int year = 0, month = 0, day = 0;

    while(1){
        if(scanf("%d %d %d", &year, &month, &day) != 3) continue;

        if((year >= 1900) && ((month > 0) && (month <= 12)) && ((day > 0) && (day <= 31))){
            sample_data.start_date.tm_year = year - 1900;
            sample_data.start_date.tm_mon = month - 1;
            sample_data.start_date.tm_mday = day;
        }else{
            printf("Wrong format or incorrect values.");
            continue;
        }

        break;
    }

    clrscr();

    uint8_t pass[17] = "";

    while(read_pass((char*) pass, "for file encryption (max length 16)"))
        perror("Couldn't read password (try again or fix the underlying problem)");

    int result = file_write(&sample_data, pass);

    return result;
}