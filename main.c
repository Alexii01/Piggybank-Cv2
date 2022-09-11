#include <stdint.h>
#include <time.h>
#include <math.h>

struct data{
    uint64_t main;
    uint64_t extra;
    uint64_t last_contribution;
    struct tm start_date;
    struct tm last_date;
};

#ifdef _WIN32
#include <conio.h>
#else
#include <stdio.h>
#define clrscr() system("clear");
#endif

#if 1
    #include "verbose.h"
#else
    #include "normal.h"
#endif

void wait_clrscr(char *s){
    printf("%sPress ENTER to continue...", s);
    while(getchar() != 10) continue;
    while(getchar() != 10) continue;

    clrscr();
}

int read_pass(char *output, char *add){
    printf("Enter password %s:\n", add);

    while(1){
        if(!fgets(output, 17, stdin)){
            perror("Couldn't read password");
            return 1;
        }

        if(strlen(output) > 1){
            clrscr();
            return 0;
        }
    }
}


int parse_args(int argc, char **argv){
    for(int i=1; i<argc; i++){
        if(!(strcmp("-h", argv[i]) && strcmp("--help", argv[i]))){
            printf("HELP:\n\t-h (--help) : shows all flags\n\t-d          : outputs function debug info for range 0-100\n\t-v          : verbose operation\n");
            return 0;
        } else if(!strcmp(argv[i], "-d")){
            // TODO: Open file, calculate values, write them down
            printf("Will output files here\n");
            return 0;
        }
    }

    return 1;
}

double diffdate(struct tm start, struct tm end){
    return ((uint64_t) abs(mktime(&start) - mktime(&end))) / 86400;
}

uint64_t exp_balance(struct tm start, struct tm end){

    double diff = diffdate(start, end);

    // Changeable function
    return (uint64_t) ((diff / 2) * (diff + 1));
}


uint64_t exp_contribution(struct tm start, struct tm end){
    return diffdate(start, end);
}

void print_digest(struct data dataptr, struct tm now){
    printf("%08.2lf  |  %08.2lf\n%08.2lf  |  %08.2lf\n", ((double) dataptr.main) / 100, ((double) exp_balance(dataptr.start_date, now)) / 100, ((double) dataptr.last_contribution) / 100, ((double) exp_contribution(dataptr.start_date, now)) / 100);
    //printf("Read aid:\n\tbalance:expected balance\n\tleft to contribute:expected contribution\n");
}

void print_full(struct data dataptr){

}

int bank_operation(uint64_t *ptr, char * valname){
    double input = 0;

    printf("Add to %s: ", valname);
    while(1)
        if(scanf("%lf", &input)) break;

    input = (int) (input * 100);

    if(!input) return 1;

    *ptr += (int64_t) input;
    return 0;
}

void delete_data(char *realpass){
    clrscr();
    wait_clrscr("You are going to delete your data\n");

    char supppass[17];
    read_pass(supppass, "to confirm data deletion");;
    if(strcmp(supppass, realpass)) return NULL;

    printf("Correct password. The operation will now start.\n");

    FILE *fptr = fopen("data.bin", "wb");
    if(!fptr) return NULL;

    uint8_t val;

    for(int i=0; i<160; i++){
        val = (uint8_t) (rand() % 255);
        fwrite(&val, 1, 1, fptr);
    }

    remove("data.bin");

    printf("Delete finished successfully\n");

    wait_clrscr("");
}

int main(int argc, char **argv){
    // Temporary int to store return values from functions
    int temp_result = 0;

    if(!parse_args(argc, argv))
        return 1;

    clrscr();

    FILE *fileptr = fopen("data.bin", "rb");

    if(!fileptr){
        perror("Error on read 'data.bin'");
        wait_clrscr("The file will be generated.\n");
        printf("Generating file\n");

        temp_result = file_gen();
        if(temp_result) return temp_result;

        printf("Data file has been successfully created. Exiting.\n");
        wait_clrscr("");
    } else {
        unsigned char pass[17] = "";
        if(read_pass((char*) pass, "for login")) return 1;

        struct data currdata;
        temp_result = file_read(&currdata, pass);
        if(temp_result) return temp_result;

        wait_clrscr("");

        time_t now_time = time(NULL);
        struct tm now = *localtime(&now_time);
        int choice = 0;

        while(choice != 3){
            clrscr();
            printf("Choose one of the options:\n1) See digest\n12) See full info\n2) Withdraw/deposit main\n21) Withdraw/deposit extra\n3) Exit\n");

            if(!scanf("%d", &choice)) continue;

            switch (choice)
            {
            case 1:
                clrscr();
                print_digest(currdata, now);
                wait_clrscr("");
                break;

            case 12:
                //See full info (in groups!!!)
                break;

            case 2:
                clrscr();
                if(bank_operation(&currdata.main, "main")) {
                    printf("Operation unsuccessful\n");
                }else{
                    file_write(&currdata, pass);
                    printf("Operation successful\n");
                }

                wait_clrscr("");
                break;

            case 21:
                clrscr();
                if(bank_operation(&currdata.extra, "extra")) {
                    printf("Operation unsuccessful\n");
                }else{
                    file_write(&currdata, pass);
                    printf("Operation successful\n");
                }

                wait_clrscr("");
                break;

            case 4:
                delete_data(pass);
                return 0;

            default:
                break;
            }
        }
    }

    return 0;
}