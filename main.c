#include <time.h>

const int VERBOSE = 0;

#if VERBOSE
    #include "verbose.h"
#else
    #include "normal.h"
#endif

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

        if(VERBOSE){
            printf("Programme running in VERBOSE mode\n");
        }
    }

    return 1;
}

int main(int argc, char **argv){
    // Temporary int to store return values from functions
    int temp_result = 0;

    if(!parse_args(argc, argv))
        return 1;

    FILE *fileptr = fopen("data.bin", "rb");

    if(!fileptr){
        perror("Error on read 'data.bin' ");
        printf("Generating file\n");

        temp_result = file_gen();
        if(temp_result) return temp_result;

        printf("Data file has been successfully created. Exiting.\n");
    } else {
        unsigned char pass[17] = "";
        if(read_pass((char*) pass, "for login")) return 1;

        struct data currdata;
        temp_result = file_read(&currdata, pass);
        if(temp_result) return temp_result;

        int choice = 0;

        while(choice != 3){
            printf("Choose one of the options:\n1) See digest\n12) See full info\n2) Withdraw/deposit main\n21) Withdraw/deposit extra\n3) Exit\n");

            if(!fscanf("%d", &choice)) continue;

            switch (choice)
            {
            case 1:
                //See digest
                break;

            case 12:
                //See full info (in groups!!!)
                break;

            case 2:
                //Withdraw/deposit (func takes main ptr)
                break;

            case 21:
                //Withdraw/deposit (func takes extra ptr)
                break;

            case 4:
                //Ask for password once again to delete all data
                break;

            default:
                break;
            }
        }
    }

    return 0;
}