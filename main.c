/*
 *
 * THIS IS A BASIC IMPLEMENTATION OF THE SHA256 ALGORITHM
 * THE SPECIFICATION FOR SHA256 CAN BE FOUND HERE:
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * 
 * TESTED WITH https://emn178.github.io/online-tools/sha256.html
 *
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sha256.h"


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Add 1 argument\n");
        return 0;
    }
    char *hashed = sha256(argv[1]);
    printf("%s\n", hashed);
    free(hashed);
}
