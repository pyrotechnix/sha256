#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// PARAMATERS
//  message:
//      This is the message that you want to encrypt
//
// RETURN VALUE
//      A null-terminated hex string that contains the hashed message
char *sha256(char *message);
