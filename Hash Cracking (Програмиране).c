#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

void sha256_string(const char *str, char *output) {

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, str, strlen(str));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    output[64] = '\0';
}

int main() {

    char target_hash[] =
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    char guess[4];
    char computed_hash[65];

    printf("--- Starting SHA-256 Brute Force ---\n");

    for (char a = 'A'; a <= 'Z'; a++) {

        for (char b = 'A'; b <= 'Z'; b++) {

            for (char c = 'A'; c <= 'Z'; c++) {

                guess[0] = a;
                guess[1] = b;
                guess[2] = c;
                guess[3] = '\0';

                sha256_string(guess, computed_hash);

                if (strcmp(computed_hash, target_hash) == 0) {

                    printf("[SUCCESS] Password found: %s\n", guess);
                    return 0;
                }
            }
        }
    }

    printf("Password not found.\n");

    return 0;
}