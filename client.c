#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define PSK "SuperSecretKey123SuperSecretKey12"

int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main() {

    int sock;
    struct sockaddr_in server_address;

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;

    int nonce;

    unsigned char iv[16];
    unsigned char key[32];

    sock = socket(AF_INET, SOCK_STREAM, 0);

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    connect(sock, (struct sockaddr*)&server_address, sizeof(server_address));

    printf("Connected to server\n");

    srand(time(NULL));
    nonce = rand();

    HMAC(EVP_sha256(),
         PSK, strlen(PSK),
         (unsigned char*)&nonce, sizeof(nonce),
         hmac, &hmac_len);

    send(sock, &nonce, sizeof(nonce), 0);
    send(sock, hmac, 32, 0);

    printf("CLIENT_HELLO sent\n");

    read(sock, iv, sizeof(iv));

    printf("IV received\n");

    memcpy(key, PSK, 32);

    char *message = "Hello secure server";

    unsigned char ciphertext[BUFFER_SIZE];

    int ciphertext_len = encrypt((unsigned char*)message,
                                 strlen(message),
                                 key,
                                 iv,
                                 ciphertext);

    send(sock, ciphertext, ciphertext_len, 0);

    printf("Encrypted message sent\n");

    close(sock);

    return 0;
}