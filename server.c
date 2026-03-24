#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define PSK "SuperSecretKey123SuperSecretKey12"

void decrypt(unsigned char *ciphertext, int ciphertext_len,
             unsigned char *key, unsigned char *iv,
             unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    plaintext[plaintext_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);
}

int main() {

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char client_hmac[32];
    unsigned char server_hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;

    int nonce;

    unsigned char iv[16];
    unsigned char key[32];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));

    listen(server_fd, 3);

    printf("Server listening on port %d\n", PORT);

    new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);

    printf("Client connected\n");

    read(new_socket, &nonce, sizeof(nonce));
    read(new_socket, client_hmac, 32);

    HMAC(EVP_sha256(),
         PSK, strlen(PSK),
         (unsigned char*)&nonce, sizeof(nonce),
         server_hmac, &hmac_len);

    if (memcmp(client_hmac, server_hmac, 32) != 0) {
        printf("Authentication failed\n");
        close(new_socket);
        return 0;
    }

    printf("Client authenticated\n");

    RAND_bytes(iv, sizeof(iv));

    send(new_socket, iv, sizeof(iv), 0);

    memcpy(key, PSK, 32);

    int ciphertext_len = read(new_socket, buffer, BUFFER_SIZE);

    unsigned char plaintext[BUFFER_SIZE];

    decrypt(buffer, ciphertext_len, key, iv, plaintext);

    printf("Decrypted message: %s\n", plaintext);

    close(new_socket);
    close(server_fd);

    return 0;
}