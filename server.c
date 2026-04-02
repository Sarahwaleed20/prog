#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h> 

#define PORT 8080
#define BUFFER_SIZE 1024
#define PSK "SuperSecretKey123SuperSecretKey12"

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
}

void *handle_client(void *socket_desc) {
    int new_socket = *(int*)socket_desc;
    free(socket_desc);

    unsigned char buffer[BUFFER_SIZE];
    unsigned char client_hmac[32], server_hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    int nonce;
    unsigned char iv[16], key[32];

    read(new_socket, &nonce, sizeof(nonce));
    read(new_socket, client_hmac, 32);
    HMAC(EVP_sha256(), PSK, strlen(PSK), (unsigned char*)&nonce, sizeof(nonce), server_hmac, &hmac_len);

    if (memcmp(client_hmac, server_hmac, 32) != 0) {
        printf("HMAC Authentication failed\n");
        close(new_socket);
        return NULL;
    }

    char username[50] = {0}, password_hash[128] = {0};
    read(new_socket, username, 50);
    read(new_socket, password_hash, 128);

    username[strcspn(username, "\r\n")] = 0;
    password_hash[strcspn(password_hash, "\r\n")] = 0;

    FILE *fptr = fopen("users.txt", "r");
    if (!fptr) {
        perror("Could not open users.txt");
        close(new_socket);
        return NULL;
    }

    char file_user[50], file_hash[128];
    int auth_success = 0;
    while (fscanf(fptr, "%s %s", file_user, file_hash) != EOF) {
        if (strcmp(file_user, username) == 0 && strcmp(file_hash, password_hash) == 0) {
            auth_success = 1;
            break;
        }
    }
    fclose(fptr);

    if (!auth_success) {
        printf("Login failed for: %s\n", username);
        close(new_socket);
        return NULL;
    }
    printf("User %s authenticated successfully\n", username);

    RAND_bytes(iv, sizeof(iv));
    send(new_socket, iv, sizeof(iv), 0);
    memcpy(key, PSK, 32);

    int ciphertext_len = read(new_socket, buffer, BUFFER_SIZE);
    unsigned char plaintext[BUFFER_SIZE];
    decrypt(buffer, ciphertext_len, key, iv, plaintext);
    printf("Decrypted message: %s\n", plaintext);

    close(new_socket);
    return NULL;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 5);
    printf("Server listening on port %d\n", PORT);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        int *new_sock = malloc(sizeof(int));
        *new_sock = new_socket;

        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void*)new_sock);
        pthread_detach(thread_id); 
    }
    close(server_fd);
    return 0;
}