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

void hash_password(const char *password, char *output_buffer) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), NULL);
    EVP_DigestUpdate(context, password, strlen(password));
    EVP_DigestFinal_ex(context, hash, &hash_len);
    EVP_MD_CTX_free(context);
    for(int i = 0; i < hash_len; i++) sprintf(output_buffer + (i * 2), "%02x", hash[i]);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
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
    unsigned char hmac[EVP_MAX_MD_SIZE], iv[16], key[32];
    unsigned int hmac_len;
    int nonce;

    char username[50], password[50], password_hash[129] = {0};

    printf("Enter Username: ");
    scanf("%s", username);
    printf("Enter Password: ");
    scanf("%s", password);

    hash_password(password, password_hash);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) return -1;

    srand(time(NULL));
    nonce = rand();
    HMAC(EVP_sha256(), PSK, strlen(PSK), (unsigned char*)&nonce, sizeof(nonce), hmac, &hmac_len);
    send(sock, &nonce, sizeof(nonce), 0);
    send(sock, hmac, 32, 0);

    char user_buf[50] = {0}, hash_buf[128] = {0};
    strncpy(user_buf, username, 49);
    strncpy(hash_buf, password_hash, 127);
    send(sock, user_buf, 50, 0);
    send(sock, hash_buf, 128, 0);

    if (read(sock, iv, sizeof(iv)) <= 0) {
        printf("Authentication failed on server side.\n");
        close(sock);
        return -1;
    }

    memcpy(key, PSK, 32);
    char *msg = "Hello secure server!";
    unsigned char ciphertext[BUFFER_SIZE];
    int c_len = encrypt((unsigned char*)msg, strlen(msg), key, iv, ciphertext);
    send(sock, ciphertext, c_len, 0);

    printf("Encrypted message sent successfully!\n");
    close(sock);
    return 0;
}