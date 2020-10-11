#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <cstring>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#define PRIVAT "./privat"
#define PUBLIC "./public"

int padding = RSA_PKCS1_PADDING;
int encrypt_length;

std::string sha256(const std::string str)  //SHA-256 функция
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void RSA_key_generator() {  //генератор ключей
    char *password = "trinket";  //пароль генерации ключей
    unsigned long bits = 2048;  //key size
    FILE *priv_key_file = NULL, *pub_key_file = NULL;
    /* контекст алгоритма шифрования */

    priv_key_file = fopen(PRIVAT, "w");
    pub_key_file = fopen(PUBLIC, "w");

    RSA *rsa = RSA_generate_key(bits, 59, NULL, NULL);

    PEM_write_RSAPrivateKey(priv_key_file, rsa, NULL, NULL, NULL, NULL, NULL);
    PEM_write_RSAPublicKey(pub_key_file, rsa);

    fclose(priv_key_file);
    fclose(pub_key_file);

    std::cout << "0: (registration) public_key written to trinket(public.txt), "
                 "private_key written to trinket(privat.txt)" << std::endl;
}

int private_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {

    int result = RSA_private_encrypt(flen, from, to, key, padding);
    return result;
}

void create_encrypted_file(char* encrypted, RSA* key_pair) {

    FILE* encrypted_file = fopen("encrypted_file.bin", "w");
    fwrite(encrypted, sizeof(*encrypted), RSA_size(key_pair), encrypted_file);
    fclose(encrypted_file);
}

int public_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {

    int result = RSA_public_decrypt(flen, from, to, key, padding);
    return result;
}

std::string trinket_generate_hasndshake(RSA *trinket_pkey) {  //handshake брелка
    std::string trinket_msg = "Open the door";

    std::cout << "1: (handshake) trinket->car: \"" << trinket_msg << "\" (trinket_msg), "
    << trinket_pkey << " (trinket_public_key)" << std::endl;
    return trinket_msg;
}

std::string car_process_challenge(std::string trinket_msg) {  //random challenge авто
    std::string error_msg = "ERROR!";
    if (trinket_msg == "Open the door") {
        unsigned long int rnd_chl = rand()%(90000000)+10000000;
        std::string rnd_chl_str = std::to_string(rnd_chl);
        std::string random_challenge = sha256(rnd_chl_str);
        std::cout << "2: (challenge) car->trinket: " << random_challenge << " (challenge for trinket)" << std::endl;
        return random_challenge;
    }
    else {
        return error_msg;
    }
}

char *trinket_response(std::string car_challenge, RSA *trinket_pub_key) {  //ЭЦП брелка
    RSA *privKey = NULL;
    FILE *priv_key_file;
    std::string hash_challenge = sha256(car_challenge);
    char *encrypt = NULL;
    char *decrypt = NULL;
    priv_key_file = fopen(PRIVAT, "rb");
    PEM_read_RSAPrivateKey(priv_key_file, &privKey, NULL, NULL);
    fclose(priv_key_file);
    encrypt = (char*)malloc(RSA_size(privKey));
    encrypt_length = private_encrypt(strlen(hash_challenge.c_str())+1,
                                        (unsigned char*)hash_challenge.c_str(),
                                        (unsigned char*)encrypt, privKey, RSA_PKCS1_PADDING);
    if (encrypt_length != -1) {
        std::cout << "3: (response) trinket->car: " << (char8_t *) encrypt << " (confirm challenge for trinket)" << std::endl;
    }
    create_encrypted_file(encrypt, privKey);
    return encrypt;
}

bool car_check_response(char *trinket_response, RSA *trinket_pub_key, std::string car_challenge) {  //проверка ЭЦП
    char *decrypt = NULL;
    std::string hash_challenge = sha256(car_challenge);
    decrypt = (char *)malloc(encrypt_length);
    int decrypt_length = public_decrypt(encrypt_length, (unsigned char*)trinket_response,(unsigned char*)decrypt, trinket_pub_key, RSA_PKCS1_PADDING);
    if (decrypt_length != -1) {
        const char *hash = hash_challenge.c_str();
        if(strcmp(hash, decrypt) == 0) {  //если ЭЦП верна
            std::cout << "4: (action) car: \n\""<< hash << "\" == \n\"" << decrypt << "\" \n(check response - ok), ";
            return true;
        }
        else {
            return false;
        }
    }
}

int main(int argc, char* argv[]) {
    srand ( time(NULL) );

    RSA_key_generator();  //генерация ключей

    RSA * trinket_pubKey = NULL;  //считываем публичный ключ брелка
    FILE *pub_key_file = NULL;
    pub_key_file = fopen(PUBLIC, "rb");  //публичный ключ брелка
    trinket_pubKey = PEM_read_RSAPublicKey(pub_key_file, NULL, NULL, NULL);

    std::string trinket_msg = trinket_generate_hasndshake(trinket_pubKey);  //брелок генерирует запрос авто
    std::string car_challenge = car_process_challenge(trinket_msg);  //авто генерирует challenge брелку
    char *trinket_rspns = trinket_response(car_challenge, trinket_pubKey);  //брелок выполняет ЭЦП challenge авто
    bool car_check_rspns = car_check_response(trinket_rspns, trinket_pubKey, car_challenge);
    if (car_check_rspns) {
        std::cout << "OPEN DOOR" << std::endl;
    }
    return 0;
}
