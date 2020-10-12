#include <iostream>
#include <string>
#include <iomanip>
#include <fstream>
#include <cstring>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define PRIVAT "./privat"
#define PUBLIC "./public"

int encrypt_length;

/* Возвращает SHA-256 hash */
std::string sha256(const std::string str)
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

/* Генерация пары ключей по алгоритму RSA */
void RSA_key_generator() {
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

/* Шифрование данных закрытым ключом по алгоритму RSA */
int private_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    int result = RSA_private_encrypt(flen, from, to, key, padding);
    return result;
}

/* Создание зашифрованного файла */
void create_encrypted_file(char* encrypted, RSA* key_pair) {
    FILE* encrypted_file = fopen("encrypted_file.bin", "w");
    fwrite(encrypted, sizeof(*encrypted), RSA_size(key_pair), encrypted_file);
    fclose(encrypted_file);
}

/* Дешифрование данных открытым ключом по алгоритму RSA */
int public_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    int result = RSA_public_decrypt(flen, from, to, key, padding);
    return result;
}

/* Брелок запрашивает разрешение на открытие двери у автомобиля */
std::string trinket_generate_hasndshake(RSA *trinket_pkey) {
    std::string trinket_msg = "Open the door";
    std::cout << "1: (handshake) trinket->car: \"" << trinket_msg << "\" (trinket_msg), "
    << trinket_pkey << " (trinket_public_key)" << std::endl;
    return trinket_msg;
}

/* Автомобиль отсылает брелку random challenge */
std::string car_process_challenge(std::string trinket_msg) {
    std::string error_msg = "ERROR!";
    if (trinket_msg == "Open the door") {
        unsigned char buf[32];
        RAND_bytes(buf, 32);  //генерируем 32 рандомных байта
        std::string rnd_chl_str((char*) buf);
        std::string random_challenge = sha256(rnd_chl_str);
        std::cout << "2: (challenge) car->trinket: " << random_challenge << " (challenge for trinket)" << std::endl;
        return random_challenge;
    }
    else {
        return error_msg;
    }
}

/* Брелок выполняет ЭЦП challenge и возвращает её автомобилю */
char *trinket_response(std::string car_challenge, RSA *trinket_pub_key) {
    RSA *privKey = NULL;
    FILE *priv_key_file;
    std::string hash_challenge = sha256(car_challenge);  //хешируем challenge по SHA-256
    char *encrypt = NULL;

    priv_key_file = fopen(PRIVAT, "rb");
    PEM_read_RSAPrivateKey(priv_key_file, &privKey, NULL, NULL);  //считываем секретный ключ из файла
    fclose(priv_key_file);

    encrypt = (char*)malloc(RSA_size(privKey));
    /* Шифруем по закрытому ключу */
    encrypt_length = private_encrypt(strlen(hash_challenge.c_str())+1,
                                        (unsigned char*)hash_challenge.c_str(),
                                        (unsigned char*)encrypt, privKey, RSA_PKCS1_PADDING);
    if (encrypt_length != -1) {
        std::cout << "3: (response) trinket->car: " << (char16_t*) encrypt << " (confirm challenge for trinket)" << std::endl;
    }
    create_encrypted_file(encrypt, privKey);  //создаем бинарный файл зашифрованного сообщения
    return encrypt;
}

/* Автомобиль проверяет подлинность ЭЦП брелка на challenge */
bool car_check_response(char *trinket_response, RSA *trinket_pub_key, std::string car_challenge) {
    std::string hash_challenge = sha256(car_challenge);
    char *decrypt = NULL;
    decrypt = (char *)malloc(encrypt_length);
    /* Расшифровываем по открытому ключу брелка */
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
    if (!(std::string(argv[1]) == "--trinket" && std::string(argv[2]) == "open")) {
        std::cout << "Проверьте правильность введенных вами данных\n";
        return 1;
    }

    RSA_key_generator();  //генерация ключей брелка
    /* Считываем публичный ключ брелка */
    RSA * trinket_pubKey = NULL;
    FILE *pub_key_file = NULL;
    pub_key_file = fopen(PUBLIC, "rb");  //публичный ключ брелка
    trinket_pubKey = PEM_read_RSAPublicKey(pub_key_file, NULL, NULL, NULL);

    std::string trinket_msg = trinket_generate_hasndshake(trinket_pubKey);  //брелок генерирует запрос авто
    std::string car_challenge = car_process_challenge(trinket_msg);  //авто генерирует challenge брелку
    char *trinket_rspns = trinket_response(car_challenge, trinket_pubKey);  //брелок выполняет ЭЦП challenge авто
    /* Проверка подлинности ЭЦП */
    bool car_check_rspns = car_check_response(trinket_rspns, trinket_pubKey, car_challenge);
    if (car_check_rspns) {
        std::cout << "OPEN DOOR" << std::endl;
    }
    return 0;
}
