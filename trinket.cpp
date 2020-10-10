#include <iostream>
#include <string>
#include <iomanip>

#include <openssl/sha.h>
#include "openssl/rand.h"

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

std::string trinket_generate_hasndshake(unsigned long int trinket_pkey) {  //handshake брелка
    std::string trinket_msg = "Open the door";
    std::cout << "1: (handshake) trinket->car: trinket_public_key: " <<
    trinket_pkey << ", trinket_msg: \"" << trinket_msg << "\"" << std::endl;
    return trinket_msg;
}

std::string car_process_challenge(std::string trinket_msg) {  //random challenge авто
    std::string error_msg = "ERROR!";
    if (trinket_msg == "Open the door") {
        unsigned long int rnd_chl = rand()%(90000000)+10000000;
        std::string rnd_chl_str = std::to_string(rnd_chl);
        std::string random_challenge = sha256(rnd_chl_str);
        std::cout << "2: (challenge) car->trinket: challenge_for_trinket: " << random_challenge;
        return random_challenge;
    }
    else {
        return error_msg;
    }
}

std::string trinket_response(std::string car_challenge) {  //ЭЦП брелка
    //return ЭЦП
}

bool car_check_response(std::string trinket_response) {  //проверка ЭЦП
    //если ЭЦП верный - вернуть тру
}

int main(int argc, char* argv[]) {
    srand ( time(NULL) );
    unsigned long int trinket_pkey = 3502941458;
    std::string trinket_msg = trinket_generate_hasndshake(trinket_pkey);  //брелок генерирует запрос авто
    std::string car_challenge = car_process_challenge(trinket_msg);  //авто генерирует challenge брелку
    std::string trinket_rsp = trinket_response(car_challenge);  //брелок выполняет ЭЦП challenge авто
    bool car_check_rsp = car_check_response(trinket_rsp);  //автомобиль проверяет ЭЦП брелка
    return 0;
}
