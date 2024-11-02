//
// Created by oleg on 1.11.24.
//
#include "helpFunctions.h"

std::string getClassName(uint16_t qclass) {
    return (qclass == 1) ? "IN" : "UNKNOWN"; // IN - Інтернет, інші класи можна додати
}

std::string getCurrentTimestamp() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

std::string getTypeName(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";        // Адресний запис IPv4
        case 28: return "AAAA";    // Адресний запис IPv6
        case 5: return "CNAME";    // Канонічне ім'я
        case 15: return "MX";      // Поштовий обмін
        case 2: return "NS";       // Сервер доменних імен
        default: return "UNKNOWN"; // Невідомий тип
    }
}

bool isPointer(uint8_t byte) {
    return (byte & 0xC0) == 0xC0;
}