//
// Created by oleg on 1.11.24.
//
#include "helpFunctions.h"

std::string getClassName(uint16_t qclass) {
    return (qclass == 1) ? "IN" : "UNKNOWN"; // IN - Інтернет, інші класи можна додати
}

std::string getCurrentTimestamp(const struct pcap_pkthdr* pkthdr) {
    time_t time = pkthdr->ts.tv_sec;
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&time);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

std::string getTypeName(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";        // Адресний запис IPv4
        case 28: return "AAAA";    // Адресний запис IPv6
        case 5: return "CNAME";    // Канонічне ім'я
        case 15: return "MX";      // Поштовий обмін
        case 2: return "NS";
        case 6: return "SOA";// Сервер доменних імен
        case 33: return "SRV";
        default: return "UNKNOWN"; // Невідомий тип
    }
}

bool isPointer(uint8_t byte) {
    return (byte & 0xC0) == 0xC0;
}