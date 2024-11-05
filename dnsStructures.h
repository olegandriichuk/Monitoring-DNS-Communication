//
// Created by oleg on 1.11.24.
//

#ifndef ISA_DNSSTRUCTURES_H
#define ISA_DNSSTRUCTURES_H
#include <iostream>
#include <unistd.h>
#include <string>
#include <vector>
struct DNSHeader {
    uint16_t id;       // Ідентифікатор
    uint16_t flags;    // Прапорці
    uint16_t qd_count; // Кількість записів у секції Question
    uint16_t an_count; // Кількість записів у секції Answer
    uint16_t ns_count; // Кількість записів у секції Authority
    uint16_t ar_count; // Кількість записів у секції Additional
};

// Структура для Question Section
struct DNSQuestion {
    std::string qname;   // Доменне ім'я, наприклад, "example.com."
    uint16_t qtype;      // Тип запиту (наприклад, 1 для A-запису)
    uint16_t qclass;     // Клас запиту (зазвичай 1 для IN - Інтернет)
};

struct DNSRecord {
    std::string name;    // Доменне ім'я, до якого належить запис (NAME)
    uint16_t type;       // Тип запису (TYPE), наприклад, A, AAAA, CNAME, NS
    uint16_t dnsClass;   // Клас запису (CLASS), зазвичай IN (1)
    uint32_t ttl;        // Час життя запису в секундах (TTL)
    uint16_t rdLength;   // Довжина даних у полі RDATA (RDLENGTH)
    std::string rdata; // Дані запису (RDATA), формат залежить від типу запису
};
#endif //ISA_DNSSTRUCTURES_H
