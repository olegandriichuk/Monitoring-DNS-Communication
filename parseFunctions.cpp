//
// Created by oleg on 2.11.24.
//

#include "parseFunctions.h"
std::string parseQName(const u_char* packet, int& offset) {
    std::string qname;
    while (packet[offset] != 0) {
        int len = packet[offset];
        offset++;
        qname.append((const char*)&packet[offset], len);
        offset += len;
        if (packet[offset] != 0) {
            qname.append(".");
        }
    }
    offset++; // Пропустити нульовий байт
//    std::cout << "Qname in  answer: " << qname << std::endl;
    return qname;
}


// Приклад використання у вашій функції розбору
std::string parseQNameForAnswer(const u_char* packet, int& offset) {
    std::string qname;
//    std::cout << "Answeroffset : " << offset << std::endl;
    while (packet[offset] != 0) {
        uint8_t label_length = packet[offset];


        // Перевірка, чи є перші два біти на `11` (тобто це вказівник)
        if (isPointer(label_length)) {
//            std::cout << "Has c0" << std::endl;
            // Зчитування зсуву з вказівника
            int pointer_offset = static_cast<int>(((label_length & 0x3F) << 8) | packet[offset + 1]);
            pointer_offset += static_cast<int>(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
//            std::cout << "Answer offset for qname : " << pointer_offset << std::endl;
            offset += 2; // Пропускаємо байти вказівника
//
//            // Рекурсивно розбираємо вказівник
            qname += parseQName(packet, pointer_offset );
            break;
        } else {
            // Якщо це не вказівник, зчитуємо як звичайну мітку
            offset++;
            qname.append((const char*)&packet[offset], label_length);
            offset += label_length;

            if (packet[offset] != 0) {
                qname.append(".");
            }
        }
    }

//    offset++; // Пропустити нульовий байт
    return qname;
}

// Функція для розбору Question Section
DNSQuestion parseQuestionSection(const u_char* packet, int& offset) {
    DNSQuestion question;
    question.qname = parseQName(packet, offset);
    question.qtype = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    question.qclass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    return question;
}
// Функція для розбору DNS-запису

DNSRecord parseDNSRecord(const u_char* packet, int& offset) {
    DNSRecord record;
    record.name = parseQNameForAnswer(packet, offset); // Читання доменного імені
//    std::cout << record.name << "   ________\n";
    record.type = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    record.dnsClass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    record.ttl = ntohl(*(uint32_t*)&packet[offset]);
    offset += 4;

    record.rdLength = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    // Читання RDATA
    record.rdata.assign(packet + offset, packet + offset + record.rdLength);
    offset += record.rdLength;

    return record;
}