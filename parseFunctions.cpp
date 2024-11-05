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
//    std::cout << "Qname in  record: " << qname << std::endl;
    return qname;
}


// Приклад використання у вашій функції розбору
//std::string parseQNameForAnswer(const u_char* packet, int& offset) {
//    std::string qname;
////    std::cout << "Answeroffset : " << offset << std::endl;
//    while (packet[offset] != 0) {
//        uint8_t label_length = packet[offset];
//
//
//        // Перевірка, чи є перші два біти на `11` (тобто це вказівник)
//        if (isPointer(label_length)) {
////            std::cout << "Has c0" << std::endl;
//            // Зчитування зсуву з вказівника
//            int pointer_offset = static_cast<int>(((label_length & 0x3F) << 8) | packet[offset + 1]);
//            pointer_offset += static_cast<int>(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
////            std::cout << "Answer offset for qname : " << pointer_offset << std::endl;
//            offset += 2; // Пропускаємо байти вказівника
////
////            // Рекурсивно розбираємо вказівник
//            qname += parseQName(packet, pointer_offset );
//            break;
//        } else {
//            // Якщо це не вказівник, зчитуємо як звичайну мітку
//            offset++;
//            qname.append((const char*)&packet[offset], label_length);
//            offset += label_length;
//
//            if (packet[offset] != 0) {
//                qname.append(".");
//            }
////            offset++;
//        }
//    }
//
////    offset++; // Пропустити нульовий байт
//    return qname;
//}

std::string parseQNameForAnswer(const u_char* packet, int& offset) {
    std::string qname;
    int originalOffset = offset;  // Зберігаємо початкове зміщення
    bool jumped = false;          // Відстежуємо, чи використовували вказівник
    int safetyCounter = 0;        // Лічильник безпеки для запобігання нескінченному циклу

    while (true) {
        if (safetyCounter++ > 100) {
            throw std::runtime_error("Помилка: можливий некоректний пакет або нескінченний цикл");
        }

        uint8_t label_length = packet[offset];

        // Якщо довжина мітки дорівнює нулю, це кінець імені
        if (label_length == 0) {
            if (!jumped) offset++;  // Збільшуємо зміщення, тільки якщо не було стрибка
            break;
        }

        // Перевірка, чи це вказівник (два старші біти повинні бути 11)
        if ((label_length & 0xC0) == 0xC0) {
            if (!jumped) {
                originalOffset = offset + 2;  // Зберігаємо зміщення для продовження після стрибка
            }
            // Отримуємо нове зміщення з вказівника
            offset = ((label_length & 0x3F) << 8) | packet[offset + 1];
            offset += static_cast<int>(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            jumped = true;
        } else {
            // Це звичайна мітка, обробляємо її
            offset++;
            qname.append(reinterpret_cast<const char*>(&packet[offset]), label_length);
            offset += label_length;
            qname.append(".");
        }
    }

    // Видаляємо останню крапку, якщо вона є
    if (!qname.empty() && qname.back() == '.') {
        qname.pop_back();
    }

    // Відновлюємо зміщення, якщо був стрибок
    if (jumped) {
        offset = originalOffset;
    }

    return qname;
}


// Функція для розбору Question Section

// Функція для розбору DNS-запису

DNSRecord parseDNSRecord(const u_char* packet, int& offset) {
    DNSRecord record;
    record.name = parseQNameForAnswer(packet, offset); // Читання доменного імені

    record.type = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
//    std::cout <<"Record type" << record.type << std::endl;
    record.dnsClass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    record.ttl = ntohl(*(uint32_t*)&packet[offset]);
    offset += 4;

    record.rdLength = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    if(record.type != 1 && record.type != 28 && record.type != 2 && record.type != 5 && record.type != 6 && record.type != 15 && record.type != 33){
        offset+=record.rdLength;
        return record;
    }
    // Обробка записів типу A (IPv4-адреса)
    if (record.type == 1) {
        if (record.rdLength == 4) {
            record.rdata = std::to_string(static_cast<unsigned char>(packet[offset])) + "." +
                           std::to_string(static_cast<unsigned char>(packet[offset + 1])) + "." +
                           std::to_string(static_cast<unsigned char>(packet[offset + 2])) + "." +
                           std::to_string(static_cast<unsigned char>(packet[offset + 3]));
            offset += 4;
        }
    }
        // Обробка записів типу NS
    if (record.type == 2) {
        record.rdata = parseQNameForAnswer(packet, offset);
    }
        // Обробка записів типу CNAME
    if (record.type == 5) {
        record.rdata = parseQNameForAnswer(packet, offset);
    }
        // Обробка записів типу SOA
    if (record.type == 6) {
//        std::cout << "============================= TYPE SOA ================================\n";
        std::stringstream ss;

        // Основний сервер і пошта відповідального
        std::string primaryNS = parseQNameForAnswer(packet, offset);
        ss << primaryNS << " ";

        std::string respAuthorityMailbox = parseQNameForAnswer(packet, offset);
        ss << respAuthorityMailbox << " ";

        // Обробка полів з фіксованою довжиною: серійний номер, оновлення, повторна спроба, закінчення терміну, мінімальний TTL
        uint32_t serial, refresh, retry, expire, minimum;
        memcpy(&serial, &packet[offset], 4);
        serial = ntohl(serial);
        offset += 4;

        memcpy(&refresh, &packet[offset], 4);
        refresh = ntohl(refresh);
        offset += 4;

        memcpy(&retry, &packet[offset], 4);
        retry = ntohl(retry);
        offset += 4;

        memcpy(&expire, &packet[offset], 4);
        expire = ntohl(expire);
        offset += 4;

        memcpy(&minimum, &packet[offset], 4);
        minimum = ntohl(minimum);
        offset += 4;

        // Додати значення до stringstream
        ss << serial << " " << refresh << " " << retry << " " << expire << " " << minimum;

        // Встановити rdata як вміст stringstream
        record.rdata = ss.str();
    }
    if (record.type == 28) {
//        std::cout << "AAAAAAAAAAAAAAAAAAAA\n" ;
        if (record.rdLength == 16) { // IPv6-адреса має довжину 16 байтів
            char ipv6Address[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &packet[offset], ipv6Address, INET6_ADDRSTRLEN);
            record.rdata = std::string(ipv6Address);
            offset += 16;
        }
    }

    return record;
}


DNSQuestion parseQuestionSection(const u_char* packet, int& offset) {
    DNSQuestion question;
    question.qname = parseQName(packet, offset);
    question.qtype = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    question.qclass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    return question;
}