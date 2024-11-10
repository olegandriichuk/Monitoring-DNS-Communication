//
// Created by oleg on 2.11.24.
//

#include "parseFunctions.h"
//std::vector<std::string> domainNames;
//std::vector<std::string> domainTranslations;
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
//    if (qname.empty() || qname.back() != '.') {
//        qname.append(".");
//    }
    offset++; // Пропустити нульовий байт
//    std::cout << "Qname in  record: " << qname << std::endl;
    return qname;
}

void storeDomainTranslation(const std::string& domain, const std::string& ipAddress) {
    std::string entry = domain + " " + ipAddress;

    // Перевіряємо, чи запис вже є у векторі
    if (std::find(domainTranslations.begin(), domainTranslations.end(), entry) == domainTranslations.end()) {
        domainTranslations.push_back(entry); // Додаємо тільки унікальні записи
    }
}



std::string parseQNameForAnswer(const u_char* packet, int& offset, bool isIPv6) {
    std::string qname;
    int originalOffset = 0;  // Зберігаємо початкове зміщення
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
                jumped = true;
                originalOffset = offset + 2;  // Зберігаємо зміщення для продовження після стрибка
            }
            // Отримуємо нове зміщення з вказівника
            offset = ((label_length & 0x3F) << 8) | packet[offset + 1];
            if(isIPv6){
                offset += static_cast<int>(sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
            } else{
                offset += static_cast<int>(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            }

            continue;
        } else {
            // Це звичайна мітка, обробляємо її
            offset++;
            qname.append(reinterpret_cast<const char*>(&packet[offset]), label_length);
            offset += label_length;
            qname.append(".");
        }
    }


    if (!qname.empty() && qname.back() == '.') {
        qname.pop_back();
    }

    // Відновлюємо зміщення, якщо був стрибок
    if (jumped) {
        offset = originalOffset;
    }
//    std::cout << "Parsed QName: " << qname << std::endl;
    return qname;
}


// Функція для розбору Question Section

// Функція для розбору DNS-запису

DNSRecord parseDNSRecord(const u_char* packet, int& offset, bool isIPv6) {
    DNSRecord record;
    record.name = parseQNameForAnswer(packet, offset, isIPv6); // Читання доменного імені
//    std::cout << "Parsed Name for A Record: " << record.name << std::endl;
    record.type = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
//    std::cout <<"Record type" << record.type << std::endl;
    record.dnsClass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    record.ttl = ntohl(*(uint32_t*)&packet[offset]);
    offset += 4;

    record.rdLength = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    if(record.type == 1 || record.type == 28 || record.type == 2 || record.type == 5 || record.type == 6 || record.type == 15 || record.type == 33){
        if (std::find(domainNames.begin(), domainNames.end(), record.name) == domainNames.end()) {
            domainNames.push_back(record.name);
        }
    }
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
        storeDomainTranslation(record.name, record.rdata);
    }
//    std::cout << "Record Name: " << record.name << ", Type: " << record.type << std::endl;

    // Обробка записів типу NS
     if (record.type == 2) {
        record.rdata = parseQNameForAnswer(packet, offset, isIPv6);
        if (std::find(domainNames.begin(), domainNames.end(), record.rdata) == domainNames.end()) {
            domainNames.push_back(record.rdata);
        }
    }
        // Обробка записів типу CNAME
    if (record.type == 5) {
        record.rdata = parseQNameForAnswer(packet, offset, isIPv6);
        if (std::find(domainNames.begin(), domainNames.end(), record.rdata) == domainNames.end()) {
            domainNames.push_back(record.rdata);
        }
    }
    // parsing MX Type
    if (record.type == 15) { // MX record
        if (record.rdLength >= 2) { // Ensure there's enough data for priority
            uint16_t priority = ntohs(*(uint16_t*)&packet[offset]);
            offset += 2;

            // Parse the domain name associated with this MX record
            std::string exchange = parseQNameForAnswer(packet, offset, isIPv6);
            if (std::find(domainNames.begin(), domainNames.end(), exchange) == domainNames.end()) {
                domainNames.push_back(exchange);
            }
            // Store the result as "priority exchange" (for example, "10 mail.example.com")
            std::stringstream ss;
            ss << priority << " " << exchange << ".";
            record.rdata = ss.str();
        } else {
            // Skip invalid MX record
            offset += record.rdLength;
        }
    }
        // Обробка записів типу SOA
    if (record.type == 6) {
//        std::cout << "============================= TYPE SOA ================================\n";
        std::stringstream ss;

        // Основний сервер і пошта відповідального
        std::string primaryNS = parseQNameForAnswer(packet, offset, isIPv6);
        if (std::find(domainNames.begin(), domainNames.end(), primaryNS) == domainNames.end()) {
            domainNames.push_back(primaryNS);
        }
        ss << primaryNS << ". ";

        std::string respAuthorityMailbox = parseQNameForAnswer(packet, offset, isIPv6);
//        if (std::find(domainNames.begin(), domainNames.end(), respAuthorityMailbox) == domainNames.end()) {
//            domainNames.push_back(respAuthorityMailbox);
//        }
        ss << respAuthorityMailbox << ". ";

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
            storeDomainTranslation(record.name, record.rdata);
        }
    }
    if (record.type == 33) {  // SRV record
        uint16_t priority = ntohs(*(uint16_t*)&packet[offset]);
        offset += 2;
        uint16_t weight = ntohs(*(uint16_t*)&packet[offset]);
        offset += 2;
        uint16_t port = ntohs(*(uint16_t*)&packet[offset]);
        offset += 2;

        std::string target = parseQNameForAnswer(packet, offset, isIPv6);  // SRV target name with trailing dot
        if (std::find(domainNames.begin(), domainNames.end(), target) == domainNames.end()) {
            domainNames.push_back(target);
        }
        std::stringstream ss;
        ss << priority << " " << weight << " " << port << " " << target << ".";
        record.rdata = ss.str();
    }

    return record;
}


DNSQuestion parseQuestionSection(const u_char* packet, int& offset, bool isIPv6) {
    DNSQuestion question;
    question.qname = parseQNameForAnswer(packet, offset, isIPv6);

    question.qtype = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    question.qclass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    if(question.qtype == 1 || question.qtype == 28 || question.qtype == 2 || question.qtype == 5 || question.qtype == 6 || question.qtype == 15 || question.qtype == 33){
        if (std::find(domainNames.begin(), domainNames.end(), question.qname) == domainNames.end()) {
            domainNames.push_back(question.qname);
        }
    }
    return question;
}