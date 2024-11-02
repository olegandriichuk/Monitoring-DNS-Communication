#include <iostream>
#include <unistd.h>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>       // Для IP-заголовків
#include <netinet/udp.h>      // Для UDP-заголовків
#include <netinet/if_ether.h> // Для Ethernet-заголовків
#include <arpa/inet.h>        // Для перетворення IP-адрес
#include "printFunctions.h"
#include "parseFunctions.h"
int numberOfPacket = 1;
// Функція для розбору QNAME
//std::string parseQName(const u_char* packet, int& offset) {
//    std::string qname;
//    while (packet[offset] != 0) {
//        int len = packet[offset];
//        offset++;
//        qname.append((const char*)&packet[offset], len);
//        offset += len;
//        if (packet[offset] != 0) {
//            qname.append(".");
//        }
//    }
//    offset++; // Пропустити нульовий байт
////    std::cout << "Qname in  answer: " << qname << std::endl;
//    return qname;
//}
//
//
//// Приклад використання у вашій функції розбору
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
//        }
//    }
//
////    offset++; // Пропустити нульовий байт
//    return qname;
//}
//
//// Функція для розбору Question Section
//DNSQuestion parseQuestionSection(const u_char* packet, int& offset) {
//    DNSQuestion question;
//    question.qname = parseQName(packet, offset);
//    question.qtype = ntohs(*(uint16_t*)&packet[offset]);
//    offset += 2;
//    question.qclass = ntohs(*(uint16_t*)&packet[offset]);
//    offset += 2;
//    return question;
//}
//// Функція для розбору DNS-запису
//
//DNSRecord parseDNSRecord(const u_char* packet, int& offset) {
//    DNSRecord record;
//    record.name = parseQNameForAnswer(packet, offset); // Читання доменного імені
////    std::cout << record.name << "   ________\n";
//    record.type = ntohs(*(uint16_t*)&packet[offset]);
//    offset += 2;
//
//    record.dnsClass = ntohs(*(uint16_t*)&packet[offset]);
//    offset += 2;
//
//    record.ttl = ntohl(*(uint32_t*)&packet[offset]);
//    offset += 4;
//
//    record.rdLength = ntohs(*(uint16_t*)&packet[offset]);
//    offset += 2;
//
//    // Читання RDATA
//    record.rdata.assign(packet + offset, packet + offset + record.rdLength);
//    offset += record.rdLength;
//
//    return record;
//}

void processPacket(const u_char* packet, bool verbose) {
    // Отримання Ethernet-заголовка
    struct ether_header* eth_header = (struct ether_header*) packet;

    // Перевірка, чи є це IP-пакетом
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Отримання IP-заголовка
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Визначення протоколу (UDP)
        if (ip_header->ip_p == IPPROTO_UDP) {
            // Отримання UDP-заголовка
            struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Перевірка, чи використовується порт 53 (DNS)
            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                // Отримання DNS-заголовка
                DNSHeader* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

                // Визначення, чи це запит чи відповідь (QR-біт)
                bool isResponse = ntohs(dns_header->flags) & 0x8000;

                // Розбір Question Section
                int offset = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct DNSHeader);

                DNSQuestion question = parseQuestionSection(packet, offset);
                std::vector<DNSRecord> answers;
                for (int i = 0; i < ntohs(dns_header->an_count); ++i) {
                    answers.push_back(parseDNSRecord(packet, offset));
                }

                if (verbose) {
                    std::cout << "NUMBER OF PACKET IS " << numberOfPacket << std::endl;
                    printVerboseDNSInfo(ip_header, udp_header, dns_header);
                    printQuestionSection(question);
                    if(dns_header->an_count >0)
                    printAnswerSection(answers); // Виведення всіх відповідей
                    numberOfPacket++;
                    std::cout << "====================\n";
                } else {
                    printBasicDNSInfo(ip_header, dns_header, isResponse);
                }
            }
        }
    }
}

// Основна функція
int main(int argc, char* argv[]) {
    // Змінні для зберігання значень аргументів
    std::string interface;
    std::string pcapfile;
    bool verbose = false;

    int option;
    // Парсинг аргументів за допомогою getopt
    while ((option = getopt(argc, argv, "i:p:v")) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                pcapfile = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                std::cerr << "Unknown option: " << option << "\n";
                return 1;
        }
    }

    // Перевірка, чи заданий хоча б один із параметрів -i або -p
    if (interface.empty() && pcapfile.empty()) {
        std::cerr << "Please provide either -i <interface> or -p <pcapfile>\n";
        return 1;
    }

    // Відкриття інтерфейсу або файлу PCAP для захоплення
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (!interface.empty()) {
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Couldn't open device: " << errbuf << "\n";
            return 1;
        }
    } else {
        handle = pcap_open_offline(pcapfile.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << "Couldn't open file: " << errbuf << "\n";
            return 1;
        }
    }

    // Захоплення пакетів та обробка
    pcap_loop(handle, 0, [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
        processPacket(packet, *(bool*)args);
    }, (u_char*)&verbose);

    pcap_close(handle);
    return 0;
}
