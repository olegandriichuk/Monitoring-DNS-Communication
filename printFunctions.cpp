//
// Created by oleg on 1.11.24.
//

#include "printFunctions.h"


void printQuestionSection(const DNSQuestion& question) {
    std::cout << "[Question Section]\n"
              << " " << question.qname << " "
              << getClassName(question.qclass) << " "
              << getTypeName(question.qtype) << "\n";
}

void printVerboseDNSInfo(const struct ip* ip_header, const struct udphdr* udp_header, const DNSHeader* dns_header) {
    std::string timestamp = getCurrentTimestamp();
    uint16_t identifier = ntohs(dns_header->id);
    uint16_t flags = ntohs(dns_header->flags);

    // Розбір прапорців
    bool qr = flags & 0x8000;
    uint8_t opcode = (flags >> 11) & 0x0F;
    bool aa = flags & 0x0400;
    bool tc = flags & 0x0200;
    bool rd = flags & 0x0100;
    bool ra = flags & 0x0080;
    bool ad = flags & 0x0020;
    bool cd = flags & 0x0010;
    uint8_t rcode = flags & 0x000F;

    // Вивід детальної інформації
    std::cout << "Timestamp: " << timestamp << "\n"
              << "SrcIP: " << inet_ntoa(ip_header->ip_src) << "\n"
              << "DstIP: " << inet_ntoa(ip_header->ip_dst) << "\n"
              << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << "\n"
              << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << "\n"
              << "Identifier: 0x" << std::hex << identifier << std::dec << "\n"
              << "Flags: QR=" << qr
              << ", OPCODE=" << (int)opcode
              << ", AA=" << aa
              << ", TC=" << tc
              << ", RD=" << rd
              << ", RA=" << ra
              << ", AD=" << ad
              << ", CD=" << cd
              << ", RCODE=" << (int)rcode << "\n";

}

void printBasicDNSInfo(const struct ip* ip_header, const DNSHeader* dns_header, bool isResponse) {
    uint16_t qd_count = ntohs(dns_header->qd_count);
    uint16_t an_count = ntohs(dns_header->an_count);
    uint16_t ns_count = ntohs(dns_header->ns_count);
    uint16_t ar_count = ntohs(dns_header->ar_count);
    std::cout << an_count <<   "rrrr" << std::endl;
    std::string timestamp = getCurrentTimestamp();
    std::cout
//              << timestamp << " "
            << inet_ntoa(ip_header->ip_src) << " -> "
            << inet_ntoa(ip_header->ip_dst) << " ("
            << (isResponse ? "R" : "Q") << " "
            << qd_count << "/"
            << an_count << "/"
            << ns_count << "/"
            << ar_count << ")\n";
    std::cout << "----------------------------------------\n";
}

// Функція для виводу даних Answer Section
void printAnswerSection(const std::vector<DNSRecord>& answers) {
    std::cout << "[Answer Section]\n";
    for (const auto& record : answers) {
        std::cout << " " << record.name << " " << record.ttl << " "
                  << getClassName(record.dnsClass) << " "
                  << getTypeName(record.type) << " ";

        // Вивід RDATA в залежності від типу запису
        if (record.type == 1) { // A-запис
            std::cout << inet_ntoa(*(in_addr*)record.rdata.data());
        } else if (record.type == 28) { // AAAA-запис
            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, record.rdata.data(), ipv6, sizeof(ipv6));
            std::cout << ipv6;
        } else if (record.type == 2) { // NS-запис
            // Обробка доменного імені у полі RDATA
            int offset = 0;
            std::string nsName = parseQName(record.rdata.data(), offset);
            std::cout << nsName;
        } else if (record.type == 5) { // CNAME-запис
            // Обробка канонічного імені у полі RDATA
            int offset = 0;
            std::string cname = parseQName(record.rdata.data(), offset);
            std::cout << cname;
        } else if (record.type == 15) { // MX-запис
            // Обробка пріоритету і доменного імені для MX-запису
            uint16_t preference = ntohs(*(uint16_t*)record.rdata.data());
            int offset = 2;
            std::string exchange = parseQName(record.rdata.data() + offset, offset);
            std::cout << preference << " " << exchange;
        } else if (record.type == 6) { // SOA-запис
            // Обробка полів для SOA-запису
            int offset = 0;
            std::string mname = parseQName(record.rdata.data(), offset);
            std::string rname = parseQName(record.rdata.data() + offset, offset);
            uint32_t serial = ntohl(*(uint32_t*)(record.rdata.data() + offset));
            offset += 4;
            uint32_t refresh = ntohl(*(uint32_t*)(record.rdata.data() + offset));
            offset += 4;
            uint32_t retry = ntohl(*(uint32_t*)(record.rdata.data() + offset));
            offset += 4;
            uint32_t expire = ntohl(*(uint32_t*)(record.rdata.data() + offset));
            offset += 4;
            uint32_t minimum = ntohl(*(uint32_t*)(record.rdata.data() + offset));
            std::cout << mname << " " << rname << " " << serial << " "
                      << refresh << " " << retry << " " << expire << " " << minimum;
        } else if (record.type == 33) { // SRV-запис
            // Обробка пріоритету, ваги, порту і цільового імені для SRV-запису
            uint16_t priority = ntohs(*(uint16_t*)record.rdata.data());
            uint16_t weight = ntohs(*(uint16_t*)(record.rdata.data() + 2));
            uint16_t port = ntohs(*(uint16_t*)(record.rdata.data() + 4));
            int offset = 6;
            std::string target = parseQName(record.rdata.data() + offset, offset);
            std::cout << priority << " " << weight << " " << port << " " << target;
        } else {
            std::cout << "<не підтримується>";
        }
        std::cout << "\n";
    }
}
