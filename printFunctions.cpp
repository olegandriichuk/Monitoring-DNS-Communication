#include "printFunctions.h"
#include <netinet/ip6.h> // Для заголовків IPv6

void printQuestionSection(const DNSQuestion& question) {
    std::cout << "[Question Section]\n"
              << question.qname << " "
              << getClassName(question.qclass) << " "
              << getTypeName(question.qtype) << "\n";
}

// Оновлена функція для друку детальної інформації про DNS для IPv4 і IPv6
void printVerboseDNSInfo(const void* ip_header, const struct udphdr* udp_header, const DNSHeader* dns_header, bool isIPv6) {
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
    std::cout << "Timestamp: " << timestamp << "\n";

    // Друк адрес в залежності від того, IPv4 чи IPv6
    if (isIPv6) {
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(((struct ip6_hdr*)ip_header)->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(((struct ip6_hdr*)ip_header)->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        std::cout << "SrcIP: " << src_ip << "\n"
                  << "DstIP: " << dst_ip << "\n";
    } else {
        std::cout << "SrcIP: " << inet_ntoa(((struct ip*)ip_header)->ip_src) << "\n"
                  << "DstIP: " << inet_ntoa(((struct ip*)ip_header)->ip_dst) << "\n";
    }

    std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << "\n"
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

void printBasicDNSInfo(const void* ip_header, const DNSHeader* dns_header, bool isResponse, bool isIPv6) {
    uint16_t qd_count = ntohs(dns_header->qd_count);
    uint16_t an_count = ntohs(dns_header->an_count);
    uint16_t ns_count = ntohs(dns_header->ns_count);
    uint16_t ar_count = ntohs(dns_header->ar_count);
    std::string timestamp = getCurrentTimestamp();

    std::cout << timestamp << " ";

    if (isIPv6) {
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(((struct ip6_hdr*)ip_header)->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(((struct ip6_hdr*)ip_header)->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        std::cout << src_ip << " -> " << dst_ip;
    } else {
        std::cout << inet_ntoa(((struct ip*)ip_header)->ip_src) << " -> "
                  << inet_ntoa(((struct ip*)ip_header)->ip_dst);
    }

    std::cout << " (" << (isResponse ? "R" : "Q") << " "
              << qd_count << "/"
              << an_count << "/"
              << ns_count << "/"
              << ar_count << ")\n";
    std::cout << "----------------------------------------\n";
}
void printAdditionalSection(const std::vector<DNSRecord>& answers){
    std::cout << "[Additional  Section]\n";
    printSection(answers);
}

void printAnswerSection(const std::vector<DNSRecord>& answers){
    std::cout << "[Answer  Section]\n";
    printSection(answers);
}

void printAuthoritySection(const std::vector<DNSRecord>& answers){
    std::cout << "[Authority  Section]\n";
    printSection(answers);
}
// Функція для виводу даних Answer Section
void printSection(const std::vector<DNSRecord>& answers) {
//    std::cout << "[Answer Section]\n";
    for (const auto& record : answers) {
        std::cout << record.name << " " << record.ttl << " "
                  << getClassName(record.dnsClass) << " "
                  << getTypeName(record.type) << " ";

        // Вивід RDATA в залежності від типу запису
        if (record.type == 1 || record.type == 28 || record.type == 2 || record.type == 5 || record.type == 6) {
            std::cout << record.rdata;
        }
        else {
            std::cout << "NOT SUPPORTED";
        }
        std::cout << "\n";
    }
}
