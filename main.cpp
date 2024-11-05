#include <iostream>
#include <unistd.h>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>       // Для IP-заголовків
#include <netinet/ip6.h>      // Для IP-заголовків IPv6
#include <netinet/udp.h>      // Для UDP-заголовків
#include <netinet/if_ether.h> // Для Ethernet-заголовків
#include <arpa/inet.h>        // Для перетворення IP-адрес
#include "printFunctions.h"
#include "parseFunctions.h"

int numberOfPacket = 1;

void processPacket(const u_char* packet, bool verbose) {
    // Отримання Ethernet-заголовка
    struct ether_header* eth_header = (struct ether_header*) packet;

    // Перевірка, чи є це IP або IPv6 пакетом
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Обробка IPv4
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_UDP) {
            // Отримання UDP-заголовка
            struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Перевірка, чи використовується порт 53 (DNS)
            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                // Обробка DNS-запиту/відповіді
                DNSHeader* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
                bool isResponse = ntohs(dns_header->flags) & 0x8000;
                int offset = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct DNSHeader);
                DNSQuestion question;
                if(dns_header->qd_count > 0)
                question = parseQuestionSection(packet, offset);
                std::vector<DNSRecord> answers;
                answers.reserve(ntohs(dns_header->an_count));
                for (int i = 0; i < ntohs(dns_header->an_count); ++i) {
                    // Parse the DNS record
                    answers.push_back(parseDNSRecord(packet, offset));
                }

                std::vector<DNSRecord> authorities;
                authorities.reserve(ntohs(dns_header->ns_count));
                for (int i = 0; i < ntohs(dns_header->ns_count); ++i) {
                    authorities.push_back(parseDNSRecord(packet, offset));
                }
                std::vector<DNSRecord> additionals;
                additionals.reserve(ntohs(dns_header->ar_count));
                for (int i = 0; i < ntohs(dns_header->ar_count); ++i) {
                    additionals.push_back(parseDNSRecord(packet, offset));
                }
                if (verbose) {
                    std::cout << "NUMBER OF PACKET IS " << numberOfPacket << std::endl;
                    printVerboseDNSInfo(ip_header, udp_header, dns_header, false);
                    printQuestionSection(question);
//                    std::cout << "ANSWERS SIZE: " << answers.size() << std::endl
//                              << "AUTHORITIES SIZE: " << authorities.size() << std::endl
//                              << "ADDITIONALS SIZE: " << additionals.size() << std::endl;
                    if (!answers.empty()) {
                        printAnswerSection(answers);
                    }
                    if (!authorities.empty()) {
                        printAuthoritySection(authorities);
                    }
                    if (!additionals.empty()) {
                        printAdditionalSection(additionals);
                    }
                    numberOfPacket++;
                    std::cout << "====================\n";
                } else {
                    printBasicDNSInfo(ip_header, dns_header, isResponse, false);
                }
            }
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        // Обробка IPv6
        auto* ip6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            // Отримання UDP-заголовка
            struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

            // Перевірка, чи використовується порт 53 (DNS)
            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                // Обробка DNS-запиту/відповіді
                auto* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
                bool isResponse = ntohs(dns_header->flags) & 0x8000;
                int offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader);
                DNSQuestion question;
                if(dns_header->qd_count > 0)
                    question = parseQuestionSection(packet, offset);
                std::vector<DNSRecord> answers;
                answers.reserve(ntohs(dns_header->an_count));
                for (int i = 0; i < ntohs(dns_header->an_count); ++i) {
                    // Parse the DNS record
                    answers.push_back(parseDNSRecord(packet, offset));
                }

                std::vector<DNSRecord> authorities;
                authorities.reserve(ntohs(dns_header->ns_count));
                for (int i = 0; i < ntohs(dns_header->ns_count); ++i) {
                    authorities.push_back(parseDNSRecord(packet, offset));
                }
                std::vector<DNSRecord> additionals;
                additionals.reserve(ntohs(dns_header->ar_count));
                for (int i = 0; i < ntohs(dns_header->ar_count); ++i) {
                    additionals.push_back(parseDNSRecord(packet, offset));
                }
                if (verbose) {
                    std::cout << "NUMBER OF PACKET IS " << numberOfPacket << std::endl;
                    printVerboseDNSInfo(ip6_header, udp_header, dns_header, true);
                    printQuestionSection(question);
//                    std::cout << "ANSWERS SIZE: " << answers.size() << std::endl
//                              << "AUTHORITIES SIZE: " << authorities.size() << std::endl
//                              << "ADDITIONALS SIZE: " << additionals.size() << std::endl;
                    if (!answers.empty()) {
                        printAnswerSection(answers);
                    }
                    if (!authorities.empty()) {
                        printAuthoritySection(authorities);
                    }
                    if (!additionals.empty()) {
                        printAdditionalSection(additionals);
                    }
                    numberOfPacket++;
                    std::cout << "====================\n";
                }  else {
                    printBasicDNSInfo(ip6_header, dns_header, isResponse, true); // Pass 'true' for IPv6
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    std::string interface;
    std::string pcapfile;
    bool verbose = false;

    int option;
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

    if (interface.empty() && pcapfile.empty()) {
        std::cerr << "Please provide either -i <interface> or -p <pcapfile>\n";
        return 1;
    }

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

    pcap_loop(handle, 0, [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
        processPacket(packet, *(bool*)args);
    }, (u_char*)&verbose);

    pcap_close(handle);
    return 0;
}
