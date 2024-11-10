//
// Created by oleg on 8.11.24.
//
#include "processPacket.h"

void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, bool verbose) {
    // Отримання Ethernet-заголовка
    auto* eth_header = (struct ether_header*) packet;

    // Перевірка, чи є це IP або IPv6 пакетом
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Обробка IPv4
        auto* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_UDP) {
            // Отримання UDP-заголовка
            auto* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Перевірка, чи використовується порт 53 (DNS)
            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                // Обробка DNS-запиту/відповіді
                auto* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
                bool isResponse = ntohs(dns_header->flags) & 0x8000;
                int offset = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct DNSHeader);
                std::vector<DNSQuestion> questions;
                questions.reserve(ntohs(dns_header->qd_count));
                for (int i = 0; i < ntohs(dns_header->qd_count); ++i) {
                    questions.push_back(parseQuestionSection(packet, offset, false));
                }
                std::vector<DNSRecord> answers;
                answers.reserve(ntohs(dns_header->an_count));
                for (int i = 0; i < ntohs(dns_header->an_count); ++i) {
                    answers.push_back(parseDNSRecord(packet, offset, false));
                }

                std::vector<DNSRecord> authorities;
                authorities.reserve(ntohs(dns_header->ns_count));
                for (int i = 0; i < ntohs(dns_header->ns_count); ++i) {
                    authorities.push_back(parseDNSRecord(packet, offset, false));
                }

                std::vector<DNSRecord> additionals;
                additionals.reserve(ntohs(dns_header->ar_count));
                for (int i = 0; i < ntohs(dns_header->ar_count); ++i) {
                    additionals.push_back(parseDNSRecord(packet, offset, false));
                }

                if (verbose) {
//                    std::cout << "NUMBER OF PACKET IS " << numberOfPacket << std::endl;
                    printVerboseDNSInfo(ip_header, udp_header, dns_header, false, pkthdr); // Передача pkthdr для часу
                    if (!questions.empty()) {
                        printQuestionSection(questions);
                    }
                    if (!answers.empty()) {
                        printAnswerSection(answers);
                    }
                    if (!authorities.empty()) {
                        printAuthoritySection(authorities);
                    }
                    if (!additionals.empty()) {
                        printAdditionalSection(additionals);
                    }
//                    numberOfPacket++;
                    std::cout << "====================\n";
                } else {
                    printBasicDNSInfo(ip_header, dns_header, isResponse, false , pkthdr);
                }
            }
        }
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        // Обробка IPv6
        auto* ip6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            auto* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                auto* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
                bool isResponse = ntohs(dns_header->flags) & 0x8000;
                int offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader);

                std::vector<DNSQuestion> questions;
                questions.reserve(ntohs(dns_header->qd_count));
                for (int i = 0; i < ntohs(dns_header->qd_count); ++i) {
                    questions.push_back(parseQuestionSection(packet, offset, true));
                }

                std::vector<DNSRecord> answers;
                answers.reserve(ntohs(dns_header->an_count));
                for (int i = 0; i < ntohs(dns_header->an_count); ++i) {
                    answers.push_back(parseDNSRecord(packet, offset, true));
                }

                std::vector<DNSRecord> authorities;
                authorities.reserve(ntohs(dns_header->ns_count));
                for (int i = 0; i < ntohs(dns_header->ns_count); ++i) {
                    authorities.push_back(parseDNSRecord(packet, offset, true));
                }

                std::vector<DNSRecord> additionals;
                additionals.reserve(ntohs(dns_header->ar_count));
                for (int i = 0; i < ntohs(dns_header->ar_count); ++i) {
                    additionals.push_back(parseDNSRecord(packet, offset, true));
                }

                if (verbose) {
//                    std::cout << "NUMBER OF PACKET IS " << numberOfPacket << std::endl;
                    printVerboseDNSInfo(ip6_header, udp_header, dns_header, true, pkthdr); // Передача pkthdr для часу
                    if (!questions.empty()) {
                        printQuestionSection(questions);
                    }
                    if (!answers.empty()) {
                        printAnswerSection(answers);
                    }
                    if (!authorities.empty()) {
                        printAuthoritySection(authorities);
                    }
                    if (!additionals.empty()) {
                        printAdditionalSection(additionals);
                    }
//                    numberOfPacket++;
                    std::cout << "====================\n";
                } else {
                    printBasicDNSInfo(ip6_header, dns_header, isResponse, true, pkthdr);
                }
            }
        }
    }
}