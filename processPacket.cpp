//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//
#include "processPacket.h"

void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, bool verbose) {
    // Obtain the Ethernet header
    auto* eth_header = (struct ether_header*) packet;

    // Check if it is an IPv4 packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Process IPv4
        auto* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_UDP) {
            // Obtain the UDP header
            auto* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Check if the packet is using port 53 (DNS)
            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                // Process DNS query/response
                auto* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
                bool isResponse = ntohs(dns_header->flags) & 0x8000;
                int offset = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct DNSHeader);

                // Parse Question section
                std::vector<DNSQuestion> questions;
                questions.reserve(ntohs(dns_header->qd_count));
                for (int i = 0; i < ntohs(dns_header->qd_count); ++i) {
                    questions.push_back(parseQuestionSection(packet, offset, false));
                }

                // Parse Answer section
                std::vector<DNSRecord> answers;
                answers.reserve(ntohs(dns_header->an_count));
                for (int i = 0; i < ntohs(dns_header->an_count); ++i) {
                    answers.push_back(parseDNSRecord(packet, offset, false));
                }

                // Parse Authority section
                std::vector<DNSRecord> authorities;
                authorities.reserve(ntohs(dns_header->ns_count));
                for (int i = 0; i < ntohs(dns_header->ns_count); ++i) {
                    authorities.push_back(parseDNSRecord(packet, offset, false));
                }

                // Parse Additional section
                std::vector<DNSRecord> additionals;
                additionals.reserve(ntohs(dns_header->ar_count));
                for (int i = 0; i < ntohs(dns_header->ar_count); ++i) {
                    additionals.push_back(parseDNSRecord(packet, offset, false));
                }

                // Display verbose DNS information if verbose mode is on
                if (verbose) {
                    printVerboseDNSInfo(ip_header, udp_header, dns_header, false, pkthdr);
                    if (!questions.empty()) {
                        printQuestionSection(questions);
                    }
                    if (!answers.empty()){
                        printAnswerSection(answers);
                    }
                    if (!authorities.empty()){
                        printAuthoritySection(authorities);
                    }
                    if (!additionals.empty()){
                        printAdditionalSection(additionals);
                    }

                    std::cout << "====================\n";
                } else {
                    // Display basic DNS information
                    printBasicDNSInfo(ip_header, dns_header, isResponse, false, pkthdr);
                }
            }
        }
    }
        // Check if it is an IPv6 packet
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {

        auto* ip6_header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));
        if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            auto* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

            // Check if the packet is using port 53 (DNS)
            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                auto* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
                bool isResponse = ntohs(dns_header->flags) & 0x8000;
                int offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + sizeof(struct DNSHeader);

                // Parse Question section
                std::vector<DNSQuestion> questions;
                questions.reserve(ntohs(dns_header->qd_count));
                for (int i = 0; i < ntohs(dns_header->qd_count); ++i) {
                    questions.push_back(parseQuestionSection(packet, offset, true));
                }

                // Parse Answer section
                std::vector<DNSRecord> answers;
                answers.reserve(ntohs(dns_header->an_count));
                for (int i = 0; i < ntohs(dns_header->an_count); ++i) {
                    answers.push_back(parseDNSRecord(packet, offset, true));
                }

                // Parse Authority section
                std::vector<DNSRecord> authorities;
                authorities.reserve(ntohs(dns_header->ns_count));
                for (int i = 0; i < ntohs(dns_header->ns_count); ++i) {
                    authorities.push_back(parseDNSRecord(packet, offset, true));
                }

                // Parse Additional section
                std::vector<DNSRecord> additionals;
                additionals.reserve(ntohs(dns_header->ar_count));
                for (int i = 0; i < ntohs(dns_header->ar_count); ++i) {
                    additionals.push_back(parseDNSRecord(packet, offset, true));
                }

                // Display verbose DNS information if verbose mode is on
                if (verbose) {
                    printVerboseDNSInfo(ip6_header, udp_header, dns_header, true, pkthdr);
                    if (!questions.empty()) {
                        printQuestionSection(questions);
                    }
                    if (!answers.empty()){
                        printAnswerSection(answers);
                    }
                    if (!authorities.empty()){
                        printAuthoritySection(authorities);
                    }
                    if (!additionals.empty()){
                        printAdditionalSection(additionals);
                    }

                    std::cout << "====================\n";
                } else {
                    // Display basic DNS information
                    printBasicDNSInfo(ip6_header, dns_header, isResponse, true, pkthdr);
                }
            }
        }
    }
}
