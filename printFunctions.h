//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//

#ifndef ISA_PRINTFUNCTIONS_H
#define ISA_PRINTFUNCTIONS_H
#include "dnsStructures.h"
#include "helpFunctions.h"
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "parseFunctions.h"
/**
 * @brief Prints detailed DNS information including flags and header details for IPv4 and IPv6.
 * @param ip_header Pointer to IP header (IPv4 or IPv6).
 * @param udp_header Pointer to UDP header.
 * @param dns_header Pointer to DNS header.
 * @param isIPv6 Boolean indicating if the IP header is IPv6.
 * @param pkthdr Pointer to pcap packet header for timestamp.
 */
void printVerboseDNSInfo(const void* ip_header, const struct udphdr* udp_header, const DNSHeader* dns_header, bool isIPv6, const struct pcap_pkthdr* pkthdr);

/**
 * @brief Prints the additional section of a DNS packet.
 * @param answers Vector of DNSRecord structures representing additional records.
 */
void printAdditionalSection(const std::vector<DNSRecord>& answers);

/**
 * @brief Prints the answer section of a DNS packet.
 * @param answers Vector of DNSRecord structures representing answer records.
 */
void printAnswerSection(const std::vector<DNSRecord>& answers);

/**
 * @brief Prints the authority section of a DNS packet.
 * @param answers Vector of DNSRecord structures representing authority records.
 */
void printAuthoritySection(const std::vector<DNSRecord>& answers);


/**
 * @brief Helper function to print the contents of a section (answer, authority, or additional).
 * @param answers Vector of DNSRecord structures to be printed.
 */
void printSection(const std::vector<DNSRecord>& answers);

/**
 * @brief Prints the question section of a DNS query.
 * @param questions Vector of DNSQuestion structures to be printed.
 */
void printQuestionSection(const  std::vector<DNSQuestion>& questions);

/**
 * @brief Prints basic DNS information including timestamp and address details.
 * @param ip_header Pointer to IP header (IPv4 or IPv6).
 * @param dns_header Pointer to DNS header.
 * @param isResponse Boolean indicating if the DNS packet is a response.
 * @param isIPv6 Boolean indicating if the IP header is IPv6.
 * @param pkthdr Pointer to pcap packet header for timestamp.
 */
void printBasicDNSInfo(const void* ip_header, const DNSHeader* dns_header, bool isResponse, bool isIPv6, const struct pcap_pkthdr* pkthdr);
#endif //ISA_PRINTFUNCTIONS_H
