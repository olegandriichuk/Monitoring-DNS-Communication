//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//

#ifndef ISA_PARSEFUNCTIONS_H
#define ISA_PARSEFUNCTIONS_H
#include "dnsStructures.h"
#include "helpFunctions.h"
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <pcap.h>             // For pcap-related functions
#include <netinet/if_ether.h> // For struct ether_header
#include <netinet/ip.h>       // For struct ip
#include <netinet/udp.h>
#include <netinet/ip6.h>
extern std::vector<std::string> domainNames;
extern std::vector<std::string> domainTranslations;

/**
 * @brief Stores a domain and its IP address translation if unique.
 * @param domain The domain name.
 * @param ipAddress The associated IP address.
 */
void storeDomainTranslation(const std::string& domain, const std::string& ipAddress);

/**
 * @brief Parses the QName in the answer section of a DNS packet.
 * @param packet The raw packet data.
 * @param offset The current offset in the packet (updated within function).
 * @param isIPv6 Whether the packet is IPv6.
 * @return The parsed QName as a string.
 */
std::string parseQNameForAnswer(const u_char* packet, int& offset, bool isIPv6);

/**
 * @brief Parses the Question section of a DNS packet.
 * @param packet The raw packet data.
 * @param offset The current offset in the packet (updated within function).
 * @param isIPv6 Whether the packet is IPv6.
 * @return The parsed DNSQuestion structure.
 */
DNSQuestion parseQuestionSection(const u_char* packet, int& offset, bool isIPv6);

/**
 * @brief Parses a DNS record in the packet.
 * @param packet The raw packet data.
 * @param offset The current offset in the packet (updated within function).
 * @param isIPv6 Whether the packet is IPv6.
 * @return The parsed DNSRecord structure.
 */
DNSRecord parseDNSRecord(const u_char* packet, int& offset, bool isIPv6);
#endif //ISA_PARSEFUNCTIONS_H
