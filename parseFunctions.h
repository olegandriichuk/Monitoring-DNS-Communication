//
// Created by oleg on 2.11.24.
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
std::string parseQName(const u_char* packet, int& offset);
void storeDomainTranslation(const std::string& domain, const std::string& ipAddress);
std::string parseQNameForAnswer(const u_char* packet, int& offset, bool isIPv6);

DNSQuestion parseQuestionSection(const u_char* packet, int& offset);
DNSRecord parseDNSRecord(const u_char* packet, int& offset, bool isIPv6);
#endif //ISA_PARSEFUNCTIONS_H
