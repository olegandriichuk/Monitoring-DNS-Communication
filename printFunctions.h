//
// Created by oleg on 1.11.24.
//

#ifndef ISA_PRINTFUNCTIONS_H
#define ISA_PRINTFUNCTIONS_H
#include "dnsStructures.h"
#include "helpFunctions.h"
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "parseFunctions.h"
void printVerboseDNSInfo(const void* ip_header, const struct udphdr* udp_header, const DNSHeader* dns_header, bool isIPv6);

void printAdditionalSection(const std::vector<DNSRecord>& answers);

void printAnswerSection(const std::vector<DNSRecord>& answers);

void printAuthoritySection(const std::vector<DNSRecord>& answers);

void printSection(const std::vector<DNSRecord>& answers);
void printQuestionSection(const DNSQuestion& question);

void printBasicDNSInfo(const void* ip_header, const DNSHeader* dns_header, bool isResponse, bool isIPv6);
#endif //ISA_PRINTFUNCTIONS_H
