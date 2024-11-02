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
void printVerboseDNSInfo(const struct ip* ip_header, const struct udphdr* udp_header, const DNSHeader* dns_header);

void printAnswerSection(const std::vector<DNSRecord>& answers);

void printQuestionSection(const DNSQuestion& question);

void printBasicDNSInfo(const struct ip* ip_header, const DNSHeader* dns_header, bool isResponse);
#endif //ISA_PRINTFUNCTIONS_H
