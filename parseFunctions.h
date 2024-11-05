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
#include <pcap.h>             // For pcap-related functions
#include <netinet/if_ether.h> // For struct ether_header
#include <netinet/ip.h>       // For struct ip
#include <netinet/udp.h>
std::string parseQName(const u_char* packet, int& offset);

std::string parseQNameForAnswer(const u_char* packet, int& offset);

DNSQuestion parseQuestionSection(const u_char* packet, int& offset);
DNSRecord parseDNSRecord(const u_char* packet, int& offset);
#endif //ISA_PARSEFUNCTIONS_H
