//
// Created by oleg on 8.11.24.
//

#ifndef ISA_PROCESSPACKET_H
#define ISA_PROCESSPACKET_H
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
void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, bool verbose);
#endif //ISA_PROCESSPACKET_H
