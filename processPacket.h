//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
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
/**
 * @brief Processes a network packet and extracts DNS information if present.
 * @param pkthdr The packet header containing metadata such as timestamp.
 * @param packet The raw packet data to be processed.
 * @param verbose If true, prints detailed DNS information; otherwise, prints basic info.
 */
void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet, bool verbose);
#endif //ISA_PROCESSPACKET_H
