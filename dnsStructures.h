//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//

#ifndef ISA_DNSSTRUCTURES_H
#define ISA_DNSSTRUCTURES_H
#include <iostream>
#include <unistd.h>
#include <string>
#include <vector>
struct DNSHeader {
    uint16_t id;       // Identifier for matching requests and responses
    uint16_t flags;    // Flags to control query and response behavior
    uint16_t qd_count; // Number of entries in the Question Section
    uint16_t an_count; // Number of entries in the Answer Section
    uint16_t ns_count; // Number of entries in the Authority Section
    uint16_t ar_count; // Number of entries in the Additional Section
};

// Structure for the Question Section
struct DNSQuestion {
    std::string qname;   // Domain name, e.g., "example.com."
    uint16_t qtype;      // Query type (e.g., 1 for an A record)
    uint16_t qclass;     // Query class (usually 1 for IN - Internet)
};

// Structure for DNS records in the Answer, Authority, or Additional Section
struct DNSRecord {
    std::string name;    // Domain name associated with the record (NAME)
    uint16_t type;       // Record type (TYPE), such as A, AAAA, CNAME, NS
    uint16_t dnsClass;   // Record class (CLASS), typically IN (1)
    uint32_t ttl;        // Time to live in seconds (TTL)
    uint16_t rdLength;   // Length of the data in the RDATA field (RDLENGTH)
    std::string rdata;   // Record data (RDATA), format depends on the record type
};

#endif //ISA_DNSSTRUCTURES_H
