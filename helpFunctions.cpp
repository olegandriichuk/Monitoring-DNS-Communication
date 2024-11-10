//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//
#include "helpFunctions.h"

std::string getClassName(uint16_t qclass) {
    return (qclass == 1) ? "IN" : "UNKNOWN";
}

std::string getCurrentTimestamp(const struct pcap_pkthdr* pkthdr) {
    time_t time = pkthdr->ts.tv_sec;
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&time);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

std::string getTypeName(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";
        case 28: return "AAAA";
        case 5: return "CNAME";
        case 15: return "MX";
        case 2: return "NS";
        case 6: return "SOA";
        case 33: return "SRV";
        default: return "UNKNOWN";
    }
}

