//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//

#ifndef ISA_HELPFUNCTIONS_H
#define ISA_HELPFUNCTIONS_H
#include <string>
#include <pcap.h>
/**
 * @brief Get the DNS class name based on the class code
 * @param qclass The DNS class code
 * @return Class name as a string (e.g., "IN" or "UNKNOWN")
 */
std::string getClassName(uint16_t qclass);

/**
 * @brief Get the current timestamp from packet header
 * @param pkthdr The packet header containing the timestamp
 * @return Timestamp as a formatted string (e.g., "YYYY-MM-DD HH:MM:SS")
 */
std::string getCurrentTimestamp(const struct pcap_pkthdr* pkthdr);

/**
 * @brief Get the DNS record type name based on the type code
 * @param qtype The DNS record type code
 * @return Type name as a string (e.g., "A", "AAAA", "CNAME", etc.)
 */
std::string getTypeName(uint16_t qtype);

#endif //ISA_HELPFUNCTIONS_H
