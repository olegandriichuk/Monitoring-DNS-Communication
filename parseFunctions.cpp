//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//

#include "parseFunctions.h"


void storeDomainTranslation(const std::string& domain, const std::string& ipAddress) {
    std::string entry = domain + " " + ipAddress;

    // Check if the entry already exists in the vector
    if (std::find(domainTranslations.begin(), domainTranslations.end(), entry) == domainTranslations.end()) {
        domainTranslations.push_back(entry); // Add only unique entries
    }
}



std::string parseQNameForAnswer(const u_char* packet, int& offset, bool isIPv6) {
    std::string qname;
    int originalOffset = 0;  // Store initial offset
    bool jumped = false;          // Track if a pointer was used
    int safetyCounter = 0;        // Prevent infinite loop

    while (true) {
        if (safetyCounter++ > 100) {
            throw std::runtime_error("ERROR: Potential infinite loop or invalid packet");
        }

        uint8_t label_length = packet[offset];
        // End of name
        if (label_length == 0) {
            if (!jumped) offset++;
            break;
        }

        if ((label_length & 0xC0) == 0xC0) {
            if (!jumped) {
                jumped = true;
                originalOffset = offset + 2;
            }
            // Adjust offset using pointer
            offset = ((label_length & 0x3F) << 8) | packet[offset + 1];
            if(isIPv6){
                offset += static_cast<int>(sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
            } else{
                offset += static_cast<int>(sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
            }
            continue;
        } else {
            // Process standard label
            offset++;
            qname.append(reinterpret_cast<const char*>(&packet[offset]), label_length);
            offset += label_length;
            qname.append(".");
        }
    }

    if (!qname.empty() && qname.back() == '.') {
        qname.pop_back();
    }
// Restore offset if jumped
    if (jumped) {
        offset = originalOffset;
    }

    return qname;
}



DNSRecord parseDNSRecord(const u_char* packet, int& offset, bool isIPv6) {
    DNSRecord record;
    record.name = parseQNameForAnswer(packet, offset, isIPv6); // Read domain name

    // Parse fields of DNSRecord
    record.type = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    record.dnsClass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    record.ttl = ntohl(*(uint32_t*)&packet[offset]);
    offset += 4;
    record.rdLength = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    // Record types to track for unique domain names
    if (record.type == 1 || record.type == 28 || record.type == 2 || record.type == 5 || record.type == 6 || record.type == 15 || record.type == 33) {
        if (std::find(domainNames.begin(), domainNames.end(), record.name) == domainNames.end()) {
            domainNames.push_back(record.name);
        }
    }

    // Skip non-relevant records
    if (record.type != 1 && record.type != 28 && record.type != 2 && record.type != 5 && record.type != 6 && record.type != 15 && record.type != 33) {
        offset += record.rdLength;
        return record;
    }

    // Process A record (IPv4 address)
    if (record.type == 1) {
        if (record.rdLength == 4) {
            record.rdata = std::to_string(static_cast<unsigned char>(packet[offset])) + "." +
                           std::to_string(static_cast<unsigned char>(packet[offset + 1])) + "." +
                           std::to_string(static_cast<unsigned char>(packet[offset + 2])) + "." +
                           std::to_string(static_cast<unsigned char>(packet[offset + 3]));
            offset += 4;
        }
        storeDomainTranslation(record.name, record.rdata);
    }

    // Process NS record
    if (record.type == 2) {
        record.rdata = parseQNameForAnswer(packet, offset, isIPv6);
        if (std::find(domainNames.begin(), domainNames.end(), record.rdata) == domainNames.end()) {
            domainNames.push_back(record.rdata);
        }
    }

    // Process CNAME record
    if (record.type == 5) {
        record.rdata = parseQNameForAnswer(packet, offset, isIPv6);
        if (std::find(domainNames.begin(), domainNames.end(), record.rdata) == domainNames.end()) {
            domainNames.push_back(record.rdata);
        }
    }

    // Process MX record
    if (record.type == 15) {
        if (record.rdLength >= 2) {
            uint16_t priority = ntohs(*(uint16_t*)&packet[offset]);
            offset += 2;

            std::string exchange = parseQNameForAnswer(packet, offset, isIPv6);
            if (std::find(domainNames.begin(), domainNames.end(), exchange) == domainNames.end()) {
                domainNames.push_back(exchange);
            }

            std::stringstream ss;
            ss << priority << " " << exchange << ".";
            record.rdata = ss.str();
        } else {
            offset += record.rdLength;
        }
    }

    // Process SOA record
    if (record.type == 6) {
        std::stringstream ss;
        std::string primaryNS = parseQNameForAnswer(packet, offset, isIPv6);
        if (std::find(domainNames.begin(), domainNames.end(), primaryNS) == domainNames.end()) {
            domainNames.push_back(primaryNS);
        }
        ss << primaryNS << ". ";

        std::string respAuthorityMailbox = parseQNameForAnswer(packet, offset, isIPv6);
        ss << respAuthorityMailbox << ". ";

        // Process additional SOA fields
        uint32_t serial, refresh, retry, expire, minimum;
        memcpy(&serial, &packet[offset], 4); serial = ntohl(serial); offset += 4;
        memcpy(&refresh, &packet[offset], 4); refresh = ntohl(refresh); offset += 4;
        memcpy(&retry, &packet[offset], 4); retry = ntohl(retry); offset += 4;
        memcpy(&expire, &packet[offset], 4); expire = ntohl(expire); offset += 4;
        memcpy(&minimum, &packet[offset], 4); minimum = ntohl(minimum); offset += 4;

        ss << serial << " " << refresh << " " << retry << " " << expire << " " << minimum;
        record.rdata = ss.str();
    }

    // Process AAAA record (IPv6 address)
    if (record.type == 28) {
        if (record.rdLength == 16) {
            char ipv6Address[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &packet[offset], ipv6Address, INET6_ADDRSTRLEN);
            record.rdata = std::string(ipv6Address);
            offset += 16;
            storeDomainTranslation(record.name, record.rdata);
        }
    }

    // Process SRV record
    if (record.type == 33) {
        uint16_t priority = ntohs(*(uint16_t*)&packet[offset]); offset += 2;
        uint16_t weight = ntohs(*(uint16_t*)&packet[offset]); offset += 2;
        uint16_t port = ntohs(*(uint16_t*)&packet[offset]); offset += 2;

        std::string target = parseQNameForAnswer(packet, offset, isIPv6);
        if (std::find(domainNames.begin(), domainNames.end(), target) == domainNames.end()) {
            domainNames.push_back(target);
        }

        std::stringstream ss;
        ss << priority << " " << weight << " " << port << " " << target << ".";
        record.rdata = ss.str();
    }

    return record;
}

DNSQuestion parseQuestionSection(const u_char* packet, int& offset, bool isIPv6) {
    DNSQuestion question;
    question.qname = parseQNameForAnswer(packet, offset, isIPv6);

    question.qtype = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;
    question.qclass = ntohs(*(uint16_t*)&packet[offset]);
    offset += 2;

    // Track unique domain names for specific question types
    if (question.qtype == 1 || question.qtype == 28 || question.qtype == 2 || question.qtype == 5 || question.qtype == 6 || question.qtype == 15 || question.qtype == 33) {
        if (std::find(domainNames.begin(), domainNames.end(), question.qname) == domainNames.end()) {
            domainNames.push_back(question.qname);
        }
    }
    return question;
}