#include <iostream>
#include <unistd.h>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>       // Для IP-заголовків
#include <netinet/ip6.h>      // Для IP-заголовків IPv6
#include <netinet/udp.h>      // Для UDP-заголовків
#include <netinet/if_ether.h> // Для Ethernet-заголовків
#include <fstream>
#include <arpa/inet.h>        // Для перетворення IP-адрес
#include "printFunctions.h"
#include "parseFunctions.h"
#include "processPacket.h"
#include "filesOperations.h"

int main(int argc, char* argv[]) {
    std::string interface;
    std::string pcapfile;
    std::string domainsfile;
    std::string translationfile;
    bool verbose = false;

    int option;
    while ((option = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                pcapfile = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'd':
                domainsfile = optarg;
                break;
            case 't':
                translationfile = optarg;
                break;
            default:
                std::cerr << "Unknown option: " << option << "\n";
                return 1;
        }
    }

    if (interface.empty() && pcapfile.empty()) {
        std::cerr << "Please provide either -i <interface> or -p <pcapfile>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (!interface.empty()) {
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Couldn't open device: " << errbuf << "\n";
            return 1;
        }
    } else {
        handle = pcap_open_offline(pcapfile.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << "Couldn't open file: " << errbuf << "\n";
            return 1;
        }
    }

    // Використовуємо лямбда-функцію для передачі pkthdr в processPacket
    pcap_loop(handle, 0, [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
        processPacket(header, packet, *(bool*)args); // Передаємо header в processPacket
    }, (u_char*)&verbose);

    if (!domainsfile.empty()) {
        saveDomainsToFile(domainsfile);
    }

    if (!translationfile.empty()) {
        saveDomainTranslationsToFile(translationfile);
    }
    pcap_close(handle);
    return 0;
}

