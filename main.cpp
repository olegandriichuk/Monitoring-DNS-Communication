#include <iostream>
#include <unistd.h>
#include <string>
#include <pcap.h>
#include <csignal>  // For signal handling
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <fstream>
#include <arpa/inet.h>
#include "printFunctions.h"
#include "parseFunctions.h"
#include "processPacket.h"
#include "filesOperations.h"
bool running = true;
std::string domainsfile;
std::string translationfile;

void signalHandler(int signum) {
    std::cout << "Received signal " << signum << ", terminating program gracefully.\n";
    running = false;

    // Save domains and translations before exiting
    if (!domainsfile.empty()) {
        saveDomainsToFile(domainsfile);
    }

    if (!translationfile.empty()) {
        saveDomainTranslationsToFile(translationfile);
    }

    // Exit the program after cleanup
    exit(0);
}
int main(int argc, char* argv[]) {
    std::string interface;
    std::string pcapfile;

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
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    if (!interface.empty()) {
        // Live capture mode
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Couldn't open device: " << errbuf << "\n";
            return 1;
        }

        // Capture packets in a loop, allowing for graceful exit on signal
        while (running) {
            pcap_dispatch(handle, 0, [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
                processPacket(header, packet, *(bool*)args);
            }, (u_char*)&verbose);
        }

    } else {
        // Offline file reading mode
        handle = pcap_open_offline(pcapfile.c_str(), errbuf);
        if (handle == nullptr) {
            std::cerr << "Couldn't open file: " << errbuf << "\n";
            return 1;
        }

        // Process packets until end of file, then exit
        pcap_loop(handle, 0, [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
            processPacket(header, packet, *(bool*)args);
        }, (u_char*)&verbose);
    }

    // Save the domains and translations to files if specified
    if (!domainsfile.empty()) {
        saveDomainsToFile(domainsfile);
    }

    if (!translationfile.empty()) {
        saveDomainTranslationsToFile(translationfile);
    }

    pcap_close(handle);
    return 0;
}

