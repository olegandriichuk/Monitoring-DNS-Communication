#include <iostream>
#include <unistd.h>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>       // Для IP-заголовків
#include <netinet/udp.h>      // Для UDP-заголовків
#include <netinet/if_ether.h> // Для Ethernet-заголовків
#include <arpa/inet.h>        // Для перетворення IP-адрес
#include <ctime>

// Структура для заголовка DNS
struct DNSHeader {
    uint16_t id;       // Ідентифікатор
    uint16_t flags;    // Прапорці
    uint16_t qd_count; // Кількість записів у секції Question
    uint16_t an_count; // Кількість записів у секції Answer
    uint16_t ns_count; // Кількість записів у секції Authority
    uint16_t ar_count; // Кількість записів у секції Additional
};
struct DNSQuestion {
    std::string qname;   // Доменне ім'я, наприклад, "example.com."
    uint16_t qtype;      // Тип запиту (наприклад, 1 для A-запису)
    uint16_t qclass;     // Клас запиту (зазвичай 1 для IN - Інтернет)
};
// Функція для перетворення QTYPE на текстове представлення
std::string getTypeName(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";        // Адресний запис IPv4
        case 28: return "AAAA";    // Адресний запис IPv6
        case 5: return "CNAME";    // Канонічне ім'я
        case 15: return "MX";      // Поштовий обмін
        case 2: return "NS";       // Сервер доменних імен
        default: return "UNKNOWN"; // Невідомий тип
    }
}

// Функція для перетворення QCLASS на текстове представлення
std::string getClassName(uint16_t qclass) {
    return (qclass == 1) ? "IN" : "UNKNOWN"; // IN - Інтернет, інші класи можна додати
}

// Функція для виводу даних Question Section
void printQuestionSection(const DNSQuestion& question) {
    std::cout << "[Question Section]\n"
              << " " << question.qname << " "
              << getClassName(question.qclass) << " "
              << getTypeName(question.qtype) << "\n";
}
// Функція для отримання поточної дати і часу у потрібному форматі
std::string getCurrentTimestamp() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    return buf;
}

// Функція для виводу базової інформації про DNS-запит
void printBasicDNSInfo(const struct ip* ip_header, const DNSHeader* dns_header, bool isResponse) {
    uint16_t qd_count = ntohs(dns_header->qd_count);
    uint16_t an_count = ntohs(dns_header->an_count);
    uint16_t ns_count = ntohs(dns_header->ns_count);
    uint16_t ar_count = ntohs(dns_header->ar_count);

    std::string timestamp = getCurrentTimestamp();
    std::cout << timestamp << " "
              << inet_ntoa(ip_header->ip_src) << " -> "
              << inet_ntoa(ip_header->ip_dst) << " ("
              << (isResponse ? "R" : "Q") << " "
              << qd_count << "/"
              << an_count << "/"
              << ns_count << "/"
              << ar_count << ")\n";
    std::cout << "----------------------------------------\n";
}

// Функція для виводу детальної інформації про DNS-запит
void printVerboseDNSInfo(const struct ip* ip_header, const struct udphdr* udp_header, const DNSHeader* dns_header) {
    std::string timestamp = getCurrentTimestamp();
    uint16_t identifier = ntohs(dns_header->id);
    uint16_t flags = ntohs(dns_header->flags);

    // Розбір прапорців
    bool qr = flags & 0x8000;
    uint8_t opcode = (flags >> 11) & 0x0F;
    bool aa = flags & 0x0400;
    bool tc = flags & 0x0200;
    bool rd = flags & 0x0100;
    bool ra = flags & 0x0080;
    bool ad = flags & 0x0020;
    bool cd = flags & 0x0010;
    uint8_t rcode = flags & 0x000F;

    // Вивід детальної інформації
    std::cout << "Timestamp: " << timestamp << "\n"
              << "SrcIP: " << inet_ntoa(ip_header->ip_src) << "\n"
              << "DstIP: " << inet_ntoa(ip_header->ip_dst) << "\n"
              << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << "\n"
              << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << "\n"
              << "Identifier: 0x" << std::hex << identifier << std::dec << "\n"
              << "Flags: QR=" << qr
              << ", OPCODE=" << (int)opcode
              << ", AA=" << aa
              << ", TC=" << tc
              << ", RD=" << rd
              << ", RA=" << ra
              << ", AD=" << ad
              << ", CD=" << cd
              << ", RCODE=" << (int)rcode << "\n"
              << "====================\n";
}

// Функція обробки пакетів
void processPacket(const u_char* packet, bool verbose) {
    // Отримання Ethernet-заголовка
    struct ether_header* eth_header = (struct ether_header*) packet;

    // Перевірка, чи є це IP-пакетом
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Отримання IP-заголовка
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Визначення протоколу (UDP)
        if (ip_header->ip_p == IPPROTO_UDP) {
            // Отримання UDP-заголовка
            struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Перевірка, чи використовується порт 53 (DNS)
            if (ntohs(udp_header->uh_dport) == 53 || ntohs(udp_header->uh_sport) == 53) {
                // Отримання DNS-заголовка
                DNSHeader* dns_header = (DNSHeader*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

                // Визначення, чи це запит чи відповідь (QR-біт)
                bool isResponse = ntohs(dns_header->flags) & 0x8000;

                // Вивід інформації
                if (verbose) {
                    printVerboseDNSInfo(ip_header, udp_header, dns_header);
                } else {
                    printBasicDNSInfo(ip_header, dns_header, isResponse);
                }
            }
        }
    }
}

// Основна функція
int main(int argc, char* argv[]) {
    // Змінні для зберігання значень аргументів
    std::string interface;
    std::string pcapfile;
    bool verbose = false;

    int option;
    // Парсинг аргументів за допомогою getopt
    while ((option = getopt(argc, argv, "i:p:v")) != -1) {
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
            default:
                std::cerr << "Unknown option: " << option << "\n";
                return 1;
        }
    }

    // Перевірка, чи заданий хоча б один із параметрів -i або -p
    if (interface.empty() && pcapfile.empty()) {
        std::cerr << "Please provide either -i <interface> or -p <pcapfile>\n";
        return 1;
    }

    // Відкриття інтерфейсу або файлу PCAP для захоплення
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

    // Захоплення пакетів та обробка
    pcap_loop(handle, 0, [](u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
        processPacket(packet, *(bool*)args);
    }, (u_char*)&verbose);

    pcap_close(handle);
    return 0;
}
