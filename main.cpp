#include <iostream>
#include <unistd.h>
#include <string>

int main(int argc, char* argv[]) {
    // Змінні для зберігання значень аргументів
    std::string interface;
    std::string pcapfile;
    std::string domainsfile;
    std::string translationsfile;
    bool verbose = false;

    int option;
    // Парсинг аргументів за допомогою getopt
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
                translationsfile = optarg;
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

    // Виведення отриманих аргументів для перевірки
    if (!interface.empty()) {
        std::cout << "Interface: " << interface << "\n";
    }
    if (!pcapfile.empty()) {
        std::cout << "PCAP file: " << pcapfile << "\n";
    }
    if (verbose) {
        std::cout << "Verbose mode enabled\n";
    }
    if (!domainsfile.empty()) {
        std::cout << "Domains file: " << domainsfile << "\n";
    }
    if (!translationsfile.empty()) {
        std::cout << "Translations file: " << translationsfile << "\n";
    }

    // Додайте подальшу логіку для обробки аргументів тут

    return 0;
}
