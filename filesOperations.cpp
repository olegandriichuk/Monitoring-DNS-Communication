//
// Created by oleg on 8.11.24.
//

#include "filesOperations.h"
#include "parseFunctions.h"
#include <fstream>
#include <iostream>
std::vector<std::string> domainNames;        // Define the vectors
std::vector<std::string> domainTranslations;

void saveDomainsToFile(const std::string& filename) {
    std::ofstream outfile(filename);
    if (!outfile) {
        std::cerr << "Error: Could not open file " << filename << " for writing.\n";
        return;
    }
    for (const auto& domain : domainNames) {
        outfile << domain << '\n';
    }
    outfile.close();
    std::cout << "Domains saved to " << filename << "\n";
}

void saveDomainTranslationsToFile(const std::string& filename) {
    std::ofstream outfile(filename);
    if (!outfile) {
        std::cerr << "Error: Could not open file " << filename << " for writing.\n";
        return;
    }
    for (const auto& translation : domainTranslations) {
        outfile << translation << '\n';
    }
    outfile.close();
    std::cout << "Domain translations saved to " << filename << "\n";
}

//#include "filesOperations.h"
//#include <fstream>
//#include <set>
//
//static std::string domainsFilename;
//static std::string translationsFilename;
//static std::set<std::string> domainSet; // унікальні домени
//static std::set<std::string> translationSet; // унікальні переклади
//
//void setDomainsFilename(const std::string& filename) {
//    domainsFilename = filename;
//}
//
//void setTranslationFilename(const std::string& filename) {
//    translationsFilename = filename;
//}
//
//void addDomainToFile(const std::string& domain) {
//    if (domainSet.find(domain) == domainSet.end()) { // Перевірка на унікальність
//        std::ofstream outfile(domainsFilename, std::ios::app);
//        if (outfile) {
//            outfile << domain << '\n';
//            domainSet.insert(domain); // Додаємо в множину
//        }
//    }
//}
//
//void addTranslationToFile(const std::string& domain, const std::string& ipAddress) {
//    std::string entry = domain + " " + ipAddress;
//    if (translationSet.find(entry) == translationSet.end()) { // Перевірка на унікальність
//        std::ofstream outfile(translationsFilename, std::ios::app);
//        if (outfile) {
//            outfile << entry << '\n';
//            translationSet.insert(entry); // Додаємо в множину
//        }
//    }
//}
