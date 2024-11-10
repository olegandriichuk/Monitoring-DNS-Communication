//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//

#include "filesOperations.h"
#include "parseFunctions.h"
#include <fstream>
#include <iostream>
std::vector<std::string> domainNames;
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

}


