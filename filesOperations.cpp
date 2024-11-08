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