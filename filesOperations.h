//
// Created by oleg on 8.11.24.
//

#ifndef ISA_FILESOPERATIONS_H
#define ISA_FILESOPERATIONS_H
#include <string>
#include <vector>
//
//// Extern declarations of vectors to use them across files
////extern std::vector<std::string> domainNames;
////extern std::vector<std::string> domainTranslations;
//
//// Function declarations
void saveDomainsToFile(const std::string& filename);
void saveDomainTranslationsToFile(const std::string& filename);


//void setDomainsFilename(const std::string& filename);
//void setTranslationFilename(const std::string& filename);
//void addDomainToFile(const std::string& domain);
//void addTranslationToFile(const std::string& domain, const std::string& ipAddress);

#endif //ISA_FILESOPERATIONS_H
