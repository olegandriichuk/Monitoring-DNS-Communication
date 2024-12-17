//
// ISA project 2024: Monitorování DNS komunikace
// Oleg Andriichuk
// xandri07
//
#ifndef ISA_FILESOPERATIONS_H
#define ISA_FILESOPERATIONS_H
#include <string>
#include <vector>

/**
 * @brief Save unique domains to file
 * @param filename The name of the file to save domains to
 */
void saveDomainsToFile(const std::string& filename);

/**
 * @brief Save domain-IP translations to file
 * @param filename The name of the file to save translations to
 */
void saveDomainTranslationsToFile(const std::string& filename);





#endif //ISA_FILESOPERATIONS_H
