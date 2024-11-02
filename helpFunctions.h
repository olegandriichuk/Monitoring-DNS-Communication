//
// Created by oleg on 1.11.24.
//

#ifndef ISA_HELPFUNCTIONS_H
#define ISA_HELPFUNCTIONS_H
#include <string>
std::string getClassName(uint16_t qclass);
std::string getCurrentTimestamp();
std::string getTypeName(uint16_t qtype);
bool isPointer(uint8_t byte);
#endif //ISA_HELPFUNCTIONS_H
