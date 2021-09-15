#include <vector>

void printShellcode(std::vector<unsigned char> shellcode, size_t len);
std::vector<unsigned char> xorCrypt(const char* key, int key_len, std::vector<unsigned char> data, int data_len);