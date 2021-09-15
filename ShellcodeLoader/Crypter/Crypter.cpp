#pragma once
#include <iostream>
#include <fstream>
#include "Crypter.h"

int main(int argc, char** argv) {
	const char key[] = "R";

	if (argc < 2) {
		printf("Usage: %s <shellcodeFile> <outFile>\n", argv[0]);
		printf("Usage: %s shellcode.bin xorShellcode.bin\n", argv[0]);
		exit(0);
	}

	// connormcgarr.github.io/
	char* inputFile = argv[1];
	char* outputFile = argv[2];
	
	std::ifstream input(inputFile, std::ios::binary);
	std::ofstream output(outputFile, std::ios::binary);

	std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(input), {});

	buffer = xorCrypt(key, sizeof(key), buffer, buffer.size());
	output.write((char*)&buffer[0], buffer.size() * sizeof(unsigned char));

	input.close();
	output.close();
}

std::vector<unsigned char> xorCrypt(const char* key, int key_len, std::vector<unsigned char> data, int data_len) {
	for (int i = 0; i < data_len; i++) {
		data[i] ^= key[i % key_len];
	}

	printShellcode(data, data_len);
	return data;
}

void printShellcode(std::vector<unsigned char> shellcode, size_t len) {
	std::cout << "unsigned char buf[] = \"";
	for (int i = 0; i < len-1; i++) {
		printf("\\x%x", shellcode[i]);
	}

	std::cout << "\";";
}

