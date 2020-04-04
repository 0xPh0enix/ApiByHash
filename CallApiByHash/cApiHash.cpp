#include "cApiHash.h"
#include "cCRC32.h"


LPVOID GetFuncByHash(LPCSTR pszLibrary, UINT uHash) {

	//��������� ���������� 
	HINSTANCE hLibrary = LoadLibraryA(pszLibrary);

	if (!hLibrary)
		return NULL;

	//�������� DOS-��������� � ��������� ��� �� ����������
	PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)hLibrary;

	if (pDOSHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;


	//�������� PE-��������� � ��������� ��� �� ����������
	PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)((LPBYTE)hLibrary + pDOSHdr->e_lfanew);

	if (pNTHdr->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if ((pNTHdr->FileHeader.Characteristics & IMAGE_FILE_DLL) == NULL ||
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == NULL ||
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == NULL)
			return NULL;

	//�������� �������� ������� ��������
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hLibrary +
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddress = (PDWORD)((LPBYTE)hLibrary + pIED->AddressOfFunctions);
	PDWORD pdwNames = (PDWORD)((LPBYTE)hLibrary + pIED->AddressOfNames);
	PWORD pwOrd = (PWORD)((LPBYTE)hLibrary + pIED->AddressOfNameOrdinals);

	//��������� ������� ��������
	for (DWORD i = 0; i < pIED->AddressOfFunctions; i++)
	{

		LPSTR pszFuncName = (LPSTR)((LPBYTE)hLibrary + pdwNames[i]);
		UINT32 u32FuncHash = cCRC32::Hash(pszFuncName, lstrlenA(pszFuncName));

		//���� ���� ��������� - ���������� ���������
		if (u32FuncHash == uHash)
			return (LPVOID)((LPBYTE)hLibrary + pdwAddress[pwOrd[i]]);
		
	}
}