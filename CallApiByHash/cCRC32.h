#pragma once
#include <Windows.h>

class cCRC32
{

public:
	static UINT uiCRC32Table[256];
	static UINT Hash(LPSTR pszData, DWORD dwLenght);

};

