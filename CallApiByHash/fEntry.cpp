#include <Windows.h>
#include "cApiHash.h"

//�������� ������� ������� ����� �������
typedef int(WINAPI* _MessageBoxA)(

	HWND hWND,
	LPCSTR pszText,
	LPCSTR pszCaption,
	UINT uType

);

VOID WINAPI Entry(VOID) {

	_MessageBoxA fpMessageBoxA = (_MessageBoxA)GetFuncByHash("user32.dll", 0x572D5D8E);
	fpMessageBoxA(NULL, "Hello xss.is", "xss.is", MB_OK);


}