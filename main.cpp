#include <stdio.h>
#include <windows.h>

char newCode_x86[5];
char oldCode_x86[5];
char newCode_x64[12];
char oldCode_x64[12];
BOOL isWOW64;
FARPROC Fun_Addr;

bool Install_HOOK(LPCSTR DLL_Name, LPCSTR Fun_Name, FARPROC Callback_Fun); 
void Suspend_HOOK();
void Recovery_HOOK();
void WritesMemory_x86(char code[]);
void WritesMemory_x64(char code[]);
int WINAPI MB_CallBack(HWND a, LPCSTR b, LPCSTR c, UINT d);

int main()
{
	Install_HOOK("user32.dll", "MessageBoxA", (FARPROC)MB_CallBack);		//安装HOOK，并且HOOK MessageBoxA 这个API函数
	MessageBoxA(NULL,"测试拦截","这是个标题",NULL);
	getchar();
	return 0;
}

int WINAPI MB_CallBack(HWND a, LPCSTR b, LPCSTR c,UINT d)					//构造 MessageBoxA 的回调函数(函数的参数数目和返回值必须一致)
{
	int ret;
	Suspend_HOOK();
	printf_s("内容：%s\n标题：%s",b,c);
	ret = MessageBoxA(NULL,b,c,NULL);
	Recovery_HOOK();
	return ret;
}

bool Install_HOOK(LPCSTR DLL_Name, LPCSTR Fun_Name, FARPROC Callback_Fun)
{
	HMODULE hDLL;
	hDLL = LoadLibraryA(DLL_Name);

	if (hDLL == 0)
	{
		return false;
	}

	Fun_Addr = GetProcAddress(hDLL, Fun_Name);

	if (Fun_Addr == 0)
	{
		FreeLibrary(hDLL);
		return false;
	}

	IsWow64Process(GetCurrentProcess(), &isWOW64);

	if (isWOW64 == false)
	{
		long long a = (long long)Callback_Fun;
		newCode_x64[0] = 0x48;
		newCode_x64[1] = 0xB8;
		newCode_x64[10] = 0x50;
		newCode_x64[11] = 0xC3;
		RtlMoveMemory(newCode_x64 + 2, &a, 8);
		DWORD pCode;
		if (VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 12, PAGE_EXECUTE_READWRITE, &pCode))
		{
			RtlMoveMemory(oldCode_x64, Fun_Addr, 12);
			WriteProcessMemory(GetCurrentProcess(), Fun_Addr, newCode_x64, 12, NULL);
			VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 12, pCode, &pCode);
		}
	}
	else
	{
		DWORD a = (DWORD)Callback_Fun - (DWORD)Fun_Addr - 5;
		newCode_x86[0] = 0xe9;
		RtlMoveMemory(newCode_x86 + 1, &a, 4);
		DWORD pCode;
		if (VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 5, PAGE_EXECUTE_READWRITE, &pCode))
		{
			RtlMoveMemory(oldCode_x86, Fun_Addr, 5);
			WriteProcessMemory(GetCurrentProcess(), Fun_Addr, newCode_x86, 5, NULL);
			VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 5, pCode, &pCode);
		}
	}

	FreeLibrary(hDLL);
	return true;
}

void Suspend_HOOK()
{
	if (isWOW64 == false)
	{
		WritesMemory_x64(oldCode_x64);
	}
	else
	{
		WritesMemory_x86(oldCode_x86);
	}
}

void Recovery_HOOK()
{
	if (isWOW64 == false)
	{
		WritesMemory_x64(newCode_x64);
	}
	else
	{
		WritesMemory_x86(newCode_x86);
	}
}

void WritesMemory_x86(char code[])
{
	DWORD pCode;
	if (VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 5, PAGE_EXECUTE_READWRITE, &pCode))
	{
		WriteProcessMemory(GetCurrentProcess(), Fun_Addr, code, 5, NULL);
		VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 5, pCode, &pCode);
	}
}

void WritesMemory_x64(char code[])
{
	DWORD pCode;
	if (VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 12, PAGE_EXECUTE_READWRITE, &pCode))
	{
		WriteProcessMemory(GetCurrentProcess(), Fun_Addr, code, 12, NULL);
		VirtualProtectEx(GetCurrentProcess(), Fun_Addr, 12, pCode, &pCode);
	}
}