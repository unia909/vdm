#include <Windows.h>
#include "res.h"

#define IDM_INSTALLDRIVER 101
#define IDM_ADDDISPLAY 102
#define IDM_REMOVEDISPLAY 103
#define IDM_EXIT 104

// WinApi c stack compatible
void *malloc(size_t size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void free(void *ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

typedef LONG NTSTATUS;

NTSYSAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOEXW lpVersionInformation);

WCHAR szDeviceInstaller[] = L"deviceinstaller  .exe";

void LocaleRead(wchar_t *data, wchar_t **buf, unsigned int bufLen)
{
    unsigned int i = 0, j = 1;
    buf[0] = data;
    while (j < bufLen && data[i])
    {
        while (data[i] != L'\n' && data[i])
            ++i;
        if (!data[i])
            return;
        buf[j++] = data + i + 1;
        data[i++] = 0;
    }
    if (data[i] != 0)
    {
        while (data[i] != L'\n' && data[i])
            ++i;
        data[i] = 0;
    }
}

int lmemcmp(void *mem1, void *mem2, int size)
{
    int i = 0;
    for (; i < size; ++i)
        if (((char*)mem1)[i] != ((char*)mem2)[i])
            return 0;
    return 1;
}

HANDLE hStdError;
char g_DebugMessageBuffer[256];

#define DEBUGMSG(...) do {                                                    \
    if (hStdError)                                                            \
    {                                                                         \
        wsprintfA(g_DebugMessageBuffer, __VA_ARGS__);                         \
        WriteFile(hStdError, g_DebugMessageBuffer,                            \
            lstrlenA(g_DebugMessageBuffer), NULL, NULL);                      \
    }                                                                         \
} while (0)

wchar_t *DefaultLocale[] = {
    L"Please note that the driver has not been tested on windows 10 below 20H2 and definitely does not work on windows 10 1607 and below",
    L"Virtual Display Manager",
    L"Failed to install usbmmidd driver.",
    L"Driver is not installed.",
    L"Driver already installed!",
    L"&File",
    L"&Install driver",
    L"&Add display",
    L"&Remove display",
    L"&Exit"
};

wchar_t *szLocBase;
wchar_t **szLoc = DefaultLocale;

void LoadLocale(PCWSTR file)
{
    HANDLE hFile = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize >= 16 * 1024)
    {
        DEBUGMSG("Locale file seems to be too big! Reading only first 16KB\n");
        dwFileSize = 16 * 1024;
    }
    char *buf = malloc(dwFileSize);
    ReadFile(hFile, buf, dwFileSize, NULL, NULL);
    CloseHandle(hFile);

    if (!lmemcmp(buf, "com.unia909.stdloc.vdm", 22))
    {
        DEBUGMSG("Locale file signature mismatch detected!\n");
        free(buf);
        return;
    }

    // skip locale file signature
    dwFileSize -= 24;
    buf += 24;

    szLocBase = malloc((dwFileSize + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, buf, dwFileSize, szLocBase, dwFileSize);
    szLocBase[dwFileSize] = 0;
    free(buf - 24);

    LocaleRead(szLocBase, szLoc, 410);
}

void sfree(void *ptr)
{
    if (ptr)
        free(ptr);
}

void FreeLocale()
{
    sfree(szLocBase);
}

HANDLE hProcessOutputReadPipe = NULL,
       hProcessOutputWritePipe = NULL;

void InitRunProcessPipes()
{
    SECURITY_ATTRIBUTES secAttr = {
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .bInheritHandle = TRUE
    };
    CreatePipe(&hProcessOutputReadPipe, &hProcessOutputWritePipe, &secAttr, 0);
    SetHandleInformation(hProcessOutputReadPipe, HANDLE_FLAG_INHERIT, 0);
}

void CloseRunProcessPipes()
{
    CloseHandle(hProcessOutputReadPipe);
    CloseHandle(hProcessOutputWritePipe);
}

PSTR RunProcess(LPWSTR lpApplicationName, LPWSTR lpCommandLine)
{
    STARTUPINFOW si = {
        .cb = sizeof(STARTUPINFOW),
        .hStdOutput = hProcessOutputWritePipe,
        .hStdError = hProcessOutputWritePipe,
        .dwFlags = STARTF_USESTDHANDLES
    };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(lpApplicationName, lpCommandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        DEBUGMSG("CreateProcess(%s, %s) Fail => %d", lpApplicationName, lpCommandLine, GetLastError());
        return NULL;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    DWORD size = GetFileSize(hProcessOutputReadPipe, NULL);
    if (size == 0)
        return NULL;
    PSTR szOutput = malloc(size + 1);
    ReadFile(hProcessOutputReadPipe, szOutput, size, NULL, NULL);
    szOutput[size] = 0;

    return szOutput;
}

PSTR StringSkipLine(PSTR str)
{
    for (;;)
    {
        while (*str && *str != '\r')
            ++str;
        if (!*str)
            break;
        if (*(++str) == '\n')
            return ++str;
    }
    return str;
}

int IsUsbmmiddDriverInstalled()
{
    PSTR szOutput = RunProcess(szDeviceInstaller, L"d find usbmmidd");
    if (!szOutput)
        return FALSE;
    int result = !lmemcmp(szOutput, "No matching devices found", 25);
    free(szOutput);
    return result;
}

HWND hMainWnd,
     hStatusBar;

HFONT hFont;
LOGFONTW lfFont;

HMENU hMenuBar,
      hFileMenu;

void CreateStatusBar()
{
    hStatusBar = CreateWindowW(L"Static", NULL, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hMainWnd, NULL, NULL, NULL);
    SendMessage(hStatusBar, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void CreateProgramMenu()
{
    hMenuBar = CreateMenu();

    //File:
    //  Install Driver
    //  Add display
    //  Remove display
    //  -------------
    //  Exit
    hFileMenu = CreateMenu();
    AppendMenuW(hFileMenu, MF_STRING, IDM_INSTALLDRIVER, szLoc[6]);
    AppendMenuW(hFileMenu, MF_STRING, IDM_ADDDISPLAY, szLoc[7]);
    AppendMenuW(hFileMenu, MF_STRING, IDM_REMOVEDISPLAY, szLoc[8]);
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hFileMenu, MF_STRING, IDM_EXIT, szLoc[9]);

    AppendMenuW(hMenuBar, MF_STRING | MF_POPUP, (UINT)hFileMenu, szLoc[5]);

    SetMenu(hMainWnd, hMenuBar);
}

void UpdateUI()
{
    if (IsUsbmmiddDriverInstalled())
    {
        SendMessageW(hStatusBar, WM_SETTEXT, 0, 0);
        EnableMenuItem(hFileMenu, IDM_INSTALLDRIVER, MF_DISABLED);
        EnableMenuItem(hFileMenu, IDM_ADDDISPLAY, MF_ENABLED);
        EnableMenuItem(hFileMenu, IDM_REMOVEDISPLAY, MF_ENABLED);
    }
    else
    {
        SendMessageW(hStatusBar, WM_SETTEXT, 0, (LPARAM)szLoc[3]);
        EnableMenuItem(hFileMenu, IDM_INSTALLDRIVER, MF_ENABLED);
        EnableMenuItem(hFileMenu, IDM_ADDDISPLAY, MF_DISABLED);
        EnableMenuItem(hFileMenu, IDM_REMOVEDISPLAY, MF_DISABLED);
    }
}

void InstallUsbmmiddDriver()
{
    if (IsUsbmmiddDriverInstalled())
    {
        UpdateUI();
        SendMessageW(hStatusBar, WM_SETTEXT, 0, (LPARAM)szLoc[4]);
        return;
    }
    PSTR szOutputPtr = RunProcess(szDeviceInstaller, L"d install usbmmidd.inf usbmmidd");
    if (!szOutputPtr)
        return;
    PSTR szOutput = szOutputPtr;
    while (*szOutput && !lmemcmp(szOutput, "Drivers installed successfully", 30))
        szOutput = StringSkipLine(szOutput);
    if (!*szOutput)
    {
        MessageBoxW(NULL, szLoc[2], NULL, 0);
        DEBUGMSG("Driver installing failed! %s output there:\r\n%s", szDeviceInstaller, szOutputPtr);
    }
    free(szOutputPtr);
    UpdateUI();
}

void AddVirtualDisplay()
{
    if (!IsUsbmmiddDriverInstalled())
    {
        UpdateUI();
        return;
    }

    free(RunProcess(szDeviceInstaller, L"d enableidd 1"));
}

void RemoveVirtualDisplay()
{
    if (!IsUsbmmiddDriverInstalled())
    {
        UpdateUI();
        return;
    }

    free(RunProcess(szDeviceInstaller, L"d enableidd 0"));
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            hMainWnd = hWnd;
#define lf lfFont
            GetObjectW(GetStockObject(DEFAULT_GUI_FONT), sizeof(LOGFONT), &lf);
            hFont = CreateFontW(lf.lfHeight, lf.lfWidth,
                                lf.lfEscapement, lf.lfOrientation, lf.lfWeight,
                                lf.lfItalic, lf.lfUnderline, lf.lfStrikeOut, lf.lfCharSet,
                                lf.lfOutPrecision, lf.lfClipPrecision, lf.lfQuality,
                                lf.lfPitchAndFamily, lf.lfFaceName);
#undef lf
            CreateProgramMenu();
            CreateStatusBar();

            UpdateUI();

            break;
        }
        case WM_SIZE:
            MoveWindow(hStatusBar, 0, HIWORD(lParam) + lfFont.lfHeight - 2, LOWORD(lParam), -lfFont.lfHeight, SWP_NOZORDER);
            break;
        case WM_COMMAND:
            if (!(lParam == 0 && HIWORD(wParam) == 0))
                break;
            switch (LOWORD(wParam))
            {
                case IDM_INSTALLDRIVER:
                    InstallUsbmmiddDriver();
                    break;
                case IDM_ADDDISPLAY:
                    AddVirtualDisplay();
                    break;
                case IDM_REMOVEDISPLAY:
                    RemoveVirtualDisplay();
                    break;
                case IDM_EXIT:
                    PostQuitMessage(0);
                    break;
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hWnd, uMsg, wParam, lParam);
    }
    return 0;
}

void CreateMainWindow()
{
    WNDCLASSW wc = {
        .lpszClassName = L"vdmwnd",
        .lpfnWndProc = WndProc,
        .hCursor = LoadCursorW(NULL, (LPWSTR)IDC_ARROW),
        .hIcon = LoadIconW(GetModuleHandleW(NULL), (LPWSTR)IDI_ICON1),
        .style = CS_VREDRAW | CS_HREDRAW,
        .hbrBackground = (HBRUSH)COLOR_WINDOW
    };
    RegisterClassW(&wc);

    CreateWindowW(wc.lpszClassName, szLoc[1], WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, NULL, NULL);
}

int WinMainCRTStartup()
{
    hStdError = GetStdHandle(STD_ERROR_HANDLE);
    LoadLocale(L"locale.lng");

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    // if system is 64 bit
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
    {
        // replace spaces by '64'
        szDeviceInstaller[15] = L'6';
        szDeviceInstaller[16] = L'4';
    }
    else
    {
        // remove spaces
        szDeviceInstaller[15] = szDeviceInstaller[17];
        szDeviceInstaller[16] = szDeviceInstaller[18];
        szDeviceInstaller[17] = szDeviceInstaller[19];
        szDeviceInstaller[18] = szDeviceInstaller[20];
        szDeviceInstaller[19] = szDeviceInstaller[20] = 0;
    }

    RTL_OSVERSIONINFOEXW osVer;
    RtlGetVersion(&osVer);
    // Lower than Windows 10 20H2
    if (osVer.dwBuildNumber < 19042)
        MessageBoxW(NULL, szLoc[0], NULL, 0);

    InitRunProcessPipes();

    CreateMainWindow();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    FreeLocale();
    CloseRunProcessPipes();
    return msg.wParam;
}
