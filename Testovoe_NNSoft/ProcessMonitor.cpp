#include "ProcessMonitor.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <cstdlib>
#include"Testovoe_NNSoft.h"

const std::string ProcessMonitor::ENCRYPTION_KEY = "elizoorgelizoorg";

ProcessMonitor::ProcessMonitor(HINSTANCE hInstance)
    : hInstance(hInstance), hMainWnd(nullptr), isInTray(false), isAdmin(false), hMutex(nullptr) {

    hMutex = CreateMutex(NULL, TRUE, L"ProcessMonitorApp");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBox(NULL, L"Application is already running!", L"Error", MB_ICONERROR);
        exit(0);
    }
}

ProcessMonitor::~ProcessMonitor() {
    RemoveTrayIcon();
    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }
}

bool ProcessMonitor::Initialize() {
    // Инициализация common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    // Регистрация класса окна
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_TESTOVOENNSOFT));
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = L"ProcessMonitor";
    wc.hIconSm = LoadIcon(wc.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    if (!RegisterClassEx(&wc)) {
        MessageBox(NULL, L"Window Registration Failed!", L"Error", MB_ICONERROR);
        return false;
    }

    // Проверяем права администратора
    isAdmin = IsRunningAsAdmin();

    // Создание главного окна
    hMainWnd = CreateWindowExW(
        0,
        L"ProcessMonitor",
        L"Process Monitor",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        NULL, NULL, hInstance, this
    );

    if (!hMainWnd) {
        MessageBox(NULL, L"Window Creation Failed!", L"Error", MB_ICONERROR);
        return false;
    }

    ShowWindow(hMainWnd, SW_SHOW);
    UpdateWindow(hMainWnd);

    return true;
}

int ProcessMonitor::Run() {
    MSG msg;

    SetTimer(hMainWnd, 1, 10000, NULL);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

LRESULT CALLBACK ProcessMonitor::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    ProcessMonitor* pThis = nullptr;

    if (msg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (ProcessMonitor*)pCreate->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pThis);
    }
    else {
        pThis = (ProcessMonitor*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }

    if (pThis) {
        return pThis->HandleMessage(hWnd, msg, wParam, lParam);
    }

    return DefWindowProc(hWnd, msg, wParam, lParam);
}

    

LRESULT ProcessMonitor::HandleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateControls(hWnd);
        RefreshProcessList();
        ShowTrayIcon();
        break;

    case WM_COMMAND:
        if (lParam != 0) {
            if (LOWORD(wParam) == 1) { 
                EndSelectedProcess();
            }
            else if (LOWORD(wParam) == 2) { 
                RestartAsAdmin();
            }
            else if (LOWORD(wParam) == 3) { 
                std::thread([this]() { SendDataToServer(); }).detach();
            }
            else if (LOWORD(wParam) == 4) {
                std::thread([this]() { GetDataFromServer(); }).detach();
            }
        }
        else {
            switch (LOWORD(wParam)) {
            case 100:
                RestoreFromTray();
                break;
            case 101:
                PostQuitMessage(0);
                break;
            }
        }
        break;

    case WM_TIMER:
        if (wParam == 1) {
            RefreshProcessList();
        }
        break;

    case WM_SIZE:
    {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        int listHeight = height - 120;
        if (listHeight < 200) listHeight = 200;

       
        int buttonTop = listHeight + 20;
        int buttonHeight = 30;
        int buttonSpacing = 10;

        
        int totalButtonWidth = width - 40 ;
        int buttonWidth = (totalButtonWidth - 3 * buttonSpacing) / 4;
        if (buttonWidth > 200) buttonWidth = 200;
        if (buttonWidth < 100) buttonWidth = 100;

      
        int listWidth = width - 20;

        
        MoveWindow(hProcessList, 10, 10, listWidth, listHeight, TRUE);

        int xPos = 10;
        MoveWindow(hEndTaskBtn, xPos, buttonTop, buttonWidth, buttonHeight, TRUE);
        xPos += buttonWidth + buttonSpacing;

        MoveWindow(hRestartAdminBtn, xPos, buttonTop, buttonWidth, buttonHeight, TRUE);
        xPos += buttonWidth + buttonSpacing;

        MoveWindow(hSendDataBtn, xPos, buttonTop, buttonWidth, buttonHeight, TRUE);
        xPos += buttonWidth + buttonSpacing;

        MoveWindow(hGetDataBtn, xPos, buttonTop, buttonWidth, buttonHeight, TRUE);

       
        if (hProcessList) {
            int nameColumnWidth = listWidth - 120; 
            if (nameColumnWidth < 200) nameColumnWidth = 200;

            ListView_SetColumnWidth(hProcessList, 0, 100); 
            ListView_SetColumnWidth(hProcessList, 1, nameColumnWidth); 
        }

        InvalidateRect(hWnd, NULL, TRUE);
        UpdateWindow(hWnd);

    }
    break;
    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* pMMI = (MINMAXINFO*)lParam;
        pMMI->ptMinTrackSize.x = 600;
        pMMI->ptMinTrackSize.y = 400;
        pMMI->ptMaxTrackSize.x = GetSystemMetrics(SM_CXSCREEN);
        pMMI->ptMaxTrackSize.y = GetSystemMetrics(SM_CYSCREEN);
    }
    break;
    case WM_SYSCOMMAND:
        if (wParam == SC_MINIMIZE || wParam == SC_CLOSE) {
            MinimizeToTray();
            return 0;
        }
        return DefWindowProc(hWnd, msg, wParam, lParam);
        break;
    case WM_DESTROY:
        RemoveTrayIcon();
        PostQuitMessage(0);
        break;
    case WM_USER + 1:
        switch (lParam) {
        case WM_RBUTTONUP:
        case WM_LBUTTONUP:
        {
            POINT pt;
            GetCursorPos(&pt);

            HMENU hMenu = CreatePopupMenu();
            InsertMenu(hMenu, 0, MF_BYPOSITION | MF_STRING, 100, L"Show");
            InsertMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 101, L"Exit");

            SetForegroundWindow(hWnd);
            TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_LEFTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
        break;
        }
        break;
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }

    return 0;
}

void ProcessMonitor::CreateControls(HWND hWnd) {
    hProcessList = CreateWindowEx(0, WC_LISTVIEW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER | LVS_SHOWSELALWAYS |
        LVS_AUTOARRANGE | WS_VSCROLL | WS_HSCROLL,
        10, 10, 760, 400, hWnd, NULL, hInstance, NULL);


    ListView_SetExtendedListViewStyle(hProcessList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);


    LVCOLUMN lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    lvc.iSubItem = 0;
    lvc.pszText = (LPWSTR)L"PID";
    lvc.cx = 100;
    ListView_InsertColumn(hProcessList, 0, &lvc);

    lvc.iSubItem = 1;
    lvc.pszText = (LPWSTR)L"Name";
    lvc.cx = 600;
    ListView_InsertColumn(hProcessList, 1, &lvc);


    hEndTaskBtn = CreateWindow(L"BUTTON", L"End Task",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 420, 100, 30, hWnd, (HMENU)1, hInstance, NULL);

    hRestartAdminBtn = CreateWindow(L"BUTTON", L"Restart with Admin",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        120, 420, 150, 30, hWnd, (HMENU)2, hInstance, NULL);

    hSendDataBtn = CreateWindow(L"BUTTON", L"Send Data",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        280, 420, 100, 30, hWnd, (HMENU)3, hInstance, NULL);

    hGetDataBtn = CreateWindow(L"BUTTON", L"Get Data",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        390, 420, 100, 30, hWnd, (HMENU)4, hInstance, NULL);

 
    if (isAdmin) {
        EnableWindow(hRestartAdminBtn, FALSE);
        SetWindowText(hRestartAdminBtn, L"Admin Mode");
    }
}

void ProcessMonitor::RefreshProcessList() {
    processes.clear();
    ListView_DeleteAllItems(hProcessList);

 
    DWORD pids[1024], cbNeeded;
    if (!EnumProcesses(pids, sizeof(pids), &cbNeeded)) {
        return;
    }

    DWORD cProcesses = cbNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < cProcesses; i++) {
        if (pids[i] != 0) {
            std::wstring name = GetProcessName(pids[i]);
            if (!name.empty()) {
                processes[pids[i]] = name;
                //std::wcout << name << std::endl;
              
                LVITEM lvi = {};
                lvi.mask = LVIF_TEXT | LVIF_PARAM;
                lvi.iItem = ListView_GetItemCount(hProcessList);
                lvi.lParam = pids[i];

             
                lvi.iSubItem = 0;
                std::wstring pidStr = std::to_wstring(pids[i]);
                lvi.pszText = const_cast<LPWSTR>(pidStr.c_str());
                int itemIndex = ListView_InsertItem(hProcessList, &lvi);

             
                ListView_SetItemText(hProcessList, itemIndex, 1, const_cast<LPWSTR>(name.c_str()));
            }
        }
    }
}

std::wstring ProcessMonitor::GetProcessName(DWORD pid) {
    if (pid == 0) return L"System Idle Process";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess == NULL) {
    
            return L"Access Denied";
        }
    }

    WCHAR szProcessName[MAX_PATH] = L"<unknown>";
    DWORD size = MAX_PATH;

   
    if (QueryFullProcessImageName(hProcess, 0, szProcessName, &size)) {

        
        std::wstring fullPath(szProcessName);
        size_t lastSlash = fullPath.find_last_of(L'\\');
        if (lastSlash != std::wstring::npos) {
            CloseHandle(hProcess);
            //std::wcout << "Process name is" << fullPath.substr(lastSlash + 1) << std::endl;
            return fullPath.substr(lastSlash + 1);
        }
        CloseHandle(hProcess);
        return fullPath;
    }

    HMODULE hMod;
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(WCHAR));
    }

    CloseHandle(hProcess);
    return std::wstring(szProcessName);
}

void ProcessMonitor::EndSelectedProcess() {
    int iSelected = ListView_GetNextItem(hProcessList, -1, LVNI_SELECTED);
    if (iSelected == -1) {
        MessageBox(hMainWnd, L"Please select a process first", L"Info", MB_ICONINFORMATION);
        return;
    }

    WCHAR szPid[256];
    ListView_GetItemText(hProcessList, iSelected, 0, szPid, sizeof(szPid) / sizeof(WCHAR));

    DWORD pid = _wtoi(szPid);
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if (hProcess == NULL) {
        MessageBox(hMainWnd, L"Failed to open process", L"Error", MB_ICONERROR);
        return;
    }

    if (TerminateProcess(hProcess, 0)) {
        MessageBox(hMainWnd, L"Process terminated successfully", L"Success", MB_ICONINFORMATION);
        RefreshProcessList();
    }
    else {
        MessageBox(hMainWnd, L"Failed to terminate process", L"Error", MB_ICONERROR);
    }

    CloseHandle(hProcess);
}

void ProcessMonitor::RestartAsAdmin() {
    WCHAR szPath[MAX_PATH];
    GetModuleFileName(NULL, szPath, MAX_PATH);

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = szPath;
    sei.hwnd = hMainWnd;
    sei.nShow = SW_NORMAL;

    if (ShellExecuteEx(&sei)) {
        PostQuitMessage(0);
    }
    else {
        MessageBox(hMainWnd, L"Failed to restart as administrator", L"Error", MB_ICONERROR);
    }
}

std::vector<std::wstring> ProcessMonitor::GetProcessDLLs(DWORD pid) {
    std::vector<std::wstring> dlls;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return dlls;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
                dlls.push_back(szModName);
            }
        }
    }

    CloseHandle(hProcess);
    return dlls;
}

std::string ProcessMonitor::GenerateRID() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    return std::to_string(millis) + "_" + std::to_string(dis(gen));
}

std::string ProcessMonitor::XOREncryptDecrypt(const std::string& input, const std::string& key) {
    std::string output = input;

    for (size_t i = 0; i < input.length(); ++i) {
        output[i] = input[i] ^ key[i % key.length()];
    }

    return output;
}

std::string ProcessMonitor::EncryptString(const std::string& input) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::string randomPrefix;
    for (int i = 0; i < 8; ++i) {
        randomPrefix += static_cast<char>(dis(gen));
    }

    std::string dataWithRandom = randomPrefix + input;
    return XOREncryptDecrypt(dataWithRandom, ENCRYPTION_KEY);
}

std::string ProcessMonitor::DecryptString(const std::string& input) {
    std::string decrypted = XOREncryptDecrypt(input, ENCRYPTION_KEY);

    if (decrypted.length() > 8) {
        return decrypted.substr(8);
    }
    return "";
}





std::string ProcessMonitor::base64_encode(const std::string& input) {
    std::string output;
    int val = 0, valb = -6;

    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        output.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (output.size() % 4) {
        output.push_back('=');
    }

    return output;
}


std::string ProcessMonitor::MakeHTTPRequest(const std::string& data) {
    HINTERNET hInternet = InternetOpen(L"ProcessMonitor", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "";

    HINTERNET hConnect = InternetConnect(hInternet, L"172.245.127.93", INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "";
    }

    HINTERNET hRequest = HttpOpenRequest(hConnect, L"POST", L"/p/applicants.php", NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    std::wstring headers = L"Content-Type: application/json";

    BOOL bSent = HttpSendRequest(hRequest, headers.c_str(), headers.length(), (LPVOID)data.c_str(), data.length());

    std::string response;
    if (bSent) {
        DWORD dwSize;
        char buffer[4096];

        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &dwSize) && dwSize > 0) {
            buffer[dwSize] = '\0';
            response += buffer;
        }
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return response;
}

void ProcessMonitor::SendDataToServer() {
    int iSelected = ListView_GetNextItem(hProcessList, -1, LVNI_SELECTED);
    if (iSelected == -1) {
        MessageBox(hMainWnd, L"Please select a process first", L"Info", MB_ICONINFORMATION);
        return;
    }

    WCHAR szPid[256];
    ListView_GetItemText(hProcessList, iSelected, 0, szPid, sizeof(szPid) / sizeof(WCHAR));
    DWORD pid = _wtoi(szPid);

    auto dlls = GetProcessDLLs(pid);
    if (dlls.empty()) {
        MessageBox(hMainWnd, L"No DLLs found for selected process", L"Info", MB_ICONINFORMATION);
        return;
    }


    std::wstring dllNames;
    for (const auto& dll : dlls) {
        dllNames += dll + L";";
    }

    std::string dllNamesUTF8 = WideToUTF8(dllNames);
    std::string encryptedData = EncryptString(dllNamesUTF8);
    std::string encryptedBase64 = base64_encode(encryptedData);
    std::string rid = GenerateRID();


    json request;
    request["cmd"] = 1;
    request["rid"] = rid;
    request["data"] = encryptedBase64;

    std::string requestStr = request.dump();
    std::string response = MakeHTTPRequest(requestStr);

    if (!response.empty()) {
        try {
            json responseJson = json::parse(response);
            if (responseJson.contains("status") && responseJson["status"] == "true") {
                MessageBox(hMainWnd, L"Data sent successfully", L"Success", MB_ICONINFORMATION);
            }
            else {
                MessageBox(hMainWnd, L"Failed to send data", L"Error", MB_ICONERROR);
            }
        }
        catch (...) {
            MessageBox(hMainWnd, L"Invalid server response", L"Error", MB_ICONERROR);
        }
    }
    else {
        MessageBox(hMainWnd, L"Failed to connect to server", L"Error", MB_ICONERROR);
    }
}

void ProcessMonitor::GetDataFromServer() {
    std::string rid = GenerateRID();

    json request;
    request["cmd"] = 2;
    request["rid"] = rid;

    std::string requestStr = request.dump();
    std::string response = MakeHTTPRequest(requestStr);

    if (!response.empty()) {
        try {
            json responseJson = json::parse(response);
            if (responseJson.contains("data")) {
                std::string encryptedData = responseJson["data"];
                std::string decryptedData = DecryptString(encryptedData);

                std::wstring message = L"Received data:\n" + UTF8ToWide(decryptedData);
                MessageBox(hMainWnd, message.c_str(), L"Received Data", MB_ICONINFORMATION);
            }
            else {
                MessageBox(hMainWnd, L"No data received from server", L"Info", MB_ICONINFORMATION);
            }
        }
        catch (...) {
            MessageBox(hMainWnd, L"Invalid server response", L"Error", MB_ICONERROR);
        }
    }
    else {
        MessageBox(hMainWnd, L"Failed to connect to server", L"Error", MB_ICONERROR);
    }
}

bool ProcessMonitor::IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

std::string ProcessMonitor::WideToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return "";

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

std::wstring ProcessMonitor::UTF8ToWide(const std::string& str) {
    if (str.empty()) return L"";

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

void ProcessMonitor::ShowTrayIcon() {
    NOTIFYICONDATA nid = {};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hMainWnd;
    nid.uID = 1455;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_USER + 1;

    // Загружаем иконку
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_SMALL));
    if (!nid.hIcon) {
        nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    }

    wcscpy_s(nid.szTip, L"Process Monitor");

    Shell_NotifyIcon(NIM_DELETE, &nid);


    if (Shell_NotifyIcon(NIM_ADD, &nid)) {
        return;
    }


    nid.uVersion = NOTIFYICON_VERSION_4;
    if (Shell_NotifyIcon(NIM_ADD, &nid)) {
        Shell_NotifyIcon(NIM_SETVERSION, &nid);
        return;
    }

}

void ProcessMonitor::RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

void ProcessMonitor::MinimizeToTray() {
    ShowWindow(hMainWnd, SW_HIDE);
    isInTray = true;
}

void ProcessMonitor::RestoreFromTray() {
    ShowWindow(hMainWnd, SW_SHOW);
    ShowWindow(hMainWnd, SW_RESTORE);
    SetForegroundWindow(hMainWnd);
    isInTray = false;
}