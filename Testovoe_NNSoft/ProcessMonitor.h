#pragma once

#include <windows.h>
#include <commctrl.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <map>
#include <thread>
#include <chrono>
#include <random>
#include <wincrypt.h>
#include <wininet.h>
#include "json.hpp"
#include <shellapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "comctl32.lib")

using json = nlohmann::json;

class ProcessMonitor {
private:
    HWND hMainWnd;
    HWND hProcessList;
    HWND hEndTaskBtn;
    HWND hRestartAdminBtn;
    HWND hSendDataBtn;
    HWND hGetDataBtn;

    HINSTANCE hInstance;
    NOTIFYICONDATA nid;
    bool isInTray;

    std::map<DWORD, std::wstring> processes;
    bool isAdmin;
    HANDLE hMutex;

    // Константы для шифрования
    static const std::string ENCRYPTION_KEY;

public:
    ProcessMonitor(HINSTANCE hInstance);
    ~ProcessMonitor();

    bool Initialize();
    int Run();

private:
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void CreateControls(HWND hWnd);
    void RefreshProcessList();
    void EndSelectedProcess();
    void RestartAsAdmin();
    void SendDataToServer();
    void GetDataFromServer();
    void ShowTrayIcon();
    void RemoveTrayIcon();
    void MinimizeToTray();
    void RestoreFromTray();

    // Методы для работы с процессами
    std::wstring GetProcessName(DWORD pid);
    std::vector<std::wstring> GetProcessDLLs(DWORD pid);

    // Методы для работы с сетью и шифрованием
    std::string GenerateRID();
    std::string EncryptString(const std::string& input);
    std::string DecryptString(const std::string& input);
    std::string XOREncryptDecrypt(const std::string& input, const std::string& key);
    std::string MakeHTTPRequest(const std::string& data);

    // Вспомогательные методы
    bool IsRunningAsAdmin();
    std::string WideToUTF8(const std::wstring& wstr);
    std::wstring UTF8ToWide(const std::string& str);



    std::string base64_encode(const std::string& input);

    const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
};


