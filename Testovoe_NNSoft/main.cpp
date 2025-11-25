#include "ProcessMonitor.h"
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    ProcessMonitor app(hInstance);

    if (!app.Initialize()) {
        return -1;
    }

    return app.Run();

    FreeConsole();
}