#include <Windows.h>
#include <iostream>


HWND clipboard_hwnd = nullptr;
HWND hWndNewNext = nullptr;
char clipText[0x1000];

HWND __cdecl create_window(
    const wchar_t* class_name,
    const wchar_t* window_name,
    LRESULT(__stdcall* callback)(HWND, UINT, WPARAM, LPARAM))
{
    WNDCLASSEXW wnd_class;
    HINSTANCE hInstance;

    hInstance = GetModuleHandleA(0);
    wnd_class.cbSize = sizeof(WNDCLASSEX);
    wnd_class.style = CS_HREDRAW | CS_VREDRAW;
    wnd_class.lpfnWndProc = callback;
    wnd_class.cbClsExtra = 0;
    wnd_class.cbWndExtra = 0;
    wnd_class.hInstance = hInstance;
    wnd_class.hIcon = LoadIconA(0, MAKEINTRESOURCEA(32512));
    wnd_class.hCursor = LoadCursorA(0, MAKEINTRESOURCEA(32512));
    wnd_class.hbrBackground = (HBRUSH)6;
    wnd_class.lpszMenuName = 0;
    wnd_class.lpszClassName = class_name;
    wnd_class.hIconSm = 0;
    RegisterClassExW(&wnd_class);
    return CreateWindowExW(0, class_name, window_name, WS_OVERLAPPEDWINDOW, 0x80000000, 0, 0x80000000, 0, 0, 0, hInstance, 0);
}


LRESULT __stdcall clipwnd_callback(HWND hWndNewViewer, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    switch (Msg)
    {
    case WM_CREATE:
        hWndNewNext = SetClipboardViewer(hWndNewViewer);
        break;

    case WM_CHANGECBCHAIN:
        if ((HWND)wParam == hWndNewNext)
            hWndNewNext = (HWND)lParam;
        else if(hWndNewNext != NULL)
            SendMessage(hWndNewNext, Msg, wParam, lParam);
        break;

    case WM_DRAWCLIPBOARD:
    {
        if (hWndNewNext)
            SendMessage(hWndNewNext, Msg, wParam, lParam);

        static UINT auPriorityList[] = { CF_TEXT };
        HANDLE hMem = nullptr;

        if (GetPriorityClipboardFormat(auPriorityList, 1) == CF_TEXT)
        {
            if (OpenClipboard(hWndNewViewer))
            {
                if ((hMem = GetClipboardData(CF_TEXT)) != NULL)
                {
                    size_t objSize = GlobalSize(hMem);
                    void* pMem = GlobalLock(hMem);
                    size_t copySize = 0;

                    if (objSize < 4096)
                        copySize = objSize;
                    else
                        copySize = 4095;

                    memmove((void*)clipText, pMem, copySize);
                    clipText[copySize] = '\x0';
                    GlobalUnlock(hMem);
                    CloseClipboard();
                    std::cout << clipText << std::endl;
                }
            }
        }

        break;
    }

    case WM_DESTROY:
        if(hWndNewViewer)
            ChangeClipboardChain(hWndNewViewer, hWndNewNext);
        break;

    default:
        break;
    }

    return  DefWindowProcA(hWndNewViewer, Msg, wParam, lParam);
}

void exec_clipboard_mon()
{
    if (!clipboard_hwnd)
    {
        clipboard_hwnd = (HWND)create_window(L"clipboard_monitor_class", L"clipboard_monitor_name", clipwnd_callback);

        if (!clipboard_hwnd)
            std::cout << "create window error " << GetLastError() << std::endl;
    }
}


int main()
{
    MSG msg;

    exec_clipboard_mon();

    while (BOOL bRet = GetMessage(&msg, 0, 0, 0)) 
    {
        if (bRet == -1)
        {
            printf("GetMessage error 0x%08X\n", GetLastError()); return 3;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
