#pragma once

class CShellDlg
{
public:
    CShellDlg()
    {
        m_hDlg = NULL;
        m_hEdit = NULL;
        m_OldEditProc = NULL;
        m_LastSel = m_Sel = 0;
    }
    ~CShellDlg()
    {
        SendMessage(m_hDlg,WM_CLOSE,0,0);
    }
    BOOL CreateDlg();
    BOOL ProcessRecvData(WCHAR *data);
    BOOL CALLBACK DialogProc(
        HWND hwndDlg, 
        UINT uMsg, 
        WPARAM wParam, 
        LPARAM lParam);
    BOOL CALLBACK EditProc(
        HWND hwndDlg, 
        UINT uMsg, 
        WPARAM wParam, 
        LPARAM lParam);
    //private:
    HWND m_hDlg;
    HWND m_hEdit;
    int  m_LastSel;
    int  m_Sel;
    WNDPROC  m_OldEditProc;
};
