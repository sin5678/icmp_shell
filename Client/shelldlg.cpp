#include <Windows.h>
#include <stdio.h>
#include "shelldlg.h"
#include  "Buffer.h"
#include <Richedit.h>
#include "resource.h"


BOOL CALLBACK _EditProc(
    HWND hwndDlg, 
    UINT uMsg, 
    WPARAM wParam, 
    LPARAM lParam
    )
{
    CShellDlg *dlg = (CShellDlg *)GetWindowLong(hwndDlg,GWL_USERDATA);
    return dlg->EditProc(hwndDlg,uMsg,wParam,lParam);
}

BOOL CALLBACK _DialogProc(
    HWND hwndDlg, 
    UINT uMsg, 
    WPARAM wParam, 
    LPARAM lParam
    )
{
    CShellDlg  *pdlg;// = (CShellDlg *)lParam;
    switch(uMsg)
    {
    case WM_INITDIALOG:
        {
            pdlg = (CShellDlg *)lParam;
            pdlg->m_hDlg = hwndDlg;
            SetWindowLong(hwndDlg,GWL_USERDATA,(long)pdlg);
            pdlg->m_hEdit = GetDlgItem(pdlg->m_hDlg,IDC_EDIT);
            ///SetFocus(pdlg->m_hEdit);
            SendMessage(pdlg->m_hEdit,EM_LIMITTEXT,-1,0);
            SendMessage(pdlg->m_hEdit,EM_SETEVENTMASK,0,(LPARAM)ENM_SELCHANGE|ENM_CHANGE);
            SetWindowLong(pdlg->m_hEdit,GWL_USERDATA,(long)pdlg);
            pdlg->m_OldEditProc = (WNDPROC)SetWindowLong(pdlg->m_hEdit,GWL_WNDPROC,(long)_EditProc);
            return TRUE;
        }
        break;
    default:
        {
            pdlg = (CShellDlg *)GetWindowLong(hwndDlg,GWL_USERDATA);
            return pdlg->DialogProc(hwndDlg,uMsg,wParam,lParam);
        }
        break;
    }
    return FALSE;
}

LRESULT CreateConsoleWindow(void *lparam)
{
    CShellDlg *dlg = (CShellDlg *)lparam;
    dlg->m_hDlg = CreateDialogParam (GetModuleHandle(NULL),MAKEINTRESOURCE(IDD_DIALOG),GetDesktopWindow(),_DialogProc,(long)dlg);
    //SetForegroundWindow(dlg->m_hDlg);
    return 0;
}

BOOL CALLBACK CShellDlg::EditProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static BOOL isfirst = TRUE;
    switch(uMsg)
    {
    case WM_CHAR:
        {
            SendMessage(m_hEdit,EM_GETSEL,(WPARAM)&m_Sel,0);
            //printf("%d %d \n",m_LastSel,m_Sel);
            switch(wParam)
            {
            case VK_RETURN:
                {
                    int len;
                    WCHAR *str;
                    CBuffer buffer;
                    //BYTE cmd = COMMAND_CMD;
                    WCHAR end = L'\0';

                    if(m_Sel - m_LastSel > 0)
                    {
                        len = SendMessageW(m_hEdit,WM_GETTEXTLENGTH,0,0);
                        if(len)
                        {
                            str = (WCHAR *)malloc((len + 1)*sizeof(WCHAR));
                            SendMessageW(m_hEdit,WM_GETTEXT,(WPARAM)(len+1),(LPARAM)str);
                            buffer.ClearBuffer();
                            //buffer.Write(&cmd,1);
                            len = wcslen(str+m_LastSel) + 1;
                            *(str + m_LastSel + wcslen(str+m_LastSel)) = L'\n';
                            buffer.Write((LPBYTE)(str + m_LastSel),len * sizeof(WCHAR));
                            buffer.Write((LPBYTE)&end,2);
                            printf("cmdshell send cmd :--%S--\n",(WCHAR *)buffer.GetBuffer(1));
                            //post_send(task->client,buffer.GetBuffer(0),buffer.GetBufferLen());
                            free(str);
                        }
                        //SendMessage(m_hEdit,EM_SETSEL,m_LastSel,m_Sel);
                        //SendMessage(m_hEdit,EM_GETSELTEXT,0,(LPARAM)str); Edit Ctrl 不支持这个消息
                        //SendMessage(m_hEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)0);
                    }
                    m_LastSel = m_Sel;
                }
                break;
            case  VK_ESCAPE:
                {
                    return TRUE;
                }
                break;
            case VK_BACK:  //不能让光标删除已存在的字 。。
                {
                    if (m_Sel <= m_LastSel)
                    {
                        return TRUE;
                    }
                }
                break;
            default:
                {
                    //		if(pMsg->wParam <30 || pMsg->wParam >126)
                    //			return TRUE;
                    if(isfirst)
                    {
                    }
                }
                break;
            }
        }
        break;
    case WM_LBUTTONDOWN:  //屏蔽鼠标消息
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONDBLCLK:
        return TRUE;
    default:
        //printf("recv msg %x \n",uMsg);
        break;
    }
    return m_OldEditProc(hwndDlg,uMsg,wParam,lParam);
}

BOOL CALLBACK  CShellDlg::DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_COMMAND:
        {
            switch((int)wParam)
            {
            case EN_CHANGE:
                {
                    printf("EN_CHANGE \n");
                }
                break;
            default:
                break;
            }
        }
        break;
    case WM_SIZE:
    case WM_SIZING:
        {
            RECT	rectClient;
            GetClientRect(hwndDlg,&rectClient);
            MoveWindow(GetDlgItem(hwndDlg,IDC_EDIT),0,0, rectClient.right,rectClient.bottom,TRUE);
        }
        break;
    case WM_CHAR:
        {
            //对话框收不到这个消息的  
            //printf("recv char : %d  %c  \n",wParam,wParam);
        }
        break;
    case WM_NOTIFY:
        {
            NMHDR *hd = (NMHDR *)lParam;
            switch(hd->code)
            {
            case EN_SELCHANGE:
                {
                    //EDIT 
                    printf("EN_SELCHANGE \n");
                }
            default:
                break;
            }
        }
        break;
    case WM_CTLCOLOREDIT:
        {
            COLORREF clr = RGB(255, 255, 255);
            HDC hDc = (HDC)wParam;
            SetTextColor(hDc,clr);   //设置白色的文本
            clr = RGB(0,0,0);
            SetBkColor(hDc,clr);     //设置黑色的背景
            return (int)CreateSolidBrush(clr);  //作为约定，返回背景色对应的刷子句柄
        }
        break;
    case WM_CLOSE:
        {
            //任务结束了 
            //SinRAT_Disconnect(task->client);
            DestroyWindow(m_hDlg);
        }
        break;
    case WM_DESTROY:
        break;
    default:
        break;
    }
    return FALSE;
}


BOOL CShellDlg::CreateDlg()
{
    //SendMessage(hMainWnd,WM_EXEC_CALLBACK,(WPARAM)CreateConsoleWindow,(LPARAM)this);  //创建对话框
    return TRUE;
}


BOOL CShellDlg::ProcessRecvData(WCHAR *data)
{
    WCHAR *str;
    int len;
    CBuffer buffer;
    buffer.ClearBuffer();
    printf("shellplugin: %S  \n",data);
    //收到第一个消息的时候 打开 对话框
    if(NULL == m_hDlg)
    {
        CreateDlg();
        UpdateWindow(m_hDlg);
        ShowWindow(m_hDlg,SW_SHOW);
        SetForegroundWindow(m_hDlg);
    }
    len = SendMessageW(m_hEdit,WM_GETTEXTLENGTH,0,0);
    if(len)
    {
        str = (WCHAR *)malloc((len + 1)*sizeof(WCHAR));
        SendMessageW(m_hEdit,WM_GETTEXT,(WPARAM)(len+1),(LPARAM)str);
        buffer.Write((LPBYTE)str,wcslen(str) * sizeof(WCHAR));
        free(str);
    }
    buffer.Write((LPBYTE)data,(wcslen(data)+1) * sizeof(WCHAR));
    //SendMessageW(m_hEdit,WM_SETTEXT,0,(LPARAM)buffer.GetBuffer());
    ///把光标放到末尾 
    SendMessage(m_hEdit, EM_SETSEL, 0, -1);//select all the text
    SendMessage(m_hEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)0);//deselect any selection
    SendMessage(m_hEdit, EM_REPLACESEL, TRUE, (LPARAM)buffer.GetBuffer());
    SendMessage(m_hEdit, EM_GETSEL, (WPARAM)&m_LastSel,0);
    if(GetForegroundWindow() != m_hDlg)
        FlashWindow(m_hDlg, TRUE);
    return TRUE;
}

