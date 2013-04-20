#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

HANDLE (__stdcall *pf_IcmpCreateFile)(void) = NULL;
DWORD (__stdcall *pf_IcmpSendEcho)(
    _In_      HANDLE IcmpHandle,
    _In_      IPAddr DestinationAddress,
    _In_      LPVOID RequestData,
    _In_      WORD RequestSize,
    _In_opt_  PIP_OPTION_INFORMATION RequestOptions,
    _Out_     LPVOID ReplyBuffer,
    _In_      DWORD ReplySize,
    _In_      DWORD Timeout
    ) = NULL;

BOOL load_deps()
{
    HMODULE lib;
    lib = LoadLibraryA("iphlpapi.dll");
    if (lib != NULL) {
        pf_IcmpCreateFile = GetProcAddress(lib, "IcmpCreateFile");
        pf_IcmpSendEcho = GetProcAddress(lib, "IcmpSendEcho");
        if (pf_IcmpCreateFile && pf_IcmpSendEcho) 
        {
            return TRUE;
        }
    } 
    // windows 2000  上面这个函数实在 ICMP.dll 里
    lib = LoadLibraryA("ICMP.DLL");
    if (lib != NULL)
    {
        pf_IcmpCreateFile = GetProcAddress(lib, "IcmpCreateFile");
        pf_IcmpSendEcho = GetProcAddress(lib, "IcmpSendEcho");
        if (pf_IcmpCreateFile && pf_IcmpSendEcho) 
        {
            return TRUE;
        }
    }

    printf("failed to load functions (%u) \n", GetLastError());

    return FALSE;
}

int __cdecl main(int argc, char **argv)  
{

    // Declare and initialize variables

    HANDLE hIcmpFile;
    unsigned long ipaddr = INADDR_NONE;
    DWORD dwRetVal = 0;
    char SendData[32] = "Data Buffer";
    LPVOID ReplyBuffer = NULL;
    DWORD ReplySize = 0;

    // Validate the parameters
    if (argc != 2) {
        printf("usage: %s IP address\n", argv[0]);
        return 1;
    }

    ipaddr = inet_addr(argv[1]);
    if (ipaddr == INADDR_NONE) {
        printf("usage: %s IP address\n", argv[0]);
        return 1;
    }

    hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("\tUnable to open handle.\n");
        printf("IcmpCreatefile returned error: %ld\n", GetLastError() );
        return 1;
    }    

    ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
    ReplyBuffer = (VOID*) malloc(ReplySize);
    if (ReplyBuffer == NULL) {
        printf("\tUnable to allocate memory\n");
        return 1;
    }  

    dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData), 
        NULL, ReplyBuffer, ReplySize, -1);
    if (dwRetVal != 0)
    {
        PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
        struct in_addr ReplyAddr;
        ReplyAddr.S_un.S_addr = pEchoReply->Address;
        printf("\tSent icmp message to %s\n", argv[1]);
        if (dwRetVal > 1) {
            printf("\tReceived %ld icmp message responses\n", dwRetVal);
            printf("\tInformation from the first response:\n"); 
        }    
        else 
        {    
            printf("\tReceived %ld icmp message response\n", dwRetVal);
            printf("\tInformation from this response:\n"); 
        }    
        printf("\t  Received from %s\n", inet_ntoa( ReplyAddr ) );
        printf("\t  Status = %ld\n", 
            pEchoReply->Status);
        printf("\t  Roundtrip time = %ld milliseconds\n", 
            pEchoReply->RoundTripTime);
    }
    else {
        printf("\tCall to IcmpSendEcho failed.\n");
        printf("\tIcmpSendEcho returned error: %ld\n", GetLastError() );
        return 1;
    }
    return 0;
}    