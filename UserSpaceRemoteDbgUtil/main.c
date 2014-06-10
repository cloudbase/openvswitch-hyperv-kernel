/*
Copyright 2014 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <WinSock2.h>
#include <stdio.h>
#include <cassert>

#include "Interface.h"

SOCKET g_serverSock = INVALID_SOCKET;

#define _IP_192_168_9_2		0x0209a8c0
#define _IP_192_168_81_1	0x0151a8c0

static UINT32 g_targetIp = _IP_192_168_81_1;
static UINT16 g_targetPort = 9000;

#if 0
SOCKET Socket_Reset(SOCKET s)
{
    SOCKET conn = INVALID_SOCKET;
    SOCKADDR_IN clientAddr;

    printf(__FUNCTION__ " called!\n");
    closesocket(s);

    int addrlen = sizeof(clientAddr);

    while (conn == INVALID_SOCKET)
    {
        printf("accepting\n");

        conn = accept(g_serverSock, (SOCKADDR*)&clientAddr, &addrlen);
        if (conn == INVALID_SOCKET)
        {
            printf("accept() failed: %u\n", WSAGetLastError());
            Sleep(1000);
        }

        printf("accepted!\n");
    }

    return conn;
}
#endif

static HANDLE _HandleCreateFile(SOCKET s, FH_MESSAGE_CREATE_IN* pMsg)
{
    FH_MESSAGE_CREATE_OUT out = { 0 };
    ULONG outSize = sizeof(out);

    out.cmd = FH_MESSAGE_COMMAND_CREATE;

    //	pMsg->fileName = (BYTE*)pMsg + OFFSET_OF(FH_MESSAGE_CREATE_IN, fileName);

    printf("CREATING FILE\n");
    if (pMsg->isAscii)
    {
        const char* fileName = (const char*)&pMsg->fileName;

        out.hFile = CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);
    }

    else
    {
        const WCHAR* fileName = (const WCHAR*)&pMsg->fileName;

        out.hFile = CreateFileW(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);
    }

    if (INVALID_HANDLE_VALUE == out.hFile)
    {
        printf("create: creation failed\n");
        out.dwLastError = GetLastError();
    }

    printf("----------sending size and data of size: %d\n", outSize);
    if (!Socket_Send(s, &outSize, sizeof(outSize), g_targetIp, g_targetPort))
        return INVALID_HANDLE_VALUE;

    if (!Socket_Send(s, &out, outSize, g_targetIp, g_targetPort))
        return INVALID_HANDLE_VALUE;

    return out.hFile;
}

static BOOL _HandleWriteFile(SOCKET s, FH_MESSAGE_WRITE_IN* pIn)
{
    FH_MESSAGE_WRITE_OUT out = { 0 };
    ULONG outSize = sizeof(out);
    VOID* pPointer, *buffer;

    pPointer = (BYTE*)pIn + OFFSET_OF(FH_MESSAGE_WRITE_IN, buffer);
    buffer = pPointer;

    if (pIn->haveOverlapped)
    {
        pIn->overlapped = *(OVERLAPPED*)pPointer;

        out.haveOverlapped = TRUE;
    }

    printf("WRITING FILE\n");

    out.cmd = FH_MESSAGE_COMMAND_WRITE;
    out.ok = WriteFile(pIn->hFile, buffer, pIn->bufferSize, NULL, pIn->haveOverlapped ? &out.overlapped : NULL);
    if (!out.ok)
    {
        printf("write: writing failed\n");
        out.dwLastError = GetLastError();
    }

    printf("----------sending size and data of size: %d\n", outSize);
    if (!Socket_Send(s, &outSize, sizeof(outSize), g_targetIp, g_targetPort))
        return FALSE;

    if (!Socket_Send(s, &out, outSize, g_targetIp, g_targetPort))
        return FALSE;

    return TRUE;
}

static BOOL _HandleReadFile(SOCKET s, FH_MESSAGE_READ_IN* pIn)
{
    FH_MESSAGE_READ_OUT out = { 0 };
    ULONG outSize = 0;
    BYTE* buffer;
    BOOL ok = TRUE;
    VOID* outBuffer = NULL;

    buffer = malloc(pIn->bufferSize);

    if (pIn->haveOverlapped)
    {
        out.haveOverlapped = TRUE;
    }

    /*
    FH_MESSAGE;
    BOOL	result;
    ULONG	bytesRead;
    BOOL	haveOverlapped;
    OVERLAPPED overlapped;
    DWORD	dwLastError;
    VOID*	data;
    */
    printf("READING FILE\n");

    out.cmd = FH_MESSAGE_COMMAND_READ;
    out.ok = ReadFile(pIn->hFile, buffer, pIn->bufferSize, &out.bytesRead, pIn->haveOverlapped ? &out.overlapped : NULL);
    if (!out.ok)
    {
        out.dwLastError = GetLastError();
    }

    outBuffer = malloc(FH_MESSAGE_READ_OUT_SIZE_BARE + out.bytesRead);
    memcpy(outBuffer, &out, FH_MESSAGE_READ_OUT_SIZE_BARE);
    memcpy((BYTE*)outBuffer + FH_MESSAGE_READ_OUT_SIZE_BARE, buffer, out.bytesRead);

    outSize = FH_MESSAGE_READ_OUT_SIZE_BARE + out.bytesRead;

    free(buffer);

    printf("----------sending size and data of size: %d; out header = %d; bytes read = %d;\n", outSize, FH_MESSAGE_READ_OUT_SIZE_BARE, out.bytesRead);
    if (!Socket_Send(s, &outSize, sizeof(outSize), g_targetIp, g_targetPort)) {
        ok = FALSE;
        goto Cleanup;
    }

    if (!Socket_Send(s, outBuffer, FH_MESSAGE_READ_OUT_SIZE_BARE, g_targetIp, g_targetPort))
        return FALSE;

    if (out.bytesRead > 0)
    {
        if (!Socket_Send(s, (const char*)outBuffer + FH_MESSAGE_READ_OUT_SIZE_BARE, out.bytesRead, g_targetIp, g_targetPort))
            return FALSE;
    }

    /*if (!Socket_Send(s, &outBuffer, outSize)) {
        ok = FALSE;
        goto Cleanup;
        }*/

Cleanup:
    free(outBuffer);
    return ok;
}

static BOOL _HandleCloseFile(SOCKET s, FH_MESSAGE_CLOSE_IN* pIn)
{
    FH_MESSAGE_CLOSE_OUT out = { 0 };
    ULONG outSize = sizeof(out);

    printf("CLOSING HANDLE\n");

    out.cmd = FH_MESSAGE_COMMAND_CLOSE;
    out.ok = CloseHandle(pIn->hFile);
    if (!out.ok)
    {
        printf("close: closing failed\n");
        out.dwLastError = GetLastError();
    }

    printf("----------sending size and data of size: %d\n", outSize);
    if (!Socket_Send(s, &outSize, sizeof(outSize), g_targetIp, g_targetPort))
        return FALSE;

    if (!Socket_Send(s, &out, outSize, g_targetIp, g_targetPort))
        return FALSE;

    return TRUE;
}

VOID DoCleanup(SOCKET server, SOCKET client)
{
    int result;

    if (client != INVALID_SOCKET)
    {
        result = shutdown(client, SD_BOTH);
        if (result)
        {
            printf("shutdown() failed: %u\n", WSAGetLastError());
        }

        result = closesocket(client);
        if (result)
        {
            printf("shutdown() failed: %u\n", WSAGetLastError());
        }
    }

    if (server != INVALID_SOCKET)
    {
        result = shutdown(server, SD_BOTH);
        if (result)
        {
            printf("shutdown() failed: %u\n", WSAGetLastError());
        }

        result = closesocket(server);
        if (result)
        {
            printf("shutdown() failed: %u\n", WSAGetLastError());
        }
    }
}

int main()
{
    WSADATA wsaData;
    int result;
    ULONG msgSize;
    DWORD dwError = 0;
    int addrlen = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD miliseconds = 0;// 1000 * 2;
    BYTE handShake = 0;

    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        printf("WSAStartup failed: %u\n", GetLastError());
        return -1;
    }

#if 0
    g_serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    g_serverSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
    if (g_serverSock == INVALID_SOCKET)
    {
        printf("socket() failed: %u\n", WSAGetLastError());
        return -1;
    }

    /*******************/

    SOCKADDR_IN address;
    address.sin_family = AF_INET;
    address.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    address.sin_port = htons(9001);

    if (SOCKET_ERROR == bind(g_serverSock, (SOCKADDR*)&address, sizeof(address)))
    {
        printf("bind() failed: %u\n", WSAGetLastError());
        return -1;
    }

#if 0
    if (SOCKET_ERROR == listen(g_serverSock, 1))
    {
        printf("listen() failed: %u\n", WSAGetLastError());
        return -1;
    }

    SOCKADDR_IN clientAddr;
    addrlen = sizeof(clientAddr);

    SOCKET conn = accept(g_serverSock, (SOCKADDR*)&clientAddr, &addrlen);
    if (conn == INVALID_SOCKET)
    {
        printf("accept() failed: %u\n", WSAGetLastError());
        return -1;
    }

#else
    SOCKET conn = g_serverSock;
#endif

    printf("initial handshake...\n");

    if (!Socket_Recv(conn, &handShake, sizeof(handShake), g_targetIp, g_targetPort))
    {
        printf("recv size failed: cleanup\n");
        return FALSE;
    }

    if (!Socket_Send(conn, &handShake, sizeof(handShake), g_targetIp, g_targetPort))
    {
        printf("recv size failed: cleanup\n");
        return FALSE;
    }

    printf("initial handshake successful. we can begin!\n");

    do {
        VOID* msg = NULL;
        int toRead = 0;

        printf("-- RECV MESSAGE\n");

        if (!Socket_Recv(conn, &msgSize, sizeof(msgSize), g_targetIp, g_targetPort))
        {
            printf("recv size failed: cleanup\n");
            goto Cleanup;
        }

        msg = malloc(msgSize);

        if (!Socket_Recv(conn, msg, msgSize, g_targetIp, g_targetPort))
        {
            printf("recv msg failed: cleanup\n");
            goto Cleanup;
        }

        result = ioctlsocket(conn, FIONREAD, &toRead);
        assert(!toRead);

        FH_MESSAGE* pMsg = (FH_MESSAGE*)msg;
        switch (pMsg->cmd)
        {
        case FH_MESSAGE_COMMAND_CREATE:
            hFile = _HandleCreateFile(conn, (FH_MESSAGE_CREATE_IN*)pMsg);
            break;

        case FH_MESSAGE_COMMAND_WRITE:
            _HandleWriteFile(conn, (FH_MESSAGE_WRITE_IN*)pMsg);
            break;

        case FH_MESSAGE_COMMAND_READ:
            _HandleReadFile(conn, (FH_MESSAGE_READ_IN*)pMsg);
            break;

        case FH_MESSAGE_COMMAND_CLOSE:
            _HandleCloseFile(conn, (FH_MESSAGE_CLOSE_IN*)pMsg);
            hFile = INVALID_HANDLE_VALUE;
            break;

        default:
            printf("invalid cmd: %u\n", pMsg->cmd);
        }

    Cleanup:
        if (msg) {
            free(msg);
            msg = NULL;
        }

        dwError = WSAGetLastError();
        if (dwError)
        {
            printf("main: have wsa error: %d\n", dwError);
        }

        else
        {
            //printf("main: handled one message!\n");
        }

        if (dwError == WSAECONNRESET) {
            printf("wsaerror: %u\n", dwError);
#if 0
            conn = Socket_Reset(conn);
#endif
            dwError = 0;
        }
    } while (TRUE/*result != SOCKET_ERROR || dwError != WSAETIMEDOUT*/);

    /*******************/

    if (INVALID_HANDLE_VALUE != hFile)
    {
        CloseHandle(hFile);
    }

    DoCleanup(g_serverSock, conn);

    if (WSACleanup())
    {
        printf("WSACleanup() failed: %u\n", WSAGetLastError());
        return -1;
    }

    return 0;
}