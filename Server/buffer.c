#include "icmp_shell.h"
#include "buffer.h"

#ifndef WIN32
#define CopyMemory memcpy
#endif

static ULONG  buffer_realloc(buffer_context *, ULONG);

void buffer_init(buffer_context *context)
{
    //context->m_nSize = 0;
    // context->m_pBase = context->m_pPtr = 0;
    memset(context, 0, sizeof(buffer_context));
}

void buffer_clean(buffer_context *pcontext)
{
    pcontext->m_pPtr = pcontext->m_pBase;
}

ULONG buffer_get_length(buffer_context *context)
{
    int nSize;
    if (context->m_pBase == NULL)
        return 0;
    nSize = context->m_pPtr - context->m_pBase;
    return nSize;
}

/*
在 data 为 NULL  只是预先分配内存
*/
ULONG buffer_write(buffer_context *context, LPBYTE data, ULONG size)
{
    buffer_realloc(context, size + buffer_get_length(context));
    if (data)  //  sincoder 改写，，
    {
        CopyMemory(context->m_pPtr, data, size);
        // Advance Pointer
        context->m_pPtr += size;
    }
    return size;
}


static ULONG buffer_realloc(buffer_context *context, ULONG size)
{
    UINT nNewSize ;
    PBYTE pNewBuffer;
    UINT nBufferLen;

    if (size < buffer_get_memsize(context))  //需要的长度小于总的长度
        return 0;
    // Allocate new size
    nNewSize = (UINT) ceil(size / 1024.0) * 1024;
    // New Copy Data Over
#ifdef WIN32
    pNewBuffer = (PBYTE) VirtualAlloc(NULL, nNewSize, MEM_COMMIT, PAGE_READWRITE);
#else
    pNewBuffer = (PBYTE) malloc(nNewSize);
#endif
    nBufferLen = buffer_get_length(context);
    CopyMemory(pNewBuffer, context->m_pBase, nBufferLen);
    if (context->m_pBase)
    {
#ifdef WIN32
        VirtualFree(context->m_pBase, 0, MEM_RELEASE);
#else
        free(context->m_pBase);
#endif
    }
    // Hand over the pointer
    context->m_pBase = pNewBuffer;
    // Realign position pointer
    context->m_pPtr = context->m_pBase + nBufferLen;
    context->m_nSize = nNewSize;
    return size;
}

ULONG buffer_get_memsize(buffer_context *context)
{
    return context->m_nSize;
}

void buffer_free(buffer_context *context)
{
    if (context->m_pBase)
    {
#ifdef WIN32
        VirtualFree(context->m_pBase, 0, MEM_RELEASE);
#else
        free(context->m_pBase);
#endif
    }
    context->m_nSize = 0;
    context->m_pBase = context->m_pPtr = NULL;
}

LPBYTE buffer_getat(buffer_context *context, ULONG offset)
{
	if(offset >= buffer_get_length(context))
	{
		return NULL;
	}
    return context->m_pBase + offset;
}


/*
交换两个 buffer 的内容
*/
void  buffer_exch(buffer_context *buff1, buffer_context *buff2)
{
    buffer_context tmp;
    memcpy(&tmp, buff1, sizeof(buffer_context));
    memcpy(buff1, buff2, sizeof(buffer_context));
    memcpy(buff2, &tmp, sizeof(buffer_context));
}

ULONG buffer_read(buffer_context *ctx, LPBYTE buff, ULONG size)
{
    if (size > buffer_get_length(ctx))
    {
        size = buffer_get_length(ctx);
    }
    if (size)
    {
        memcpy(buff, buffer_getat(ctx, 0), size);
        memmove(ctx->m_pBase, ctx->m_pBase + size , buffer_get_length(ctx) - size);
        ctx->m_pPtr -= size;
    }

    return size;
}