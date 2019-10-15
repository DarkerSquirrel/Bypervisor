#pragma once
#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "ia32.h"

#define BYPERVISOR_NONPAGEDPOOL_TAG 'ppnB'
#define BYPERVISOR_PAGEDPOOL_TAG    'ppyB'

typedef VMCS* PVMCS;
typedef VMX_MSR_BITMAP* PMSRBMAP;

typedef struct _VMM_CONTEXT
{
    UINT32 SystemProcessorCount;
    UINT32 ProcessorsInitialised;
} VMM_CONTEXT, *PVMM_CONTEXT;

typedef struct _REG_CAPTURE
{
    UINT64 rax;
    UINT64 rbx;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 rbp;
    UINT64 rsp;

    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;

    SEGMENT_SELECTOR cs;
    SEGMENT_SELECTOR ds;
    SEGMENT_SELECTOR es;
    SEGMENT_SELECTOR fs;
    SEGMENT_SELECTOR gs;
    SEGMENT_SELECTOR ss;

    UINT64 dr0;
    UINT64 dr1;
    UINT64 dr2;
    UINT64 dr3;
    UINT64 dr6;
    UINT64 dr7;
} REG_CAPTURE, *PREG_CAPTURE;

typedef struct _REG_SPEC_CAPTURE
{
    UINT64 cr0;
    UINT64 cr2;
    UINT64 cr3;
    UINT64 cr4;
} REG_SPEC_CAPTURE, *PREG_SPEC_CAPTURE;

typedef struct _VMM_PER_PROC_CONTEXT
{
    BOOLEAN HasLaunched;
    PVMCS pVmcs;
    PVOID pPhysVmcs;
    PMSRBMAP pMsrBitmap;
    PVOID pPhysMsrBitmap;
};