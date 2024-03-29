#pragma once
#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "ia32.h"

#define BYPERVISOR_NONPAGEDPOOL_TAG 'ppnB'
#define BYPERVISOR_PAGEDPOOL_TAG    'ppyB'

// 16 MB
#define VMM_HOST_STACK_SIZE         0x1000000

// Standard sizes for zie page hierarchy (No PSE)
#define PAGE_TABLE_SIZE             (1 << 9)
#define PAGE_TABLE_ENTRY_SIZE       (1 << 12)

typedef VMCS*           PVMCS;
typedef VMX_MSR_BITMAP* PMSRBMAP;
typedef UINT64          REG64;
typedef UINT32          REG32;
typedef EPT_PML4*       PPML4;
typedef PDPTE_64*       PPDPTE;
typedef PDE_64*         PPDE;
typedef PTE_64*         PPTE;

typedef union
{
    REG64 Registers[17];
    struct
    {
        IA32_VMX_BASIC_REGISTER             Basic;
        IA32_VMX_PINBASED_CTLS_REGISTER     PinBased;
        IA32_VMX_PROCBASED_CTLS_REGISTER    ProcBased;
        IA32_VMX_EXIT_CTLS_REGISTER         Exit;
        IA32_VMX_ENTRY_CTLS_REGISTER        Entry;
        IA32_VMX_MISC_REGISTER              Misc;
        REG64                               FixedCr0_0;
        REG64                               FixedCr0_1;
        REG64                               FixedCr4_0;
        REG64                               FixedCr4_1;
        IA32_VMX_VMCS_ENUM_REGISTER         VmcsEnum;
        IA32_VMX_PROCBASED_CTLS2_REGISTER   ProcBasedCtrls2;
        IA32_VMX_EPT_VPID_CAP_REGISTER      EptVpidCap;
        REG64                               TruePinBasedCtrls;
        REG64                               TrueProcBasedCtrls;
        REG64                               TrueExitCtrls;
        REG64                               TrueEntryCtrls;
    };
} VMX_MSR_REGS, *PVMX_MSR_REGS;

typedef struct _VMX_ON_REGION
{
	UINT32 RevisionId;
} VMX_ON_REGION, *PVMX_ON_REGION;

typedef struct _VMM_CONTEXT
{
    UINT32			SystemProcessorCount;
    UINT32			ProcessorsInitialised;
    ULONG64			SystemDirectoryTableBase;
    
} VMM_CONTEXT, *PVMM_CONTEXT;

typedef struct _VMM_HOST_STACK
{
    UINT8 Stack[VMM_HOST_STACK_SIZE];
} VMM_HOST_STACK, *PVMM_HOST_STACK;

typedef struct _REG_CONTEXT
{
    REG64 rax;
    REG64 rbx;
    REG64 rcx;
    REG64 rdx;
    REG64 rsi;
    REG64 rdi;
    REG64 rbp;
    REG64 rsp;
    
    REG64 r8;
    REG64 r9;
    REG64 r10;
    REG64 r11;
    REG64 r12;
    REG64 r13;
    REG64 r14;
    REG64 r15;

    REG64 dr0;
    REG64 dr1;
    REG64 dr2;
    REG64 dr3;
    REG64 dr6;
    REG64 dr7;

    REG64 rflags;

    REG64 rip;

    SEGMENT_SELECTOR cs;
    SEGMENT_SELECTOR ds;
    SEGMENT_SELECTOR es;
    SEGMENT_SELECTOR fs;
    SEGMENT_SELECTOR gs;
    SEGMENT_SELECTOR ss;
} REG_CONTEXT, *PREG_CONTEXT;

typedef struct _REG_SPEC_CAPTURE
{
    UINT64 cr0;
    UINT64 cr2;
    UINT64 cr3;
    UINT64 cr4;

    IA32_DEBUGCTL_REGISTER      DebugControl;
    IA32_SYSENTER_CS_REGISTER   SysenterCs;
    REG64                       SysenterEsp;
    REG64                       SysenterEip;

    UINT64                      gsBase;
} REG_SPEC_CAPTURE, *PREG_SPEC_CAPTURE;

typedef struct _EPT_PAGE_TABLE
{
    PML4E_64  Pml4[PAGE_TABLE_SIZE];
    PDPTE_64  Pdpt[PAGE_TABLE_SIZE];
    PDE_64    Pde[PAGE_TABLE_SIZE];
    PTE_64    Pte[PAGE_TABLE_ENTRY_SIZE];
} EPT_PAGE_TABLE, *PEPT_PAGE_TABLE;

typedef struct _VMM_PER_PROC_CONTEXT
{
    BOOLEAN             HasLaunched;
    REG_CONTEXT         RegisterCapture;
    REG_SPEC_CAPTURE    RegisterSpecCapture;
    PEPT_PAGE_TABLE     pEpt;
    PVOID               pPhysEpt;
    PVMM_CONTEXT        pVmmContext;
    VMX_MSR_REGS        MsrRegisters;

    DECLSPEC_ALIGN(PAGE_SIZE)
    VMX_ON_REGION       VmxOnRegion;

    DECLSPEC_ALIGN(PAGE_SIZE)
    VMCS                Vmcs;

    PHYSICAL_ADDRESS    PhysPVmxOn;
    PHYSICAL_ADDRESS    PhysPVmcs;
} VMM_PER_PROC_CONTEXT, *PVMM_PER_PROC_CONTEXT;

VOID
CaptureContext(
    _In_ PREG_CONTEXT RegisterCapture
);