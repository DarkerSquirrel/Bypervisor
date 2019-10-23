#include "Bypervisor.h"

PVMM_CONTEXT BypervisorContext = NULL;

BOOLEAN ProbeVtx()
{
    NTSTATUS Status = FALSE;
    int CpuIdOut[4];

    __cpuid(CpuIdOut, 1);

    if (!(CpuIdOut[2] & 0x20))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "VT-x not supported.\n");
        goto Exit;
    }

    UINT64 FeatureControl = __readmsr(IA32_FEATURE_CONTROL);

    // Check LOCK bit of IA32_FEATURE_CONTROL (b0)
    if (!(FeatureControl & 0x1))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "Feature control MSR - Lock bit not set.\n");
        goto Exit;
    }

    // Check Out-of-SMX operation of IA32_FEATURE_CONTROL (b2)
    if (!(FeatureControl & 0x40))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "VT-x not supported outside of SMX.\n");
        goto Exit;
    }

    Status = TRUE;

Exit:
    return Status;
}

BOOLEAN SetupVmcs(PVMM_PER_PROC_CONTEXT pContext)
{
    pContext->Vmcs.RevisionId = pContext->MsrRegisters.Basic.VmcsRevisionId;
    pContext->Vmcs.RevisionId &= ~(1 << 31);

    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0);
}

BOOLEAN EnterVmxOperation(PVMM_PER_PROC_CONTEXT pContext)
{
    // Set CR4.VMXE
	__writecr4((__readcr4() | CR4_VMX_ENABLE_BIT));

    // Do the fixed bits junk
    REG64 cr0 = __readcr0();
    REG64 cr4 = __readcr4();

    // It is the OTHER WAY AROUND
    // Intel? Why?
    // You would think that the 1 bits in "fixedcr0_0" MSR
    // would tell you which bits to fix to 0 in cr0.
    // And the 1 bits in "fixedcr0_1" MSR 
    // would tell you which bits to fix to 1 in cr0.
    // But nah. 1s in cr0_0 are fixed to 1s and 
    // 0s in cr0_1 are the ones fixed to 0.
    // huh.png
    cr0 |= pContext->MsrRegisters.FixedCr0_0;
    cr0 &= pContext->MsrRegisters.FixedCr0_1;
    cr4 |= pContext->MsrRegisters.FixedCr4_0;
    cr4 &= pContext->MsrRegisters.FixedCr4_1;

    __writecr0(cr0);
    __writecr4(cr4);

    if (__vmx_on(&pContext->PhysPVmxOn))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "EnterVmxOperation: Vmxon failed.\n");
        return FALSE;
    };

    if (__vmx_vmclear(&pContext->PhysPVmcs))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "EnterVmxOperation: Vmxclear failed.\n");
        __vmx_off();
        return FALSE;
    }

    return TRUE;
}

NTSTATUS InitialiseProcessorVmx()
{
    PVMM_PER_PROC_CONTEXT pContext = ExAllocatePoolWithTag(NonPagedPoolNx, 
        sizeof(VMM_PER_PROC_CONTEXT),
        BYPERVISOR_NONPAGEDPOOL_TAG);

    if (pContext == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
            DPFLTR_ERROR_LEVEL,
            "InitialiseProcessorVmx: ExAllocatePoolWithTag failed.\n");
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(pContext, sizeof(pContext));

    // Read the IA32_VMX capability registers
    for (UINT32 i = 0;
        i < sizeof(pContext->MsrRegisters.Registers) /
        sizeof(pContext->MsrRegisters.Registers[0]); i++)
    {
        pContext->MsrRegisters.Registers[i] = __readmsr(IA32_VMX_BASIC + i);
    }

    // Setup VMX on region
    // RevisionId MSB needs to be cleared
    // To indicate VMCS shadowing is not supported
    pContext->VmxOnRegion.RevisionId =  pContext->MsrRegisters.Basic.VmcsRevisionId;
    pContext->VmxOnRegion.RevisionId &= ~(1 << 31);
    pContext->PhysPVmxOn =              MmGetPhysicalAddress(&pContext->VmxOnRegion);
    pContext->PhysPVmcs =               MmGetPhysicalAddress(&pContext->Vmcs);

    EnterVmxOperation(pContext);

    SetupVmcs(pContext);

    return STATUS_SUCCESS;
}

NTSTATUS SetupVtx()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (!ProbeVtx())
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VT-x probe failed.\n");
        goto Exit;
    }

    BypervisorContext = (PVMM_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx, 
        sizeof(VMM_CONTEXT), 
        BYPERVISOR_NONPAGEDPOOL_TAG);

    if (BypervisorContext == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to allocate memory.\n");
        goto Exit;
    }

    BypervisorContext->ProcessorsInitialised = 0;
    BypervisorContext->SystemProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    ASSERT(BypervisorContext->SystemProcessorCount > 0);

    BypervisorContext->SystemDirectoryTableBase = __readcr3();

    Status = STATUS_SUCCESS;

Exit:
    return Status;
}