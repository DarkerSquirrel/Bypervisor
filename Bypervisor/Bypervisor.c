#include "Bypervisor.h"

PVMM_CONTEXT BypervisorContext = NULL;

BOOLEAN ProbeVtx()
{
    NTSTATUS Status = FALSE;
    int CpuIdOut[4];

    __cpuid(CpuIdOut, 1);

    if (!(CpuIdOut[2] & 0x20))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VT-x not supported.\n");
        goto Exit;
    }

    unsigned long long FeatureControl = __readmsr(IA32_FEATURE_CONTROL);

    // Check LOCK bit of IA32_FEATURE_CONTROL (b0)
    if (!(FeatureControl & 0x1))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Feature control MSR - Lock bit not set.\n");
        goto Exit;
    }

    // Check Out-of-SMX operation of IA32_FEATURE_CONTROL (b2)
    if (!((FeatureControl >> 2) & 0x1))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VT-x not supported outside of SMX.\n");
        goto Exit;
    }

    Status = TRUE;

Exit:
    return Status;
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

    Status = STATUS_SUCCESS;

Exit:
    return Status;
}