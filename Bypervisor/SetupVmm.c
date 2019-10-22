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

    UINT64 FeatureControl = __readmsr(IA32_FEATURE_CONTROL);

    // Check LOCK bit of IA32_FEATURE_CONTROL (b0)
    if (!(FeatureControl & 0x1))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Feature control MSR - Lock bit not set.\n");
        goto Exit;
    }

    // Check Out-of-SMX operation of IA32_FEATURE_CONTROL (b2)
    if (!(FeatureControl & 0x40))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VT-x not supported outside of SMX.\n");
        goto Exit;
    }

    Status = TRUE;

Exit:
    return Status;
}

IA32_VMX_BASIC_REGISTER GetVmxBasicRegister()
{
	IA32_VMX_BASIC_REGISTER VmxBasicRegister;
	VmxBasicRegister.Flags = __readmsr(IA32_VMX_BASIC);
	return VmxBasicRegister;
}

NTSTATUS SetupVmxOnRegion(PVMM_CONTEXT pVmmContext)
{
	PVMX_ON_REGION pVmxOnRegion = ExAllocatePoolWithTag(NonPagedPoolNx, 
		sizeof(VMX_ON_REGION), 
		BYPERVISOR_NONPAGEDPOOL_TAG);

	if (pVmxOnRegion == NULL)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID,
			DPFLTR_ERROR_LEVEL,
			"SetupVmxOnRegion: No more NonPagedPool memory.\n");
		return STATUS_NO_MEMORY;
	}

	pVmxOnRegion->RevisionNumber = GetVmxBasicRegister().VmcsRevisionId;
	pVmmContext->pVmxOnRegion = pVmxOnRegion;

	return STATUS_SUCCESS;
}

VOID SetupFixedControlBits()
{
	UINT64 FixedCr0_0 = __readmsr(IA32_VMX_CR0_FIXED0);
	UINT64 FixedCr0_1 = __readmsr(IA32_VMX_CR0_FIXED1);
	UINT64 FixedCr4_0 = __readmsr(IA32_VMX_CR4_FIXED0);
	UINT64 FixedCr4_1 = __readmsr(IA32_VMX_CR4_FIXED1);

	UINT64 FinalCr0 = __readcr0();
	FinalCr0 &= ~FixedCr0_0;
	FinalCr0 |= FixedCr0_1;
	__writecr0(FinalCr0);

	UINT64 FinalCr4 = __readcr4();
	FinalCr4 &= ~FixedCr4_0;
	FinalCr4 |= FixedCr4_1;
	__writecr4(FinalCr4);
}

NTSTATUS EnterVmxOperation(PVMM_CONTEXT pVmmContext)
{
	NTSTATUS Status = STATUS_SUCCESS;

	__writecr4((__readcr4() & CR4_VMX_ENABLE_BIT));

	SetupFixedControlBits();

	Status = SetupVmxOnRegion(pVmmContext);

	if (!NT_SUCCESS(Status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
			DPFLTR_ERROR_LEVEL, 
			"EnterVmxOperation: SetupVmxOnRegion failed.\n");
		goto Exit;
	}

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

    BypervisorContext->SystemDirectoryTableBase = __readcr3();

    Status = STATUS_SUCCESS;

Exit:
    return Status;
}