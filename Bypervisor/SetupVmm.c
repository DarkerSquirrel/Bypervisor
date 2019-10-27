#include "Bypervisor.h"
#include "BypervisorUtil.h"

PVMM_CONTEXT BypervisorContext = NULL;

BOOLEAN
ProbeVtx(
)
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

BOOLEAN
EnterVmxOperation(
    _In_ PVMM_PER_PROC_CONTEXT pContext
)
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

// Whole routine is a joke
BOOLEAN
LoadAndSetupVmcs(
    _In_ PVMM_PER_PROC_CONTEXT pContext
)
{
    if (__vmx_vmclear(&pContext->PhysPVmcs))
    {
        __vmx_off();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "LoadAndSetupVmcs: VMClear failed.\n");
        return FALSE;
    }

    if (__vmx_vmptrld(&pContext->PhysPVmcs))
    {
        __vmx_off();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "LoadAndSetupVmcs: Vmptrld failed.\n");
        return FALSE;
    }

    pContext->Vmcs.RevisionId = pContext->MsrRegisters.Basic.VmcsRevisionId;
    pContext->Vmcs.RevisionId &= ~(1 << 31);

    // Do the meme where you gotta set 
    // 1s if you don't support VMCS shadowing
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0);

    UINT32 PrimaryProcBasedCtrls = IA32_VMX_PROCBASED_CTLS_RDTSC_EXITING_BIT |
        IA32_VMX_PROCBASED_CTLS_ACTIVATE_SECONDARY_CONTROLS_BIT |
        IA32_VMX_PROCBASED_CTLS_MOV_DR_EXITING_BIT;
    UINT32 SecondaryProcBasedCtrls = 0;
    UINT32 PinBasedCtrls = 0;
    UINT32 VmEntryCtrls = IA32_VMX_ENTRY_CTLS_IA32E_MODE_GUEST_BIT;
    UINT32 VmExitCtrls = IA32_VMX_EXIT_CTLS_HOST_ADDRESS_SPACE_SIZE_BIT;

    // Do the meme where you gotta set
    // reserved-bits
    // Oh wait
    // There's MORE.
    // You gotta check bit 55 of the basic register.
    if (IsTrueCapabilityMSRSupported(pContext))
    {
        __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.TruePinBasedCtrls, PinBasedCtrls));

        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.TrueProcBasedCtrls, PrimaryProcBasedCtrls));

        __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.TrueEntryCtrls, VmEntryCtrls));

        __vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.TrueExitCtrls, VmExitCtrls));
    }
    else
    {
        __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.PinBased.Flags, PinBasedCtrls));

        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.ProcBased.Flags, PrimaryProcBasedCtrls));

        __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.Entry.Flags, VmEntryCtrls));

        __vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS,
            EnforceCapabilityMSR((REG64)pContext->MsrRegisters.Exit.Flags, VmExitCtrls));

        if (pContext->MsrRegisters.ProcBased.ActivateSecondaryControls)
            __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                EnforceCapabilityMSR((REG64)pContext->MsrRegisters.ProcBasedCtrls2.Flags, SecondaryProcBasedCtrls));
    }

    return TRUE;
}

BOOLEAN 
LaunchVmx(
)
{
    __vmx_vmlaunch();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "LaunchVmx: Failed to launch - Error code => %llu", 
        VmRead(VMCS_VM_INSTRUCTION_ERROR));

    return FALSE;
}

NTSTATUS 
InitialiseProcessorVmx(
)
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

NTSTATUS 
SetupVtx(
)
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