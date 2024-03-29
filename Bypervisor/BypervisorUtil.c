#include "Bypervisor.h"

UINT32
EnforceCapabilityMSR(
    _In_ REG64  CapabilityMSR,
    _In_ UINT32 Value
)
{
    Value |= (CapabilityMSR & (0xffffffff));
    Value &= (CapabilityMSR >> 32);

    return Value;
}

BOOLEAN
IsTrueCapabilityMSRSupported(
    _In_ PVMM_PER_PROC_CONTEXT pContext
)
{
    return pContext->MsrRegisters.Basic.VmxControls;
}

UINT64
VmRead(
    _In_ UINT64 Encoding
)
{
    UINT64 Information;
    __vmx_vmread(Encoding, &Information);
    return Information;
}