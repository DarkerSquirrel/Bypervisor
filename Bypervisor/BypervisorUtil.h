#pragma once

// Capability MSRs are all 32 bits so ya
UINT32
EnforceCapabilityMSR(
    _In_ REG64  CapabilityMSR,
    _In_ UINT32 Value
);

// Helper to determine if the "True" MSRs
// are supported
BOOLEAN
IsTrueCapabilityMSRSupported(
    _In_ PVMM_PER_PROC_CONTEXT pContext
);