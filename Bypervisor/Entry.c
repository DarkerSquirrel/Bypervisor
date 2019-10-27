#include "ntddk.h"
#include "wdm.h"
#include "Shared.h"

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  pDriverObject,
    _In_ PUNICODE_STRING pRegPath
)
{
    UNREFERENCED_PARAMETER(pRegPath);

    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT pDeviceObject = NULL;
    BOOLEAN DeviceCreated = FALSE;
    BOOLEAN SymlinkCreated = FALSE;

    // First of all, initialise the hypervisor
    Status = InitialiseHypervisor();

    if (!NT_SUCCESS(Status))
        goto Exit;

    UNICODE_STRING BypervisorName;
    RtlInitUnicodeString(&BypervisorName, Bypervisor);

    Status = IoCreateDevice(
        pDriverObject,
        0,
        &BypervisorName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &pDeviceObject
    );

    if (!NT_SUCCESS(Status))
        goto Exit;

    DeviceCreated = TRUE;

    UNICODE_STRING BypervisorLinkName;
    RtlInitUnicodeString(&BypervisorLinkName, BypervisorDosDevices);
    
    Status = IoCreateSymbolicLink(&BypervisorLinkName, &BypervisorName);

    if (!NT_SUCCESS(Status))
        goto Exit;

    SymlinkCreated = TRUE;

Exit:
    if (!NT_SUCCESS(Status))
    {
        if (SymlinkCreated)
            IoDeleteSymbolicLink(&BypervisorLinkName);

        if (DeviceCreated)
            IoDeleteDevice(pDeviceObject);
    }
    return Status;
}