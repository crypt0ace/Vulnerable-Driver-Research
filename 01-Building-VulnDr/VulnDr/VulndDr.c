#include <ntddk.h>
#include <ntstrsafe.h>
#include "public.h"

static LONG g_TotalIoctlsHandled = 0;

static unsigned char g_FakeKernelRegion[VULNDR_FAKE_REGION_SIZE] =
"VulnDr fake internal kernel buffer. This is not real kernel memory.";

static NTSTATUS VulnDrCompleteRequest(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS VulnDrCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IRP_MJ_CREATE / IRP_MJ_CLOSE received\n"
    );

    return VulnDrCompleteRequest(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS VulnDrUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Unsupported IRP received\n"
    );

    return VulnDrCompleteRequest(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

static NTSTATUS VulnDrHandleGetVersion(
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_VERSION_INFO versionInfo;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (OutputBufferLength < sizeof(VULNDR_VERSION_INFO))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    RtlZeroMemory(systemBuffer, OutputBufferLength);

    versionInfo = (PVULNDR_VERSION_INFO)systemBuffer;

    versionInfo->Major = 1;
    versionInfo->Minor = 0;
    versionInfo->Build = 1;

    RtlStringCchCopyW(
        versionInfo->Message,
        ARRAYSIZE(versionInfo->Message),
        L"Vulnerable Driver"
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_GET_VERSION handled\n"
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_VERSION_INFO)
    );
}

static NTSTATUS VulnDrHandleEcho(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_ECHO_REQUEST echoRequest;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_ECHO_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    if (OutputBufferLength < sizeof(VULNDR_ECHO_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    echoRequest = (PVULNDR_ECHO_REQUEST)systemBuffer;

    if (echoRequest->InputLength > sizeof(echoRequest->Input))
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    echoRequest->Input[sizeof(echoRequest->Input) - 1] = '\0';

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_ECHO handled. InputLength=%lu Input=%s\n",
        echoRequest->InputLength,
        echoRequest->Input
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_ECHO_REQUEST)
    );
}

static NTSTATUS VulnDrHandleGetStats(
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_STATS stats;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (OutputBufferLength < sizeof(VULNDR_STATS))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    RtlZeroMemory(systemBuffer, OutputBufferLength);

    stats = (PVULNDR_STATS)systemBuffer;

    stats->TotalIoctlsHandled = g_TotalIoctlsHandled;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_GET_STATS handled. Total=%ld\n",
        stats->TotalIoctlsHandled
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_STATS)
    );
}

static const char* VulnDrMethodToString(
    _In_ ULONG Method
)
{
    switch (Method)
    {
    case METHOD_BUFFERED:
        return "METHOD_BUFFERED";

    case METHOD_IN_DIRECT:
        return "METHOD_IN_DIRECT";

    case METHOD_OUT_DIRECT:
        return "METHOD_OUT_DIRECT";

    case METHOD_NEITHER:
        return "METHOD_NEITHER";

    default:
        return "UNKNOWN_METHOD";
    }
}

static const char* VulnDrAccessToString(
    _In_ ULONG Access
)
{
    switch (Access)
    {
    case FILE_ANY_ACCESS:
        return "FILE_ANY_ACCESS";

    case FILE_READ_ACCESS:
        return "FILE_READ_ACCESS";

    case FILE_WRITE_ACCESS:
        return "FILE_WRITE_ACCESS";

    case FILE_READ_ACCESS | FILE_WRITE_ACCESS:
        return "FILE_READ_ACCESS | FILE_WRITE_ACCESS";

    default:
        return "UNKNOWN_ACCESS";
    }
}

static VOID VulnDrLogIoctlDetails(
    _In_ ULONG IoctlCode
)
{
    ULONG deviceType;
    ULONG access;
    ULONG function;
    ULONG method;

    deviceType = (IoctlCode >> 16) & 0xFFFF;
    access = (IoctlCode >> 14) & 0x3;
    function = (IoctlCode >> 2) & 0xFFF;
    method = IoctlCode & 0x3;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL decode: Code=0x%X DeviceType=0x%X Function=0x%X Method=%s Access=%s\n",
        IoctlCode,
        deviceType,
        function,
        VulnDrMethodToString(method),
        VulnDrAccessToString(access)
    );
}

static BOOLEAN VulnDrValidateFakeRegionRequest(
    _In_ PVULNDR_FAKE_RW_REQUEST Request
)
{
    if (Request->Size == 0)
    {
        return FALSE;
    }

    if (Request->Size > VULNDR_FAKE_REGION_MAX_TRANSFER)
    {
        return FALSE;
    }

    if (Request->Offset >= VULNDR_FAKE_REGION_SIZE)
    {
        return FALSE;
    }

    if (Request->Size > (VULNDR_FAKE_REGION_SIZE - Request->Offset))
    {
        return FALSE;
    }

    return TRUE;
}

static NTSTATUS VulnDrHandleSafeReadFakeRegion(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_FAKE_RW_REQUEST request;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST) ||
        OutputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    request = (PVULNDR_FAKE_RW_REQUEST)systemBuffer;

    if (!VulnDrValidateFakeRegionRequest(request))
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    RtlCopyMemory(
        request->Data,
        &g_FakeKernelRegion[request->Offset],
        request->Size
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] SAFE_READ_FAKE_REGION Offset=0x%X Size=%lu\n",
        request->Offset,
        request->Size
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_FAKE_RW_REQUEST)
    );
}

static NTSTATUS VulnDrHandleSafeWriteFakeRegion(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_FAKE_RW_REQUEST request;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST) ||
        OutputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    request = (PVULNDR_FAKE_RW_REQUEST)systemBuffer;

    if (!VulnDrValidateFakeRegionRequest(request))
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    RtlCopyMemory(
        &g_FakeKernelRegion[request->Offset],
        request->Data,
        request->Size
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] SAFE_WRITE_FAKE_REGION Offset=0x%X Size=%lu\n",
        request->Offset,
        request->Size
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_FAKE_RW_REQUEST)
    );
}

__declspec(noinline)
static VOID VulnDrUnsafeStackCopy(
    _In_ PVULNDR_VULN_STACK_REQUEST Request
)
{
    volatile unsigned char kernelStackBuffer[32];

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Vulnerable copy starting. DestinationSize=32 UserSize=%lu\n",
        Request->Size
    );

    //
    // INTENTIONAL VULNERABILITY:
    // This trusts Request->Size and copies into a fixed 32-byte stack buffer.
    //
    RtlCopyMemory(
        (PVOID)kernelStackBuffer,
        Request->Data,
        Request->Size
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Vulnerable copy completed\n"
    );
}

static NTSTATUS VulnDrHandleVulnStackOverflow(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_VULN_STACK_REQUEST request;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_VULN_STACK_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    request = (PVULNDR_VULN_STACK_REQUEST)systemBuffer;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_VULN_STACK_OVERFLOW received. Size=%lu\n",
        request->Size
    );

    VulnDrUnsafeStackCopy(request);

    return VulnDrCompleteRequest(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS VulnDrDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack;
    ULONG ioctlCode;
    ULONG inputBufferLength;
    ULONG outputBufferLength;

    stack = IoGetCurrentIrpStackLocation(Irp);

    ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    InterlockedIncrement(&g_TotalIoctlsHandled);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IRP_MJ_DEVICE_CONTROL received. IoctlCode=0x%X InputLength=%lu OutputLength=%lu\n",
        ioctlCode,
        inputBufferLength,
        outputBufferLength
    );

    VulnDrLogIoctlDetails(ioctlCode);

    switch (ioctlCode)
    {
    case IOCTL_VULNDR_GET_VERSION:
        return VulnDrHandleGetVersion(Irp, outputBufferLength);

    case IOCTL_VULNDR_ECHO:
        return VulnDrHandleEcho(Irp, inputBufferLength, outputBufferLength);

    case IOCTL_VULNDR_GET_STATS:
        return VulnDrHandleGetStats(Irp, outputBufferLength);

    case IOCTL_VULNDR_SAFE_READ_FAKE_REGION:
        return VulnDrHandleSafeReadFakeRegion(
            Irp,
            inputBufferLength,
            outputBufferLength
        );

    case IOCTL_VULNDR_SAFE_WRITE_FAKE_REGION:
        return VulnDrHandleSafeWriteFakeRegion(
            Irp,
            inputBufferLength,
            outputBufferLength
        );

    case IOCTL_VULNDR_VULN_STACK_OVERFLOW:
        return VulnDrHandleVulnStackOverflow(
            Irp,
            inputBufferLength
        );

    default:
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] Unknown IOCTL received: 0x%X\n",
            ioctlCode
        );

        return VulnDrCompleteRequest(
            Irp,
            STATUS_INVALID_DEVICE_REQUEST,
            0
        );
    }
}

VOID VulnDrUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING dosDeviceName;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] DriverUnload called\n"
    );

    RtlInitUnicodeString(&dosDeviceName, VULNDR_DOS_DEVICE_NAME);

    IoDeleteSymbolicLink(&dosDeviceName);

    if (DriverObject->DeviceObject != NULL)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Device and symbolic link deleted\n"
    );
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING dosDeviceName;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] DriverEntry called\n"
    );

    RtlInitUnicodeString(&deviceName, VULNDR_DEVICE_NAME);
    RtlInitUnicodeString(&dosDeviceName, VULNDR_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] IoCreateDevice failed: 0x%X\n",
            status
        );

        return status;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Device created: %wZ\n",
        &deviceName
    );

    status = IoCreateSymbolicLink(
        &dosDeviceName,
        &deviceName
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] IoCreateSymbolicLink failed: 0x%X\n",
            status
        );

        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Symbolic link created: %wZ -> %wZ\n",
        &dosDeviceName,
        &deviceName
    );

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = VulnDrUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = VulnDrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = VulnDrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VulnDrDeviceControl;

    DriverObject->DriverUnload = VulnDrUnload;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Driver loaded successfully\n"
    );

    return STATUS_SUCCESS;
}