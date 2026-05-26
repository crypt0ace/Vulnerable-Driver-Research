# 01 - Building VulnDr

This folder contains the code for the first part of the vulnerable driver research series.

The purpose of this section is to build a Windows kernel driver from scratch, understand how user-mode applications communicate with drivers through IOCTLs, and demonstrate how a simple trust-boundary mistake can become a kernel-mode vulnerability.

> **Warning**
>
> This folder contains an intentionally vulnerable driver path. Run it only inside an isolated Windows VM. The vulnerable IOCTL can crash the system.

## Folder Structure

```text
01-Building-VulnDr/
│
├── README.md
│
├── VulnDr/
│   └── Kernel driver source
│
├── VulnDr_Client/
│   └── User-mode IOCTL client
│
└── VulnDrExp/
    └── User-mode PoC for the intentionally vulnerable IOCTL
```

## Components

### VulnDr

`VulnDr` is the Windows WDM kernel driver.

It demonstrates:

- `DriverEntry`
- Driver unload routine
- Device object creation
- Symbolic link creation
- `IRP_MJ_CREATE`
- `IRP_MJ_CLOSE`
- `IRP_MJ_DEVICE_CONTROL`
- IOCTL dispatching
- Safe buffer validation
- Dangerous-looking but safe fake read/write operations
- One intentionally vulnerable stack overflow IOCTL

Device names used:

```text
Kernel device name:     \Device\VulnDr
DOS symbolic link:      \DosDevices\VulnDr
User-mode path:         \\.\VulnDr
```

### VulnDr_Client

`VulnDr_Client` is a normal user-mode client that opens the driver and sends safe IOCTL requests.

It demonstrates:

- Opening `\\.\VulnDr` with `CreateFileW`
- Sending IOCTLs with `DeviceIoControl`
- Receiving version information
- Sending echo data
- Reading driver stats
- Reading and writing to a fake internal driver buffer

### VulnDrExp

`VulnDrExp` is the local proof-of-concept client for the intentionally vulnerable IOCTL.

It sends controlled input to the vulnerable stack-copy routine and demonstrates how trusting a user-controlled size field can corrupt kernel stack memory and crash the VM.

This PoC is for local lab crash analysis only.

## IOCTLs Covered

```text
IOCTL_VULNDR_GET_VERSION
IOCTL_VULNDR_ECHO
IOCTL_VULNDR_GET_STATS
IOCTL_VULNDR_SAFE_READ_FAKE_REGION
IOCTL_VULNDR_SAFE_WRITE_FAKE_REGION
IOCTL_VULNDR_VULN_STACK_OVERFLOW
```

## Build Requirements

- Windows 10 host
- Visual Studio 2022
- Windows Driver Kit
- Windows 10 VirtualBox VM
- Test signing enabled in the VM
- WinDbg configured for kernel debugging

## VM Setup

Inside the Windows VM, enable test signing:

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

Enable kernel debugging:

```cmd
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
shutdown /r /t 0
```

## Loading the Driver

Copy the built driver to the VM:

```text
C:\DriverLab\VulnDr.sys
```

Create and start the driver service:

```cmd
sc.exe create VulnDr type= kernel start= demand binPath= C:\DriverLab\VulnDr.sys
sc.exe start VulnDr
```

Stop and delete the service:

```cmd
sc.exe stop VulnDr
sc.exe delete VulnDr
```

## WinDbg Notes

Useful WinDbg commands:

```text
.symfix C:\Symbols
.reload
ed nt!Kd_IHVDRIVER_Mask 0xffffffff

lm m VulnDr
x VulnDr!*
!drvobj \Driver\VulnDr 7
!object \Device\VulnDr
!devobj \Device\VulnDr

bp VulnDr!VulnDrDeviceControl
bp VulnDr!VulnDrHandleVulnStackOverflow
bp VulnDr!VulnDrUnsafeStackCopy

!irp @rdx
!analyze -v
kv
```

## Main Learning Points

By the end of this section, the reader should understand:

- How a basic Windows kernel driver is structured
- How a driver is loaded and unloaded
- What device objects and symbolic links are
- How user mode opens a handle to a driver
- What IRPs are
- How IOCTLs work
- How `DeviceIoControl` reaches `IRP_MJ_DEVICE_CONTROL`
- How `METHOD_BUFFERED` uses `SystemBuffer`
- Why IOCTL buffer validation matters
- How vulnerable driver bugs can come from trusting user-controlled fields
- How WinDbg can be used to observe and debug driver behavior

## Disclaimer

This code is intentionally written for educational driver research in an isolated VM. The vulnerable IOCTL is designed to demonstrate a bug class and may crash the test machine. Do not run this code on production systems.