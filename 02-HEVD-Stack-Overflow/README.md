# 02 - HEVD - Stack Overflow

This folder contains the code for the second part of the vulnerable driver research series. The code has SMEP bypass as well. In case youre working without SMEP follow the blogbost and you'll find the working code for that as well.

The purpose of this section is to move from a custom vulnerable driver to a public vulnerable driver target, reverse the HEVD stack overflow path, understand how the IOCTL reaches the vulnerable function, and build a small user-mode client to trigger and study the bug in WinDbg.

Read the blog post [here](https://crypt0ace.github.io/posts/Hunting-For-Vulnerable-Drivers-pt-2/)

> **Warning**
>
> This folder contains exploit-development code for a deliberately vulnerable Windows kernel driver. Run it only inside an isolated Windows VM. The code can crash the system and is intended for local lab analysis only.

## Folder Structure

```text
Source/
│
├── HEVDExp.slnx
├── HEVDExp.vcxproj
├── HEVDExp.vcxproj.filters
│
├── main.cpp
│   └── User-mode exploit for HEVD
│
└── payload.asm
    └── x64 assembly payload used during lab testing
```

Generated files such as `payload.bin`, `shellcode.txt`, `shellcode.c`, Visual Studio user files, and build folders are intentionally excluded from the repo.

## Components

### HEVDExp

`HEVDExp` is the user-mode client used to communicate with HackSys Extreme Vulnerable Driver.

It demonstrates:

- Opening the HEVD device from user mode
- Sending IOCTL requests with `DeviceIoControl`
- Triggering the HEVD stack overflow IOCTL
- Controlling the input buffer sent to the driver
- Observing the crash in WinDbg
- Calculating the overwrite offset
- Redirecting execution during controlled lab testing

Device names used:

```text
User-mode path:         \\.\HackSysExtremeVulnerableDriver
```

## Rebuilding the Payload

If NASM is installed, the assembly payload can be rebuilt manually:

```powershell
nasm -f bin payload.asm -o payload.bin
```

The generated `payload.bin` file is not committed to the repository.

## Main Learning Points

By the end of this section, the reader should understand:

- How to move from a custom vulnerable driver to a public vulnerable driver target
- How to identify the HEVD device name used from user mode
- How to send an IOCTL to a kernel driver with `DeviceIoControl`
- How the HEVD stack overflow IOCTL reaches the vulnerable function
- How user-controlled input reaches a kernel stack buffer
- How to use WinDbg breakpoints during driver analysis
- How to inspect registers and stack memory during a crash
- How to calculate the overwrite offset
- Why kernel stack overflows are dangerous
- Why mitigations like SMEP matter during Windows kernel exploitation
- How exploit development can be studied safely inside a VM

## Disclaimer

This code is written for educational driver research in an isolated VM. It targets an intentionally vulnerable driver and may crash the test machine. Do not run this code on production systems or on systems you do not own or have permission to test.
