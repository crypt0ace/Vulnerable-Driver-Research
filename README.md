# Vulnerable Driver Research

A Windows kernel driver research repository for learning WDM driver development, IOCTL handling, WinDbg debugging, and vulnerable driver analysis inside an isolated VM lab.

This repository follows a blog-series style structure. The goal is to start from basic Windows driver development, understand how user-mode applications communicate with kernel drivers, and then gradually move toward vulnerable-driver hunting and reverse engineering.

Read the blog [here](https://crypt0ace.github.io/)

> **Warning**
>
> This repository is for educational research in an isolated lab environment only. It contains intentionally vulnerable driver code for learning and crash analysis. Do not load these drivers on a production system or your main machine.

## Repository Structure

```text
Vulnerable-Driver-Research/
│
├── README.md
├── .gitignore
│
└── 01-Building-VulnDr/
    ├── README.md
    ├── VulnDr/
    ├── VulnDr_Client/
    └── VulnDrExp/
```

## Current Content

### 01-Building-VulnDr

This section covers the first part of the research series:

- Building a basic Windows WDM kernel driver
- Loading and unloading the driver
- Creating a device object
- Creating a symbolic link
- Opening the driver from user mode
- Implementing IOCTL handling
- Adding safe IOCTLs
- Adding dangerous-looking but safe fake read/write IOCTLs
- Adding one intentionally vulnerable IOCTL
- Triggering the vulnerability from user mode
- Observing driver behavior and crashes in WinDbg

## Lab Environment

The intended lab setup is:

```text
Windows 10 Host
├── Visual Studio
├── Windows Driver Kit
└── WinDbg

VirtualBox Windows 10 VM
├── Test signing enabled
├── Kernel debugging enabled
├── VulnDr.sys loaded here
└── Client/PoC executed here
```

## Safety Notes

Use a disposable VM snapshot before loading the driver.

Do not run the vulnerable driver on a production machine.

Do not enable test signing on a real workstation unless you understand the security implications.

The vulnerable code is intentionally included for local crash analysis and learning purposes only.

<<<<<<< HEAD
=======
## Blog Series Plan (maybe?)

```text
Part 1: Building VulnDr
Part 2: Reversing VulnDr
Part 3: Hunting Real Vulnerable Drivers
```

>>>>>>> 0f738f47ccf0b4517b1b4407259d9ad959e090d0
## Disclaimer

This project is intended only for security education, vulnerability research, and defensive learning in a controlled lab environment. The author is not responsible for misuse or damage caused by running this code outside an isolated test environment.
