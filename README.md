# Vulnerable Driver Research

A Windows kernel driver research repository for learning WDM driver development, IOCTL handling, WinDbg debugging, and vulnerable driver analysis inside an isolated VM lab.

This repository follows a blog-series style structure. The goal is to start from basic Windows driver development, understand how user-mode applications communicate with kernel drivers, and then gradually move toward vulnerable-driver hunting and reverse engineering.

Read the blog [here](https://crypt0ace.github.io/)

> **Warning**
>
> This repository is for educational research in an isolated lab environment only. It contains intentionally vulnerable driver code for learning and crash analysis. Do not load these drivers on a production system or your main machine.

## Safety Notes

Use a disposable VM snapshot before loading the driver.

Do not run the vulnerable driver on a production machine.

Do not enable test signing on a real workstation unless you understand the security implications.

The vulnerable code is intentionally included for local crash analysis and learning purposes only.

## Disclaimer

This project is intended only for security education, vulnerability research, and defensive learning in a controlled lab environment. The author is not responsible for misuse or damage caused by running this code outside an isolated test environment.
