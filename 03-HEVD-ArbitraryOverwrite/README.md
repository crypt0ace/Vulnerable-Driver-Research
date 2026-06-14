# HEVD Arbitrary Overwrite Exploits

The goal is to demonstrate different exploitation paths depending on whether common kernel mitigations such as **SMEP** and **kCFG** are enabled. Read the blog [here]()

## Folder Structure

```text
03-HEVD-ArbitraryOverwrite/
├── Source/
│   ├── No-kCFG-No-SMEP.cpp
│   ├── kCFG-Bypass-No-SMEP.cpp
│   ├── kCFG-Bypass-SMEP-Bypass.cpp
│   └── payload.asm
└── README.md
```

## Files

| File                          | Purpose                                                                            |
| ----------------------------- | ---------------------------------------------------------------------------------- |
| `No-kCFG-No-SMEP.cpp`         | Basic arbitrary overwrite exploit for a lab setup without kCFG or SMEP.            |
| `kCFG-Bypass-No-SMEP.cpp`     | Exploit variant that avoids/bypasses kCFG-related issues when SMEP is not enabled. |
| `kCFG-Bypass-SMEP-Bypass.cpp` | Exploit variant that handles both kCFG and SMEP.                                   |
| `payload.asm`                 | Assembly payload used by the SMEP bypass variant.                                  |


## Disclaimer

This code is for educational research in an isolated lab environment only. Do not run it on systems you do not own or have permission to test.
