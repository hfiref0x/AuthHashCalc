[![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2FAuthHashCalc&countColor=%23263759&style=flat)](https://visitorbadge.io/status?path=https%3A%2F%2Fgithub.com%2Fhfiref0x%2FAuthHashCalc)
# AuthHashCalc

## Authenticode Hash Calculator for PE32/PE32+ files

<img src="https://raw.githubusercontent.com/hfiref0x/AuthHashCalc/master/Screenshots/mainwnd.png" width="600" />
<img src="https://raw.githubusercontent.com/hfiref0x/AuthHashCalc/master/Screenshots/cli.png" width="600" />

# System Requirements

* x86/x64 Windows 7/8/8.1/10/11
* Administrative privileges are not required

# Features
* Portable Executable (PE32/PE32+) Authenticode hash calculation (MD5/SHA1/SHA256/SHA384/SHA512)
* WDAC-compliant page hash calculation (image header only hash), SHA1/SHA256
* GUI and CLI versions combined in a single executable
* Drag and drop support for GUI version

# Usage
* Open the desired file using the button [...], select hash types you want to calculate, and press the "Calculate" button. Or drop your file using drag and drop.
* CLI usage: run the program from the console, supplying as a parameter the input filename for which you want to calculate Authenticode hashes, e.g., **ahc64.exe c:\dir\mydriver.sys**.
* If you want to save the result to a file, use a third parameter as the output filename, e.g., **ahc64.exe c:\dir\mydriver.sys c:\dir\result.txt**.

# Build

AuthHashCalc comes with full source code written in C.
To build from source you need Microsoft Visual Studio 2015 or later.

# Links
* https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode
* https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool

# Authors

(c) 2021 - 2025 AuthHashCalc Project
