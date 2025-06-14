
# AuthHashCalc
## Authenticode Hash Calculator for PE32/PE32+ files

<img src="https://raw.githubusercontent.com/hfiref0x/AuthHashCalc/master/Screenshots/mainwnd.png" width="600" />
<img src="https://raw.githubusercontent.com/hfiref0x/AuthHashCalc/master/Screenshots/cli.png" width="600" />

# System Requirements

* x86/x64 Windows 7/8/8.1/10/11
* Administrative privileges are not required

# Features
* Portable Executable (PE32/PE32+) authenticode hash calculation (MD5/SHA1/SHA256/SHA384/SHA512);
* WDAC compliant page hash calculation (image header only hash), SHA1/SHA256;
* GUI and CLI version combined in single executable;
* Drag and drop support for GUI version.

# Usage
* Open desired file using button [...], select hash types you want to calculate and press "Calculate" button. Or drop your file using drag and drop operation.
* CLI usage -> run program from console supplying parameter as input filename which authenticode hashes you want to calculate, **e.g. ahc64.exe c:\dir\mydriver.sys**. 
If you want save result to the file then use third parameter as output filename, e.g. **ahc64.exe c:\dir\mydriver.sys c:\dir\result.txt**.

# Build

AuthHashCalc comes with full source code written in C.
In order to build from source you need Microsoft Visual Studio 2015 and later versions.

# Links
* https://docs.microsoft.com/en-us/windows-hardware/drivers/install/authenticode
* https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool

# Authors

(c) 2021 - 2025 AuthHashCalc Project
