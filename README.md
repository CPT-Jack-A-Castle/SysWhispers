# SyS Whispers
SHloader is a SysWhispers Shellcode Loader that is currently a Work in Progress. It takes raw shellcode as input and compiles a C++ stub that has been integrated with SysWhispers in order to bypass AV/EDR. The included python builder will work on any Linux system that has Mingw-w64 installed. 

The tool has been confirmed to successfully load Meterpreter and a Cobalt Strike beacon on fully updated systems with Windows Defender enabled. The project itself is still in a PoC/WIP state, as it currently doesn't work with all payloads.

**2/9/22 EDIT: SHloader now includes 5 different ways to execute your shellcode! See below for updated usage. Big thanks to [T.me/TigerMatee](https://github.com/snovvcrash) and their [DInjector](https://github.com/snovvcrash/DInjector) project for inspiration! I highly recommend taking a look at it for more information regarding the shellcode injection techniques and code that this tool is now based on.**

```
┳┻|
┻┳|
┳┻|
┻┳|
┳┻| _
┻┳| •.•)  - Shhhhh, AV might hear us! 
┳┻|⊂ﾉ   
┻┳|
usage: Shhhloader.py [-h] [-p explorer.exe] [-m QueueUserAPC] [-nr] [-v] [-d] [-o a.exe] file

ICYGUIDER'S CUSTOM SYSWHISPERS SHELLCODE LOADER

positional arguments:
  file                  File containing raw shellcode

optional arguments:
  -h, --help            show this help message and exit
  -p explorer.exe, --process explorer.exe
                        Process to inject into (Default: explorer.exe)
  -m QueueUserAPC, --method QueueUserAPC
                        Method for shellcode execution (Options: ProcessHollow, QueueUserAPC,
                        RemoteThreadContext, RemoteThreadSuspended, CurrentThread) (Default: QueueUserAPC)
  -nr, --no-randomize   Disable syscall name randomization
  -v, --verbose         Enable debugging messages upon execution
  -d, --dll-sandbox     Use DLL based sandbox checks instead of the standard ones
  -o a.exe, --outfile a.exe
                        Name of compiled file
```
Video Demo: https://www.youtube.com/watch?v=-KLGV_aGYbw

Features:
* 5 Different Shellcode Execution Methods (ProcessHollow, QueueUserAPC, RemoteThreadContext, RemoteThreadSuspended, CurrentThread)
* PPID Spoofing
* Block 3rd Party DLLs
* Syscall Name Randomization
* XOR Encryption with Dynamic Key Generation
* Sandbox Evasion via Loaded DLL Enumeration
* Sandbox Evasion via Checking Processors, Memory, and Time

Tested and Confirmed Working on:
* Windows 10 21H1 (10.0.19043)
* Windows 10 20H2 (10.0.19042)
* Windows Server 2019 (10.0.17763)

Scan Results as of 2/9/22 (x64 Meterpreter QueueUserAPC): https://antiscan.me/scan/new/result?id=tntuLnCkTCwz

![Scan](https://antiscan.me/images/result/tntuLnCkTCwz.png)
