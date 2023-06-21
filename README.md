#Midnight-Quicksand

Motivation for creating this came from analyzing samples from APT28 and APT29 and their evasive methodology. I simply added my own touch to it. I hope it is enlightening.
This is a fairly comprehensive proof of concept (PoC) for a malicious PowerShell script. It checks for various conditions like user privileges, keyboard input, network activity, virtual machine environment, and more to determine if it should run or not. Moreover, it shows clear signs of polymorphism and file infection capability, all the while establishing persistence and remaining ever-changing and unseen, hence the name. It should be noted that running scripts like this or publicly releasing them could cause significant harm to a system, violate user privacy, and likely break various laws. For this reason, I have provided a description of the PoC with support from ChatGPT.

Here are the key aspects:
This PowerShell script is intended to perform several checks for stealthy operation, perform obfuscation techniques, and run a payload under specific conditions. Here is a rough breakdown of its functionality:

1. **Mutex and Privilege Escalation:** The script first creates a mutex to ensure a single instance of itself. If it can't gain control of the mutex, it exits. It then checks if it's running with administrator privileges. If not, it restarts itself with elevated privileges.

2. **Stealth Checks:** The script performs a number of checks to see if it's running under debugging, or if it's being run on a virtual machine or a system with specific monitoring DLLs loaded. It also checks for an attached debugger or keystrokes. These steps are designed to help the script avoid being analyzed by security researchers or automated analysis tools.

3. **Payload Preparation and Execution:** The script then prepares a payload that includes turning off the User Account Control (UAC) to avoid any user prompt when it tries to perform privileged operations, and launching a payload as a new thread in the process's context. 

4. **File Manipulation:** The script also enumerates `.ps1` PowerShell scripts from the local and network drives, and then modifies each file by adding a calculated MD5 hash at the top as a checksum, a string at the beginning of the file (encrypted using a simple XOR cipher), and modifying the permissions to allow full control to the current user. 

5. **Obfuscation:** To make the code harder to understand and analyze, it employs a simple form of code obfuscation by creating dynamic functions in a string and executing them with `Invoke-Expression`. 


6. **Polymorphism**: The function `mq($main, $filename)` and the appended `quicksand` block indicate polymorphic behavior. The function generates a key of random length and content and uses it to xor-encrypt a payload string. This results in a different, encrypted payload every time the function is executed. This polymorphic behavior makes it harder for traditional signature-based detection systems to recognize and block the script.

7. **File Infection Capability**: The function `Midnight($main)` is responsible for file infection. It checks all local and network `.ps1` files, computes their MD5 hash, and then writes an infected copy of the file with a checksum in the form of a comment. It also modifies the Access Control List (ACL) for the parent directory and the file itself to grant the current user full control. If a file already contains an infected version of the script (detected via the checksum comment), it is not infected again.

Below is a more "under-the-hood" view of how mq performs its malicious actions without being caught by AV or EDR:

1. The script defines a function called "Midnight" that takes a single parameter named "$main." This function is responsible for executing a series of checks and actions.

2. The function begins by creating a mutex object using the `System.Threading.Mutex` class. This mutex ensures that only one instance of the script can run at a time by checking for ownership of the mutex.

3. The script attempts to acquire ownership of the mutex by calling the `WaitOne` method on the mutex object. If ownership is already acquired by another instance of the script, the current instance exits.

4. Next, the script checks if the current user has administrative privileges. If not, it starts a new PowerShell process with elevated privileges using the `Start-Process` cmdlet and exits the current instance.

5. The script defines an array called "$artifacts" that contains a list of file names. It then checks if any of these artifacts (DLL files) are loaded by the current PowerShell process. If any of the artifacts are found, the script exits. List contains common analysis dlls.

6. The script dynamically adds two C# code blocks using the `Add-Type` cmdlet. The first code block defines a class called "DebuggerCheck" that contains a P/Invoke declaration for the `IsDebuggerPresent` function from the kernel32.dll library. This function is used to check if a debugger is present. If a debugger is detected, the script exits.

7. The second code block defines a class called "Keyboard" that contains P/Invoke declarations for the `GetAsyncKeyState` and `IsAnyKeyPressed` functions from the user32.dll library. These functions are used to monitor how many keys are pressed.

8. The script generates a random sleep period between 15 and 40 seconds using the `Get-Random` cmdlet and pauses the script execution for that duration.

9. After the sleep period, the script checks how many keys were pressed. If threshhold is met, it outputs "Midnight" and continues to the next step. Otherwise, it exits the script.

10. The script retrieves the active TCP connections using the `Get-NetTCPConnection` cmdlet and filters for established connections. If the number of established connections exceeds 100, the script exits. This evades large OSINT sandboxes like VT and Joesandbox.

11. The script checks if a debugger is attached to the current PowerShell process using the `IsAttached` property of the `System.Diagnostics.Debugger` class. If a debugger is attached, the script exits.

12. The script checks if the system is running inside a virtual machine (VM) by inspecting the "Model" information obtained from the `systeminfo` command output. If the model matches any of the predefined VM strings (VirtualBox, VMWare, Hyper-V, Xen, QEMU), the script exits.

13. The script checks the loaded modules of the current process and exits if the "dbgcore.dll" module is found.

14. The script retrieves the number of logical processors using the `Get-WmiObject` cmdlet and the `Win32_ComputerSystem` class. If the number of logical processors is less than or equal to 2, the script exits.

15. Another C# code block is added to the script, defining a class called "Mouse" with a P/Invoke declaration for the `GetCursorPos` function from the user32.dll library. This function retrieves the current position of the mouse cursor.

16. The script records the initial mouse cursor position and sleeps for a random duration between 15 and 40 seconds.

17. After the sleep period, the script retrieves the new mouse cursor position and compares it to the initial position. If the positions are the same, indicating no mouse movement, the script exits.

18. The script retrieves information about network adapters using the `Get-WmiObject` cmdlet and the `Win32_NetworkAdapter` class. It checks if the adapter names contain "VMware" or "VirtualBox" and exits if any matching adapters are found.

19. The script retrieves the drive letters of network connections using the `Get-WmiObject` cmdlet and the `Win32_NetworkConnection` class. It then searches for PowerShell script files (*.ps1) within those network drives and adds them to the `$filenamesNetwork` array.

20. The script searches for PowerShell script files (*.ps1) on all physical drives and adds them to the `$filenamesLocal` array.

21. The script concatenates the arrays `$filenamesNetwork` and `$filenamesLocal` to create the `$filenames` array, containing all the PowerShell script files found.

22. For each filename in the `$filenames` array, the script performs the following actions:
    - Reads the contents of the file and calculates an MD5 hash of the filename to create a checksum.
    - Checks if the first line of the script is a comment containing the calculated checksum. If it matches, the script skips to the next filename.
    - Renames the original file to a temporary name with the ".dat" extension.
    - Writes the checksum, an initialization string(quicksand payload - encrypted with polyxor), and the original script contents to the renamed file.
    - Grants full control permissions to the current user for the parent directory and the renamed file.
    - Renames the file back to its original name, overwriting the temporary ".dat" file.

23. The script defines a function called "mq" that takes the `$main` and `$filename` parameters. This function generates a random key and uses it to encrypt the `$main` string using an XOR cipher. It returns the encrypted string.

24. The script defines another function called "xorCipherBytes" that takes the `$textBytes` and `$key` parameters. This function performs an XOR operation between the text bytes and key bytes to decrypt the text and returns the decrypted string.

25. The script defines a final function called "xorCipher" that takes the `$text` and `$key` parameters. This function converts the text and key into byte arrays and calls the "xorCipherBytes" function to perform the XOR encryption. It then converts the encrypted byte array to a Base64 string and returns the result.

26. The script reads the content of the current script file, and assigns it to the `$main` variable.

27. The script calls the "mq" function, passing the `$main` variable, to encrypt the `$main` string.

28. A dynamic polymorphic payload is computed with the `$quicksand` variable, this payload contains a simple inline loader for shellcode execution, further evasive functionality, and more polymorphic encryption. The "quicksand" payload will be broken down in the subsequent points.

29. The script adds another C# code block, defining a class called "AdminLauncher" that contains two methods. The first method, "RunAsAdmin," checks if the current user has administrator privileges and, if not, starts a new process with elevated privileges using the `ProcessStartInfo` class and the "runas" verb. The second method, "DisableUAC," modifies the registry settings to disable User Account Control (UAC).

30. The script checks if the current user is system (implying system privileges), and if not it will download and execute psexec.exe from 'https://live.sysinternals.com/psexec.exe' and save it to the 'C:\Temp\psexec.exe' path using the `Invoke-WebRequest` cmdlet.

31. The script retrieves the path of the current script using `$MyInvocation.MyCommand.Path` and assigns it to the `$scriptPath` variable.

32. The script executes the downloaded psexec.exe file with the `-i -s powershell.exe -ExecutionPolicy Bypass -File $scriptPath` arguments using the `&` (call operator) and the path to psexec.exe.

33. The script adds yet another C# code block, defining a class called "ShellCodeRunner." This class contains several P/Invoke declarations for various functions related to thread creation, thread context manipulation, and internal process module checks. The class also includes a `Run` method that performs several checks, including API hooking detection, and unexpected module detection. Finally, if all checks are passed, shellcode is executed with SYSTEM privileges in a new suspended thread.

34. The ShellCodeRunner "Run" method will check for unexpected modules and attempt to call Freelibrary on these modules, it will also check for hooks on the functions "CreateThread", "GetCurrentThread", "GetThreadContext", "SetThreadContext", and "ResumeThread", if no unexpected modules or hooks are found, the method proceeds to execute the shellcode.

35. The script defines a variable `$hexShellcode` with a placeholder value "00112233445566778899aabbccddeeff." This variable is meant to hold the actual shellcode in hexadecimal format (beacon, RAT, or other shellcodes).

36. The script converts the `$hexShellcode` into a byte array using the `FromBase64String` method and assigns it to the `$shellcodeBytes` variable.

37. The script invokes the `Run` method of the `ShellCodeRunner` class, passing the `$shellcodeBytes` as the shellcode to execute.

38. Finally, the script calls the `Midnight` function, passing the encrypted `$main` string, which triggers the execution of the entire script.

39. In addition, the entire script is then encrypted with a polymorphic AES CBC cipher and packed within a new script(this packer is basically just the quicksand payload loader stub).  This creates 3 dynamic layers of polymorphic encryption.


FUD (06/20/2023 - no payload https://www.virustotal.com/gui/file/75f4348cbe5c40fd67c386ac57084c8a3998099c625344caed835adfe117db99?nocache=1) ; FUD with Cobalt shellcode beacon 06/20/23 (https://www.virustotal.com/gui/file/816758e843786d956cdf0b2fb13b38d57e70264305c6435d4b211a43d2710957/detection)

****NOTE****
Since there is so much head fuckery in this scripts evasion, specifically the decryption logic at runtime, here is the decryption flow when the quicksand payload is finally invoked:
POLYXOR --> B64 --> POLYAESCBC --> B64 --> POLYXOR --> B64 | iex

Also if this virus is caught, it is during the shellcode execution stage, which due to the programs logic, means that every file has already been infected with a polymorphic more encrypted version of itself, Happy Hunting AVs!
****Special Shoutout****
Zenbox - flagged as "malware evader" 06/21/23, good work zenbox. Now if only AVs would follow suit..
Plaintext PoC only 13 detections, give it up for your MVPs:
ALYac
Arcabit
Baidu
BitDefender
Emsisoft
eScan
GData
Kaspersky
MAX
McAfee (oh yea brudder)
FireEye
VIPRE
ZoneAlarm
*****
These vendors as well lose their detection it after the final layer of encryption
FUD 06/21/23 https://www.virustotal.com/gui/file/b3ee4e8cf427712ed864e3499ec974165fd4cbea06b93226a5c565accd917b98/community
