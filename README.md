#Midnight-Quicksand FUD 07/03/2023 (https://www.virustotal.com/gui/file/89c8424799369da26860683464214fbdf8a88248f0bcd525f80996c16aa5c4c6?nocache=1) (JoeSandbox detection: https://www.joesandbox.com/analysis/1266259)

1. **XOR Cipher Function:** The `xorCipherBytes` and `xorCipher` functions are using XOR cipher, which is a simple encryption algorithm, to either encrypt or decrypt the input data. The key to this algorithm is the `$key` which is used to alter the input data.

2. **Script Reading:** The script reads its own content using `Get-Content $MyInvocation.MyCommand.Path`.

3. **Payload Extraction:** It identifies the section of its code enclosed by `#Procedure:OPEN` and `#Procedure:CLOSE` comments. These lines of code are combined into a string, which is stored in the `$main` variable. 

4. **Thread Synchronization with Monitors:** A mutual exclusion lock (mutex) is established around the call to the `Midnight` function with the `$main` parameter. This lock is acquired and released using the `Enter` and `Exit` methods of the `Monitor` class. This lock is used to prevent concurrent execution of the `Midnight` function by multiple threads. By implementing thread synchronization, the script aims to prevent concurrent execution of the critical code section, making it harder for AV or monitoring tools to detect or analyze the script's behavior. This technique can add an additional layer of complexity and evasion to the script's execution.

5. **Infection Mechanism:** By copying the payload between the `#Procedure:OPEN` and `#Procedure:CLOSE` comments and executing it, the script "infects" other PowerShell scripts. The infected scripts will contain and execute the same payload. 

6. **Mutex**: It starts by creating a mutex (a synchronization primitive) named "Global\Midnight". This technique is often used by malware to ensure only one instance of itself is running on a system at any given time. 

7. **Privilege Escalation**: The script checks if it has administrator rights. If not, it attempts to elevate its privileges by launching a new instance of itself with administrator privileges.

8. **Anti-Analysis/Debugging**: The script then checks for various DLLs that are commonly associated with malware analysis or sandboxing environments. If it finds any, it exits.

9. **Debugger Check**: It further checks if a debugger is present using the `IsDebuggerPresent` function from `kernel32.dll`.

10. **User Interaction**: The script performs checks to see if it's being run in an interactive environment. It checks for a certain number of keys being pressed and mouse movement, then it sleeps for a random period of time between 15 and 40 seconds. 

11. **Network Activity**: The script checks if there are more than 100 established TCP connections. If there are, it exits. 

12. **VM Checks**: It performs checks for signs of virtual machines or debuggers, including checking system information for indications of VM software, and scanning loaded modules for debugging-related DLLs. 

13. **Processor Checks**: The script checks if the machine has more than two logical processors. If not, it exits. 

14. **File Infection**: After all these checks, the script scans the filesystem for PowerShell scripts (.ps1 files), both on local and network drives. For each script it finds, it calculates a checksum, adds it to the script, and checks if the script is already infected. If the script is already infected, it doesn't modify it further. It changes the access permissions to ensure it has full control, then writes the new content to a temporary file, deletes the original file, and renames the temporary file to the original name. 

15. This function starts by generating two random strings, `$str` and `$key`. `$str` is a random hexadecimal string of a length between 16 to 32

 characters, and `$key` is a randomly indexed substring from `$str` with a length equal to the length of `$main`. 

16. The `$main` and `$key` variables are then used as inputs to the `xorCipher` function that was defined in the first section. The result is stored in the variable `$mq`.

17. After that, a PowerShell script is built and stored in the `$quicksand` variable. This script includes multiple class and function definitions that perform various actions:

18. `CheckForHookedAPI`: This function checks for JMP (jump) instructions in the first few bytes of a function at a given memory address. This can be used to detect if a function has been hooked, which could indicate malicious activity. 

19. `AdminLauncher` class with `RunAsAdmin` and `DisableUAC` methods:
   - `RunAsAdmin`: This function attempts to run a program as an administrator. If the current user is not an administrator, it uses the "runas" verb to start a new process with administrative privileges.
   - `DisableUAC`: This function attempts to disable User Account Control (UAC) in Windows. It modifies certain keys in the registry to change UAC settings.

20. `ModuleChecker` class with `CheckForUnexpectedModules` method: This function scans the current process's loaded modules and checks for any that are not located in the Windows folder or have certain file extensions. If any are found, it attempts to unload them and then checks again to see if any unexpected modules are still loaded.

21. `TokenManipulator` class with `CreateProcessWithToken` method: This function duplicates the current process's access token, creates a new environment block for a new process, and then creates that process. The new process is started with the duplicated token, effectively running it under the same security context as the original process.

22. **Escalating Privileges:** The script tries to escalate its privileges to "NT AUTHORITY\SYSTEM", the highest privilege level on a Windows system, using scheduled tasks. If it's not already running as SYSTEM, it creates a scheduled task to run the script at system startup and then restarts the computer.

23. **UAC Bypass:** The script appears to disable UAC (User Account Control), a security feature of Windows, via the "AdminLauncher" object. Disabling UAC can allow the script to perform actions without any prompts or warnings to the user.

24. **Creating and Running Encrypted Batch File:** The script also generates a batch file with numerous commands that alter system settings, disable security measures, and potentially download and execute additional payloads. The batch file is then encrypted using AES and RSA encryption, presumably to avoid detection by antivirus programs. An associated PowerShell function is created to decrypt and execute the contents of this encrypted batch file.

25. **Modifying Windows Defender and Other System Settings:** The script modifies various system settings via the batch file it creates, including disabling Windows Defender, disabling Task Manager, and more. These modifications could potentially make a system more vulnerable to other attacks.

26. **Executing Shellcode:** The script includes functionality for executing shellcode, which is a type of malicious payload. 

27. **File System Permission Manipulation:** It also modifies the file system permissions for the script's directory and file, granting the current user FullControl permissions. This can potentially make it easier for the script to modify or create files in its directory.

28. **Mutual Exclusion with `Monitor.Enter` and `Monitor.Exit`:** These are used to ensure that certain parts of the script do not run concurrently if multiple instances of the script are running. This could be used to prevent race conditions or other unintended behavior, however in this instance, It is used to further avoid AV and EDR monitoring DLLs

So in summary:
The script includes a variety of advanced techniques to perform potentially harmful operations on a Windows system and evade detection.

It exhibits polymorphic characteristics by using randomly generated XOR, AES-CBC, and RSA keys for encryption, which allows it to avoid static detection methods by altering its appearance in each iteration.  Polymorphic viruses change their identifiable features to evade detection by antivirus software. The amalgamation of these techniques in a PowerShell script is indicative of a sophisticated piece of malware designed to infect PowerShell scripts, modify its code to evade detection (polymorphism), and employ evasion techniques to avoid analysis and detection.

It attempts to escalate its privileges, disable security features, manipulate file system permissions, and alter various system settings, potentially leaving a system more vulnerable to other attacks.

It includes functionality to execute shellcode, which can be used to perform various types of malicious activity.

The script infects other PowerShell scripts by adding its payload between specific comments, thus propagating its malicious behavior to other files.

It creates a mutex to ensure only one instance of itself is running on a system at any given time.

The script employs various checks and techniques to avoid analysis and detection, including checking for the presence of debuggers, virtual machines, and DLLs associated with analysis or sandboxing environments.

By leveraging the XOR cipher and using randomly generated keys, AES-CBC, and RSA encryption, it evades static detection and exhibits polymorphic behavior.

It demonstrates sophisticated capabilities such as privilege escalation, UAC bypass, creation and execution of an encrypted batch file, modification of system settings, execution of shellcode, and manipulation of file system permissions.
