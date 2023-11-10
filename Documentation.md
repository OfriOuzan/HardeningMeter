# Documentation
## Linux
### Binaries
#### States
HardeningMeter’s output is consisted of 3 different states:
- (X) - This state indicates that the binary hardening mechanism is disabled.
- (V) - This state indicates that the binary hardening mechanism is enabled.
- (-) - This state indicates that the binary hardening mechanism is not relevant in this particular case. 
####Check ELFs
HardeningMeter can retrieve a directory or a list of files to be scanned. It loops over the files and directory recursively, looking only for files of type ELF using the `file` command.
It checks if the `f'{file}: ELF'` string is included in the output of the `file` command.
####Readelf
HardeningMeter uses the `readelf` command to check the binary hardening mechanisms. Since the `readelf` command has a 
limitation that only outputs lines of less than 80 characters, we add the `-W` flag to each execution of the `readelf` 
command, which allows an output width greater than 80 characters.
####File Type
The creation of the 'File Type' field consists of 3 steps.
First, HardeningMeter distinguishes between the different ELF binary files. ELFs have different file types that identify 
their behavior, including: Relocatables, Executables, Dynamic Shared Objects, Dynamic Position Independent Executables.
In addition, binary files can be linked statically or dynamically. HardeningMeter first checks the file type in the 
program header section:
```
readelf -W -h <ELF file> | grep -i Type
```
There is a dictionary containing all ELF types in order to check if the type of the readelf file contains one of the 
following dictionary keys:
```
ELF_TYPES = {'DYN (Position-Independent Executable file)': 'PIE', 'REL (Relocatable file)': 'REL', 'DYN (Shared object file)': 'SO', 'EXEC (Executable file)': 'Exec'}
```
If this is the case, the appropriate value is specified as the file type.
HardeningMeter also checks if the file is a Go binary (Golang language). Go binaries are usually different because their 
compilation process is different, and we have found that they usually lack binary hardening mechanisms. We believe that 
the reason for this is that people lack knowledge when it comes to compiling Go binaries.
Then it separates relocatable ELFs from the others because relocatable files do not go through the final linking process
like other types of ELF binaries.
For other files, it adds a check of the linking status (statically linking or dynamically linking) using the 
`file` command. If the file contains a `statically linked` string, the file type starts with ‘Static’, otherwise it 
starts with ‘Dynamic’.
```
file <ELF file> | grep -i statically linked
```
####PIE/PIC
HardeningMeter checks if the file is compiled with Position Independent binary hardening mechanism. We exclude relocatable
files and statically linked files since they can not be position independent.
Then if the file type field is `DYN (Position-Independent Executable file)` or `DYN (Shared object file)` then the code was 
compiled with PIE/PIC.
####RELRO
In order to know whether the code was compiled with RELRO or not, HardeningMeter searches for the `GNU_RELRO` string in 
the program header.
```
readelf -W -l <ELF file> | grep -i GNU_RELRO
```
If the string exists then the ELF file was compiled with RELRO enabled.
####Not Exec Stack
In order to know if the file was compiled with execute code from the stack HardeningMeter checks the `GNU_STACK` 
permissions in the program headers:
```
readelf -W -l <ELF file>
```
If the permissions are `RWE` then the stack is executable, if it only has `RW` then the stack is not executable 
(not stack exec).
####BIND NOW
In order to know whether the code was compiled with BIND NOW or not, HardeningMeter checks if the `(FLAGS)` and `BIND_NOW`
strings are in the dynamic section.
```
readelf -W -d <ELF file>
```
If the strings exist then the ELF file was compiled with BIND NOW enabled.
####Stack Protector
HardeningMeter checks if the file was compiled with stack protector by searching for the `__stack_chk_fail` function which
is called to perform the program's error-handling mechanism when buffer overflow is detected, in the dynamic symbol table: 
```
readelf -W -s --dyn-syms <ELF file> | grep -i __stack_chk_fail
```
It's important to note that the compiler's decision to add stack canaries can vary based on optimization levels, 
compiler settings, and specific code patterns. Therefore, the presence of `__stack_chk_fail` in the compiled code is not 
guaranteed to be present in every code compiled with stack canaries.
####Fortify
When compiling a code using Fortify Source the compiler uses a protected version of functions  which adds checks to 
potentially targeted functions.
In order to identify the targeted functions bucket, HardeningMeter searches for the symbols of the `libc.so.6` file. It 
tries to find the location of the `libc.so.6` file via the `ldd` command which displays a list of shared libraries that 
the specified file depends on.
If it finds the `libc.so.6` file in the list, it uses the path displayed in the output.
However, in cases like relocatable files and statically linked files that are not linked, it can not find the `libc.so.6`
via the `ldd` function, so it searches in strategic locations in the filesystem, using the following command:
```
find /lib /usr/lib /lib64 /usr/lib64 -name "libc.so.6"
```
After finding the `libc.so.6`, it searches for the potentially targeted functions in the dynamic symbol table:
```
readelf -W -s --dyn-syms <ELF file> | grep -i _chk
```
Of course, HardeningMeter does not include the `__stack_chk_fail` function because this function performs the program's 
error-handling mechanism when buffer overflow is detected.
After building the list of the functions that have the `_chk` string, it creates another list of the same functions 
but without the `_chk` string in order to identify the functions that could be fortified but did not.
It then moves to find the functions in the binary file, using the dynamic symbol table HardeningMeter identifies functions 
that are potentially targeted functions or already fortified.
```
readelf -W -s --dyn-syms <ELF file>
```
Lastly, the final output is built by counting the fortified functions out of the potentially targeted functions and 
accordingly mark if fortify is enabled or not if at least one of the potentially targeted functions is fortified.
####ASAN
ASAN is an external check that is performed only when the user enables external checks.
When an ELF file is compiled with ASAN, there is a library named `libasan` and other functions starting 
with `__asan` string in the dynamic symbol table. In order to identify if ASAN is enabled, HardeningMeter does not search 
for the `libasan` library in the dynamic (because this section is missing in both relocatable files and statically 
linked files), it searches for a function that starts with `__asan` string in the dynamic symbol table.
```
readelf -s --dyn-syms <ELF file>
```
If it finds at least one function, then it determines that the file was compiled with ASAN enabled.
### System
####ASLR
HardeningMeter checks the ASLR status according to the following file:
```
/proc/sys/kernel/randomize_va_space
```
It determines ASLR status according to the following:
- If the file contains `0` then the ASLR status is `Disabled`.
- If the file contains `1` then the ASLR status is `Partially Enabled`.
- If the file contains any other number, then the ASLR status is `Fully Enabled`.
####NX bit
HardeningMeter checks the NX bit status using the `dmesg` command.
It determines the NX bit state according to the value presented after the following line:
```
NX (Execute Disable) protection
```