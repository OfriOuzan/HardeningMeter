# **Hardening Meter**

Copyright (c) OfriOuzan (B4MB1)

# Description
HardeningMeter is an open-source Python tool carefully designed to comprehensively assess the security hardening of 
binaries and systems. Its robust capabilities include thorough checks of various binary exploitation protection 
mechanisms, including Stack Canary, RELRO, randomizations (ASLR, PIC, PIE), None Exec Stack, Fortify, ASAN, NX bit. 
This tool is suitable for all types of binaries and provides accurate information about the hardening status of each 
binary, identifying those that deserve attention and those with robust security measures.
Hardening Meter supports all Linux distributions and machine-readable output, the results can be printed to the screen a table 
format or be exported to a csv.
(For more information see Documentation.md file)

# Execute Scanning Example
Scan the '/usr/bin' directory, the '/usr/sbin/newusers' file, the system and export the results to a csv file.
```
python3 HardeningMeter.py -f /bin/cp -s
```
![HardeningMeterOutput](https://github.com/OfriOuzan/HardeningMeter/assets/104366208/45ae211d-999d-4f08-a0dc-59cb0d488c63)

# Installation Requirements

Before installing HardeningMeter, make sure your machine has the following:
1. `readelf` and `file` commands
2. python version 3
3. pip
4. tabulate

`pip install tabulate`

# Install HardeningMeter

The very latest developments can be obtained via git.

Clone or download the project files (no compilation nor installation is required)
```
git clone https://github.com/OfriOuzan/HardeningMeter
```

# Arguments

## -f --file

Specify the files you want to scan, the argument can get more than one file seperated by spaces.

## -d --directory

Specify the directory you want to scan, the argument retrieves one directory and scan all ELF files recursively.

## -e --external

Specify whether you want to add external checks (False by default).

## -m --show_missing

Prints according to the order, only those files that are missing security hardening mechanisms and need extra attention.

## -s --system

Specify if you want to scan the system hardening methods.

## -c --csv_format'

Specify if you want to save the results to csv file (results are printed as a table to stdout by default).


# Results
HardeningMeter’s results are printed as a table and consisted of 3 different states:
- (X) - This state indicates that the binary hardening mechanism is disabled.
- (V) - This state indicates that the binary hardening mechanism is enabled.
- (-) - This state indicates that the binary hardening mechanism is not relevant in this particular case.
