% In Field Scan Command Line Interface(IFS CLI) User's Guide

Synopsis
========
'in_field_scan_app [command line arguments]'

Description
===========
In Field Scan Command Line Interface(IFS CLI) is silicon defect detection 
tool that scans CPU cores for 'stuck at' faults.  It is a stand-alone CLI 
application that requires root privileges and displays testing information
to a user via stdout and stderr.

Installing `IFS CLI`
====================
Extract the file containing IFS CLI to a directory on the target system.

Known Limitations of `IFS CLI`
==============================
Scan repeat intervals are between 30 and 525600 minutes.
Multi-blob support not yet available. For BLOB reload use -r0.

Operation
=========
On start, all default parameters are written to the target files,
then command line parameters are evaluated and parameter files
are updated. Next, the appropriate cpus are signaled to begin
scanning and each status file is polled until the status is
not busy (EBUSY on popen). If any scan failures are detected
a message is sent to the console (or stderr) showing which cpus
and which sockets had failing indications. The application either
exits if cycle wait is equal to 0 or stop is requested, otherwise
poll looking for a stop command. At the next cycle interval a
new scan is initiated and the status files are again read and
processed.

Executing 'IFS CLI'
===================
> ./in_field_scan_app [command line arguments]

Arguments
=========
-h  :   display usage parameters
-r  :   reload scan blob (0-n), where n is number of blobs -1
-s  :   stop all scans and exit app (0/1 - default = 0)
-t  :   thread wait (1-500) - in milliseconds (default = 1)
-d  :   core delay (1-1000) - in milliseconds (default = 1)
-w  :   cycle wait timer (0-525600) - in minutes (default = 0)
-p  :   CSV list of all cpu to test (-1 means all)
-l  :   scan lp0 or lp1 on each core in all sockets (0/1)
-f  :   additional items on failure results (0 to 3)
        1 = add clock time, 2 = add iterations, 3 = add both
-i  :   noint (1:no interrupts during scan, 0:interrupts ok)
-D  :   display iteration time and count
-I  :   inject random error on random core on each iteration
-E  :   display chunk, core, and error/warning code information
-W  :   display excessive time to complete warning
-R  :   number of test retries
-P  :   display passing indication on stdout
-X  :   exit application on error
-F  :   fail on any offline cpu

Note:
The cycle wait timer is used to automatically repeat the scan(s)
- 0     means do only 1 scan (no repeats)
- 1440  means repeat the scan(s) at 24 hours intervals
- Min interval = 30 minutes, Max interval = 525600 minutes (1 year)

Return codes
============
`pass`		:   No issues were found. Exit status value of 0.

`fatal error`	:   A fatal error was encountered and the application 
                    exited. Exit status varies depending on failure 
                    reason.

Execution Example
=================
> ./in_field_scan_app -r0 -s0 -w1 -i1 -R5 -f3 -D -E -W

STDOUT SCREEN SHOT BELOW
------------------------

In-Field Scan (IFS) Application - Version: 1.7.0
Intel Corporation - Copyright (c) 2022

Command Line      = -r0 -s0 -w1 -i1 -R5 -f3 -D -E -W 
Scan Blob Version = 0xF0000000
Microcode Version = 0x8D0003B0

WARNING - Scan repeat interval limited to the minimum of 30 minutes.

Wed Mar  2 19:23:28 2022 - Executing In-Field Scan - Iteration #: 1
                           WARNING: Chunk   0 on CPU #  61, Warning code = 0x01: Other thread could not join

Author
======
Copyright (c) 2022 Intel Corporation
