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

Operation
=========
On start, all default parameters are written to the sysfs files,
then command line parameters are evaluated and parameter files
are updated. Next, the appropriate cpus are signaled to begin
scanning and each result file is polled until the result is
not busy (not equal to -1). If any scan failures are detected
a message is sent to the console (or stderr) showing which cpus
and which sockets had failing indications. The application either
exits if cycle wait is equal to 0 or stop is requested, otherwise
poll every 1 second looking for a stop command. At the next cycle
interval a new scan is initiated and the results files are again
read and processed.

Executing 'IFS CLI'
===================
> ./in_field_scan_app [command line arguments]

Arguments
=========
-h  :   display usage parameters
-r  :   reload scan blob into each cpu scan processor's memory
-q  :   verbose/quiet mode (0/1 - default = 1)
-s  :   stop all scans and exit app (0/1 - default = 0)
-t  :   thread wait (1-500) - in milliseconds (default = 1)
-d  :   core delay (1-1000) - in milliseconds (default = 1)
-w  :   cycle wait timer (0-525600) - in minutes (default = 0)
-p  :   CSV list of all cpu to test (-1 means all)
-l  :   scan lp0 or lp1 on each core in all sockets (0/1)
-f  :   additional items on failure results (0 to 3)
        1 = add clock time, 2 = add iterations, 3 = add both
-i  :   noint (1:no interrupts during scan, 0:interrupts ok)
-a  :   start chunk (default = 0)
-z  :   stop chunk (blob dependent - default read from sysfs)
-D  :   display iteration time and count
-I  :   inject random error on random core on each iteration
-E  :   display chunk, core, and error/warning code information
-W  :   display excessive time to complete warning

Note:
The cycle wait timer is used to automatically repeat the scan(s)
- 0     means do only 1 scan (no repeats)
- 1440  means repeat the scan(s) at 24 hours intervals
- Min interval=30 minutes, Max interval=525600 minutes (1 year)

Return codes
============
`pass`		:   No issues were found. Exit status value of 0.

`fatal error`	:   A fatal error was encountered and the application 
                    exited. Exit status varies depending on failure 
                    reason.

Execution Example
=================
> ./in_field_scan_app -q0 -s0 -t1 -d1 -w1 -i0 -f3 -D -E -W 

STDOUT SCREEN SHOT BELOW
------------------------

In Field Scan (IFS) Application - Version: 1.5.4
Intel Corporation - Copyright (c) 2022

Command Line      = -q0 -s0 -t1 -d1 -w1 -i0 -f3 -D -E -W 
Scan Blob Version = 0xF0000000
Microcode Version = 0x9137D291

WARNING - Scan repeat interval limited to the minimum of 30 minutes.

Thu Sep 16 21:05:24 2021 - Executing In Field Scan - Iteration #: 1
                           FAILURE: Chunk    0 on CPU #  21, Failure code = 0x02: Scan signature did not match the expected value
                           FAILURE: Chunk    0 on CPU #  61, Failure code = 0x02: Scan signature did not match the expected value
Thu Sep 16 21:05:24 2021 - (iteration # 00001, cycle time = minute 0000000)
                           Failing logical cpu(s)     = 21,61
                           Failing physical core(s)   = 1:1
                           Failing physical socket(s) = 1:NO PPIN

Author
======
Copyright (c) 2022 Intel Corporation