/*!
*****************************************************************************

INTEL CONFIDENTIAL

Copyright (c) 2021 Intel Corporation. All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.
  * Neither the name of Intel Corporation nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*****************************************************************************
\file scan_field_app.c

\brief Linux application to control scan at field tests

\par NOTES:
            Reload the scan blob on all scan processors:
            - sudo echo 1 > /sys/devices/system/cpu/scan/reload

            Run the scan test on all cpus:
            - sudo echo 1 > /sys/devices/system/cpu/scan/run_test_all

            Stop repeating scans on targeted cpus:
            - sudo echo 1 > ./SAF_User_Files/stop_test_all

            Load start chunk for cpuX:
            - sudo echo A > /sys/devices/system/cpu/cpu<X>/scan/start_chunk

            Load stop chunk for cpuX:
            - sudo echo Z > /sys/devices/system/cpu/cpu<X>/scan/stop_chunk

            Run the scan test for a target cpu:
            - sudo echo 1 > /sys/devices/system/cpu/cpu<X>/scan/scan_start

            After start, read this file for each cpu result as follows:
            - cat /sys/devices/system/cpu/cpu<X>/scan/scan_result
                : -1 = scan is in progress
                :  other values are evaluated by the application

            After all scans complete, display string with all failing cpus
            and all failing sockets.

            Command line parameters:
            -h  :   display usage parameters
            -r  :   reload scan blob into each cpu scan processor's memory
            -q  :   verbose/quiet mode (0/1 - default = 1)
            -s  :   stop all scans and exit app (0/1 - default = 0)
            -t  :   thread wait (1-500) - in milliseconds (default = 1)
            -d  :   core delay (1-1000) - in milliseconds (default = 1)
            -w  :   cycle wait timer (0-1440) - in minutes (default = 0)
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

            The cycle wait timer is used to automatically repeat the scan(s)
            - 0     means do only 1 scan (no repeats)
            - 1440  means repeat the scan(s) at 24 hours intervals
            - Min interval=30 minutes, Max interval=525600 minutes (1 year)

            Operation:
            On start, all default parameters are written to the target files,
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

*****************************************************************************
\par REVISION HISTORY:

01/25/2021       wlhines          Original draft
02/08/2021       wlhines          Formatting of console output modifications
02/12/2021       wlhines          Removed definitions and code used for debug
02/17/2021       wlhines          Modified time to read next cycle result
03/03/2021       wlhines          Modified directory names and added chunks
03/04/2021       wlhines          Modified directory names and scan restart
03/09/2021       wlhines          Added ctrl-c handler and modified defaults
03/10/2021       wlhines          Additional checking of -p string
03/10/2021       wlhines          Created SAF_User_Files directory and files
05/05/2021       wlhines          Modified to add error code/text on failure
05/06/2021       wlhines          Modified to add excess time warning
05/20/2021       wlhines          Changed noint documentation from 0 to 1
05/20/2021       wlhines          Added version number to stdout splash
06/02/2021       wlhines          Fixed failed socket indication
06/04/2021       wlhines          Rearranged functions
06/08/2021       wlhines          Fixed string overflow on XCC parts
06/08/2021       wlhines          Added errorFile for copying stderr
06/23/2021       wlhines          Added scan blob version
06/23/2021       wlhines          Added microcode version
06/23/2021       wlhines          Added socket ppin code for failed cpu
07/12/2021       wlhines          Increased signal stack size (Fix SIGSEGV)
08/02/2021       wlhines          Fixed warning/error chunk reported
08/04/2021       wlhines          Added the ability to scan LP0 or LP1
08/23/2021       wlhines          Fixed bugs in read scan results file
08/25/2021       wlhines          Added repeat interval limit warnings
08/25/2021       wlhines          Fixed INT and LONG max and min values
08/27/2021       wlhines          Updated display for -h command
08/30/2021       wlhines          Changed socket PPIN variable to unsigned
08/31/2021       wlhines          Added failing physical core ID 
09/04/2021       wlhines          Display command line parameters

*****************************************************************************
*/

/* Includes */
#include <dlfcn.h>
#include <error.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Check for 64-bit compiler
#if __GNUC__
  #if __x86_64__ || __ppc64__
    #define ENV_64BIT
  #else
    #define ENV_32BIT
  #endif
#endif

/* Definitions */
#define VERSION "1.5.3"
#define ROOT 0
#define BUSY "-1"
#define PASSED "0"
#define FAILED "1"
#define MAX_CPUS 2048
#define EMPTY_STRING ""
#define ERROR_FILE stderr
#define OUTPUT_FILE stdout
#define ONE_MINUTE 60
#define POLLING_DWELL 10000
#define MIN_SCAN_INTERVAL 30        // TODO - 1 minute for testing
#define MAX_SCAN_INTERVAL 525600    // 1 year
#define INT_MAX 2147483647
#define INT_MIN -INT_MAX
#ifdef ENV_64BIT
  #define LONG_MAX 9223372036854775807
  #define LONG_MIN -LONG_MAX
#else
  #define LONG_MAX INT_MAX
  #define LONG_MIN INT_MIN
#endif
#define LKM_NAME "ift"
#define APPLICATION_NAME "scan_field_app"
#define SAF_USER_FILES "./SAF_User_Files"
#define MIN_ERROR_CODE 1001
#define MAX_ERROR_CODE 1004
#define FAILURE_OFFSET 1000
#define NO_RESULTS_FILE 1004
#define DELAY_WARNING_TIME 500
#define NO_ERROR_DETECTED 0
#define LKM_ERROR -1
#define INVALID_CMDLINE_PARAM -2
#define INVALID_CMDLINE_VALUE -3
#define DISPLAY_USAGE -4
#define INVALID_FILE -5
#define INVALID_FILE_PERMISSIONS -6
#define INVALID_EXECUTE_PERMISSIONS -7
#define SCAN_CHUNK_RANGE_ERROR -8
#define INVALID_CHUNK_FILE -9
#define SCAN_FAILURES_DETECTED -10
#define LIBRARY_OPEN_FAILED -11
#define NO_MEMORY -12

/* Enumerations */
enum scanParams {
  stop,
  quiet,
  thread_wait,
  core_delay,
  cycle_wait_time,
  noint
};

enum scanResults { result_busy = -1, result_passed = 0, result_failed = 1 };

/* Function pointers */
int (*numaNodeOfCpu)(int cpu);

/* Structures */
struct sigaction sa, oldAction;

typedef struct warnError {
  int warningLevel;
  int retryLimit;
  char *description;
} warnError;

typedef struct cpuSiblings {
  char List[256];
  int Number;
  int Siblings[4];
  int CoreID;
} cpuSiblings;

/* Warning and error code arrays of structures */
static warnError errorCodeStructureArray[] = {
    {0, 0, "No Error"},
    {0, 0,
     "The installed SCAN program is not valid and"
     " must be reinstalled"},
    {0, 0, "Scan signature did not match the expected value"},
    {0, 0, "Scan status register bits 62 and 63 are both set"},
    {0, 0, "Scan results file missing or corrupt"}};

static warnError warningCodeStructureArray[] = {
    {0, 0, "No Error"},
    {1, 0, "Other thread could not join"},
    {1, 0, "Interrupt occurred prior to SCAN coordination"},
    {1, 0, "Core Abort SCAN Response"},
    {0, 0,
     "Non valid chunks in the range CHUNK_STOP_INDEX :"
     " CHUNK_START_INDEX"},
    {0, 0, "Mismatch in arguments between threads T0/T1"},
    {0, 0, "Core not capable of performing SCAN currently"},
    {0, 0, "Debug Mode. Scan-At-Field results not to be trusted"},
    {1, 0,
     "Exceeded number of Logical Processors (LP) allowed to run "
     "Scan-At-Field concurrently. MAX_CORE_LIMIT exceeded"},
    {1, 0, "Interrupt occurred prior to SCAN start"}};

/* Variables for scan control */
int *g_cpuArray;
int g_cpuArrayLength;
int g_stopScanning;
int g_cycleWaitTime;
int g_numberOfChunks;
int g_chunkSize;
int g_startChunk;
int g_stopChunk;
int g_failedCpu;
int g_failedChunk;
int g_failureCode;
int g_failureTarget;
bool g_alarmSignal;
bool g_addTime;
bool g_addIterations;
bool g_exitApplication;
bool g_injectRandomError;
bool g_displayInterationInformation;
bool g_displayWarningsAndErrors;
bool g_displayTimeToCompleteWarning;
bool g_storeErrorsInFile = true;
bool g_displayDebug = false;
bool g_testOneThread;

struct cpuSiblings *g_cpuSiblings;

/* Sysfs scan files */
const char *scanOneCpuDirectory = "/sys/devices/system/cpu/cpu";
const char *scanAllCpusDirectory = "/sys/devices/system/cpu/scan/";
const char *reloadScanBlobFile = "/sys/devices/system/cpu/scan/reload";
const char *scanBlobVersionFile = "/sys/devices/system/cpu/scan/blob_version";

/* User scan configuration files */
const char *targetedCpusFile = "./SAF_User_Files/cpus";
const char *stopAllScansFile = "./SAF_User_Files/stop_test_all";
const char *cycleWaitTimeFile = "./SAF_User_Files/cycle_wait_time";

/* Signal handler for all assigned signals */
void handler(int signum, siginfo_t *si, void *ucontext) {
  if (signum == SIGALRM)
    g_alarmSignal = true;
  else
    g_exitApplication = true;
}

/* Assign signal handler for desired signals */
void setSignalHandler(int signalNumber) {
  sa.sa_sigaction = handler;
  sa.sa_restorer = NULL;
  sa.sa_flags = SA_ONSTACK;

  sigaction(signalNumber, &sa, &oldAction);
}

/* Set signal handler for desired signals */
bool setSignals(void) {
  bool rv = false;

  stack_t ss;
  static char stack[8 * SIGSTKSZ];

  ss.ss_sp = stack;
  ss.ss_size = sizeof(stack);
  ss.ss_flags = 0;

  if (sigaltstack(&ss, NULL) != -1) {
    // Initialize signal action
    sa.sa_flags |= SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    // Assign signal handlers
    setSignalHandler(SIGALRM);
    setSignalHandler(SIGINT);
    setSignalHandler(SIGQUIT);
    setSignalHandler(SIGTSTP);
    setSignalHandler(SIGHUP);
    setSignalHandler(SIGTERM);

    rv = true;
  } else {
    fprintf(ERROR_FILE,
            "ERROR: '%s' could not set signal handlers - "
            "exiting application.\n",
            APPLICATION_NAME);
  }

  return rv;
}

/* Get position of character or string in a string */
int strpos(char *haystack, char *needle) {
  char *p = strstr(haystack, needle);

  if (p)
    return (p - haystack);
  else
    return -1;
}

/* Check for directory existence */
bool directoryExists(const char *path) {
  struct stat buffer;
  bool rv = false;

  if (stat(path, &buffer) != 0)
    rv = false;
  else if (buffer.st_mode & S_IFDIR)
    rv = true;
  else
    rv = false;

  return rv;
}

/* Check for file existence */
bool fileExists(const char *fileName) {
  struct stat buffer;
  return (stat(fileName, &buffer) == 0);
}

/* print debug information */
void debug(const char *str){
    if(g_displayDebug != true)
				return;
    fprintf(ERROR_FILE, "DEBUG: %s\n", str);
    fflush(ERROR_FILE);
		return;
}

/* Function to verify kernel module is loaded */
bool kernelModuleIsLoaded(void) {
  // Local variables
  bool rv = false;
  FILE *cmd = NULL;
  char buf[256] = EMPTY_STRING;
  char lsMod[256] = EMPTY_STRING;

  // Initialize command strings
		//snprintf(lsMod, sizeof(lsMod) - 1, "lsmod | grep '%s'", LKM_NAME);
  snprintf(lsMod, sizeof(lsMod) - 1, "lsmod | grep -e ift -e saf");

  // Execute command
  cmd = popen(lsMod, "r");

  if (cmd) {
    // Get string returned
    while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
      ;
    pclose(cmd);
		
		debug(buf);
    // If string <> "" LKM is loaded
    if (strlen(buf) != 0)
      rv = true;
  }
  
	//check the file blob_version, because some times the name of driver was renamed.
	if (rv != true)
			if( fileExists(scanBlobVersionFile))
					rv = true;

  // Return result
  return rv;
}

/* Convert command line parameter to int with checking */
bool convertOptArgToInt(char *inStr, int *result) {
  // Local variables
  char *end = NULL;
  bool rv = true;

  // Use base 10
  long lnum = strtol(inStr, &end, 10);

  // if no characters were converted these pointers are equal
  if (end == inStr) {
    fprintf(ERROR_FILE, "ERROR: can't convert string to number \n");
    fflush(ERROR_FILE);
    rv = false;
  }

  // If sizeof(int) == sizeof(long), we have to check for overflows
  if ((lnum == LONG_MAX) || (lnum == LONG_MIN)) {
    fprintf(ERROR_FILE, "ERROR: number out of range for LONG \n");
    fflush(ERROR_FILE);
    rv = false;
  }

  // Because strtol produces a long, check for overflow
  if ((lnum > INT_MAX) || (lnum < INT_MIN)) {
    fprintf(ERROR_FILE, "ERROR: number out of range for INT\n");
    fflush(ERROR_FILE);
    rv = false;
  }

  // Finally cast the result to a int
  *result = (int)lnum;

  // return pass or fail
  return rv;
}

/* Swap integer values */
void swapIntegerValues(int *a, int *b) {
  int tmp = *a;
  *a = *b;
  *b = tmp;
}

/* Sort an integer array (ascending) */
void sortIntegerArray(int intArray[], int numberOfElements) {
  int i, j, minimumIndex;

  for (i = 0; i < (numberOfElements - 1); i++) {
    minimumIndex = i;
    for (j = (i + 1); j < numberOfElements; j++)
      if (intArray[j] < intArray[minimumIndex])
        minimumIndex = j;

    swapIntegerValues(&intArray[minimumIndex], &intArray[i]);
  }
}

/* Remove duplicates from an integer array */
int removeDuplicatesFromSortedArray(int intArray[], int numberOfElements) {
  int newArraySize = 0;

  for (int i = 0; i < numberOfElements; i++) {
    if ((i < (numberOfElements - 1)) && (intArray[i] == intArray[i + 1])) {
      continue;
    }
    intArray[newArraySize++] = intArray[i];
  }

  return newArraySize;
}

/* Get random number within a range */
int randomNumber(int min, int max) {
  return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

/* Search an array for a value */
int findElemenInArray(int array[], int size, int value) {
  int position = -1;

  for (int index = 0; index < size; index++) {
    if (array[index] == value) {
      position = index;
      break;
    }
  }

  return position;
}

/* Split a string on commas and load values into an array */
void splitCommaSeparatedString(char *csv, int array[],
                               int *numElementsPopulated) {
  const int MAX_NUMBER_LENGTH = 5; // 4 digits and null char

  char *comma;
  char *position;

  char numberValue[MAX_NUMBER_LENGTH];
  char numberArray[MAX_CPUS][MAX_NUMBER_LENGTH];

  comma = strchr(csv, ',');
  position = csv;

  int elementCount = 0;

  while (comma) {
    int i = 0;

    while ((position < comma) && (i < (MAX_NUMBER_LENGTH - 1))) {
      numberValue[i++] = *position;
      position++;
    }

    numberValue[i] = '\0';
    strncpy(numberArray[elementCount++], numberValue, MAX_NUMBER_LENGTH);

    position++;
    comma = strchr(position, ',');
  }

  strncpy(numberArray[elementCount++], position, MAX_NUMBER_LENGTH);

  for (int i = 0; i < elementCount; i++)
    array[i] = atoi(numberArray[i]);

  sortIntegerArray(array, elementCount);

  numElementsPopulated[0] =
      removeDuplicatesFromSortedArray(array, elementCount);
}

/* Load array with cores targeted to test */
void getArrayOfCPUs(char *commaSepCPUs, int *array, int *arraySize) {
  int arrayElements = 0;
  splitCommaSeparatedString(commaSepCPUs, array, &arrayElements);
  *arraySize = arrayElements;
}

/* Remove a single character from a string */
void removeCharFromString(char c, char *const target) {
  int strLength = strlen(target) + 1;

  for (int i = 0; i < strLength; i++) {
    if (target[i] == c)
      strncpy(&target[i], &target[i + 1], (strLength - i));
  }
}

/* Remove an entire string from another string */
void removeStringFromString(char *s1, char *s2) {
  int i = 0, j = 0, k = 0;
  while (s1[i]) {
    for (j = 0; (s2[j] && s2[j] == s1[i + j]); j++)
      ;
    if (!s2[j]) {
      for (k = i; s1[k + j]; k++)
        s1[k] = s1[k + j];
      s1[k] = 0;
    } else {
      i += 1;
    }
  }
}

/* Remove leading spaces from string */
void removeLeadingSpaces(char *targetString) {
  int i, idx = 0;

  while (targetString[idx] == ' ' || targetString[idx] == '\t' ||
         targetString[idx] == '\n') {
    idx++;
  }

  if (idx != 0) {
    i = 0;
    while (targetString[i + idx] != '\0') {
      targetString[i] = targetString[i + idx];
      i++;
    }
    targetString[i] = '\0';
  }
}

/* Get rid of final comma in a string */
void removeTrailingComma(char *targetString) {
  if (targetString[strlen(targetString) - 1] == ',')
    targetString[strlen(targetString) - 1] = '\0';
}

/* Open NUMA library and get function pointer */
bool openNumaLibrary(void) {
  bool returnValue = false;

  void *handle = dlopen("libnuma.so.1", RTLD_NOW | RTLD_GLOBAL);
  if (handle) {
    numaNodeOfCpu =
        (__typeof__(numaNodeOfCpu))dlsym(handle, "numa_node_of_cpu");
    if (numaNodeOfCpu)
      returnValue = true;
  }

  return returnValue;
}

/* Read the physical core id of a cpu */
int getCoreId(int cpu) {
  char buf[32] = EMPTY_STRING;
  char dir[256] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;
  char *ptr;
  int rv = -1;

  snprintf(dir, sizeof(dir) - 1, "%s%d%s", scanOneCpuDirectory, cpu,
           "/topology/core_id");

  if (fileExists(dir)) {
    snprintf(command, sizeof(command) - 1, "cat %s", dir);

    FILE *cmd = popen(command, "r");

    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
        ;
      pclose(cmd);

      rv = strtol(buf, &ptr, 10);
    }
  }

  return rv;
}

/* Read the physical package id of a cpu */
int getPhysicalPackageId(int cpu) {
  char buf[32] = EMPTY_STRING;
  char dir[256] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;
  char *ptr;
  int rv = -1;

  snprintf(dir, sizeof(dir) - 1, "%s%d%s", scanOneCpuDirectory, cpu,
           "/topology/physical_package_id");

  if (fileExists(dir)) {
    snprintf(command, sizeof(command) - 1, "cat %s", dir);

    FILE *cmd = popen(command, "r");

    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
        ;
      pclose(cmd);

      rv = strtol(buf, &ptr, 16);
    }
  }

  return rv;
}

/* Read the package PPIN */
unsigned long long getPhysicalPackagePPIN(int cpu) {
  char *ptr;
  char buf[32] = EMPTY_STRING;
  char dir[256] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;
  long long rv = (long long)-1;

  snprintf(dir, sizeof(dir) - 1, "%s%d%s", scanOneCpuDirectory, cpu,
           "/topology/ppin");

  if (fileExists(dir)) {
    snprintf(command, sizeof(command) - 1, "cat %s", dir);

    FILE *cmd = popen(command, "r");

    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
        ;
      pclose(cmd);

      rv = strtoull(buf, &ptr, 16);
    }
  }

  return rv;
}

/* Read the logical proc thread siblings */
void getcpuSiblings(int cpu) {
  char *ptr;
  int siblingsArray[4] = {-1, -1, -1, -1};
  int numberOfSiblings;
  int targetSibling;
  char buf[62] = EMPTY_STRING;
  char dir[256] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;
  char siblingsString[64] = EMPTY_STRING;
  long long rv = (long long)-1;

  snprintf(dir, sizeof(dir) - 1, "%s%d%s", scanOneCpuDirectory, 
           g_cpuArray[cpu], "/topology/thread_siblings_list");

  if (fileExists(dir)) {
   snprintf(command, sizeof(command) - 1, "cat %s", dir);

   FILE *cmd = popen(command, "r");

    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
         ;
       pclose(cmd);

       removeLeadingSpaces(buf);

       if (strpos(buf, ",") >= 0) {
         strncpy(siblingsString, buf, sizeof(siblingsString) - 1);

         if (siblingsString[0] == ',')
            siblingsString[0] = ' ';

        removeLeadingSpaces(siblingsString);
        removeTrailingComma(siblingsString);
        removeCharFromString('\n', siblingsString);
        removeCharFromString('\r', siblingsString);

        getArrayOfCPUs(siblingsString, siblingsArray, &numberOfSiblings);

        if (siblingsArray) {
          strncpy(g_cpuSiblings[cpu].List, siblingsString, 
                  sizeof(siblingsString) - 1);
          g_cpuSiblings[cpu].Number = numberOfSiblings;

          for (int i = 0; i < numberOfSiblings; i++) {
            g_cpuSiblings[cpu].Siblings[i] = siblingsArray[i];
            if (g_cpuSiblings[cpu].Siblings[i] ==  g_cpuArray[cpu])
                targetSibling = i;
          }
          
          if (g_cpuSiblings[cpu].Siblings[targetSibling] != -1)
            g_cpuSiblings[cpu].CoreID = 
              getCoreId(g_cpuSiblings[cpu].Siblings[targetSibling]);
        } 
      }
    }
  }
}

/* Get the scan blob version */
int getScanBlobVersion(void) {
  char *ptr;
  char buf[32] = EMPTY_STRING;
  char file[256] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;
  int rv = -1;

  snprintf(file, sizeof(file) - 1, "%s", scanBlobVersionFile);

  if (fileExists(file)) {
    snprintf(command, sizeof(command) - 1, "cat %s", file);

    FILE *cmd = popen(command, "r");

    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
        ;
      pclose(cmd);

      rv = strtol(buf, &ptr, 16);
    }
  }

  return rv;
}

/* Get information from /proc/cpuinfo */
int grepCpuInformation(char *tag, int base) {
  char *ptr;
  char buf[256] = EMPTY_STRING;
  char command[256] = "cat /proc/cpuinfo | grep ";

  strncat(command, tag, sizeof(command) - 1);

  FILE *cmd = popen(command, "r");
  if (cmd) {
    while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
      ;
    pclose(cmd);

    removeCharFromString('\n', buf);
    removeCharFromString('\r', buf);
  } else {
    strncat(buf, "-1", 3);
  }

  return strtol(buf, &ptr, base);
}

/* Check for hyperthreading */
bool systemIsHyperthreaded(void) {
  char buf[32] = EMPTY_STRING;
  char command[256] = "cat /proc/cpuinfo | grep -o ht | uniq";
  bool rv = false;

  FILE *cmd = popen(command, "r");

  if (cmd) {
    while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
      ;
    pclose(cmd);

    rv = (strncmp(buf, "ht", 2) == 0);
  }

  return rv;
}

/* Get the microcode version */
int getMicrocodeVersion(void) {
  int microcodeVersion =
      grepCpuInformation("'microcode' | sort | uniq | cut -d':' -f2", 16);

  return (microcodeVersion);
}

/* Get the number of physical sockets */
int getPhysicalSocketCount(void) {
  int numberOfSockets =
      grepCpuInformation("'physical id' | sort | uniq | wc -l", 10);

  return ((numberOfSockets == 0) ? 1 : numberOfSockets);
}

/* Get the number of physical cores */
int getPhysicalCoreCount(void) {
  return grepCpuInformation("'cpu cores' | sort | uniq | cut -d':' -f2", 10);
}

/* Save scan parameter to file */
int writeScanParameterValue(int parameter, int value) {
  char dir[256] = EMPTY_STRING;

  switch (parameter) {
  case stop:
    g_stopScanning = value;
    snprintf(dir, sizeof(dir) - 1, "%s", stopAllScansFile);
    break;
  case quiet:
    snprintf(dir, sizeof(dir) - 1, "%s", scanAllCpusDirectory);
    strncat(dir, "quiet", 6);
    break;
  case thread_wait:
    snprintf(dir, sizeof(dir) - 1, "%s", scanAllCpusDirectory);
    strncat(dir, "thread_wait", 12);
    break;
  case core_delay:
    snprintf(dir, sizeof(dir) - 1, "%s", scanAllCpusDirectory);
    strncat(dir, "core_delay", 11);
    break;
  case cycle_wait_time:
    g_cycleWaitTime = value;
    snprintf(dir, sizeof(dir) - 1, "%s", cycleWaitTimeFile);
    break;
  case noint:
    snprintf(dir, sizeof(dir) - 1, "%s", scanAllCpusDirectory);
    strncat(dir, "noint", 6);
    break;
  }

  if (!fileExists(dir)) {
    return INVALID_FILE;
  } else {
    char cmd[256] = EMPTY_STRING;
    snprintf(cmd, sizeof(cmd) - 1, "echo %d > %s", value, dir);
		debug(cmd);
    int systemCallResult = system(cmd);
    return systemCallResult;
  }
}

/* Save CPU array to file */
int writeCPUsArray(int array[], int arrayLength) {
  char dir[1024] = EMPTY_STRING;
  char temp[1024] = EMPTY_STRING;
  char data[1024] = EMPTY_STRING;

  if (g_cpuArray)
    free(g_cpuArray);

  g_cpuArray = (int *)calloc(arrayLength, sizeof(int));
  g_cpuArrayLength = arrayLength;

  if (g_cpuArray) {
    for (int i = 0; i < arrayLength; i++) {
      g_cpuArray[i] = array[i];
      snprintf(temp, sizeof(temp) - 1, "%d", g_cpuArray[i]);
      strncat(data, temp, 5);
      if (i < (arrayLength - 1))
        strncat(data, ",", 2);
    }

    snprintf(dir, sizeof(dir) - 1, "%s", targetedCpusFile);

    if (!fileExists(dir)) {
      return INVALID_FILE;
    } else {
      char command[4096] = EMPTY_STRING;
      snprintf(command, sizeof(command) - 1, "echo %s > %s", data, dir);
				debug(command);
      int systemCallResult = system(command);
      return systemCallResult;
    }
  } else {
    return NO_MEMORY;
  }
}

/* Save LPU array to file */
int writeLPUsArray(int value) {
  char dir[1024] = EMPTY_STRING;
  char temp[1024] = EMPTY_STRING;
  char data[1024] = EMPTY_STRING;

  int numberOfLogicalProcessors = get_nprocs_conf();

  if (g_cpuArray)
    free(g_cpuArray);

  g_cpuArray = (int *)calloc((numberOfLogicalProcessors / 2), sizeof(int));
  g_cpuArrayLength = (numberOfLogicalProcessors / 2);

  if (g_cpuArray) {
    int lpuStart = (value == 0) ? 0 : (numberOfLogicalProcessors / 2);

    for (int i = 0; i < g_cpuArrayLength; i++) {
      g_cpuArray[i] = (lpuStart + i);
      snprintf(temp, sizeof(temp) - 1, "%d", g_cpuArray[i]);
      strncat(data, temp, 5);
      if (i < (g_cpuArrayLength - 1))
        strncat(data, ",", 2);
    }

    snprintf(dir, sizeof(dir) - 1, "%s", targetedCpusFile);

    if (!fileExists(dir)) {
      return INVALID_FILE;
    } else {
      char command[4096] = EMPTY_STRING;
      snprintf(command, sizeof(command) - 1, "echo %s > %s", data, dir);
		  debug(command);
      int systemCallResult = system(command);
      return systemCallResult;
    }
  } else {
    return NO_MEMORY;
  }
}

/* Reload scan blob file into cpu scan processors */
int reloadScanBlob(void) {
  if (!fileExists(reloadScanBlobFile)) {
    return INVALID_FILE;
  } else {
    char cmd[256] = EMPTY_STRING;
    snprintf(cmd, sizeof(cmd) - 1, "echo 1 > %s", reloadScanBlobFile);
		debug(cmd);
    int systemCallResult = system(cmd);
    return systemCallResult;
  }
}

/* Read scan chunk information */
bool readChunkInformation(void) {
  char buf[8] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;
  char chunkSize[256] = EMPTY_STRING;
  char numberOfChunks[256] = EMPTY_STRING;
  bool rv = true;

  g_numberOfChunks = 0;
  g_chunkSize = 0;
  g_startChunk = 0;
  g_stopChunk = 0;

  snprintf(numberOfChunks, sizeof(numberOfChunks) - 1, "%s%s",
           scanAllCpusDirectory, "num_chunks");

  snprintf(chunkSize, sizeof(chunkSize) - 1, "%s%s", scanAllCpusDirectory,
           "chunk_size");

  if (!fileExists(numberOfChunks) || !fileExists(chunkSize)) {
    rv = false;
  } else {
    snprintf(command, sizeof(command) - 1, "cat %s", numberOfChunks);
    FILE *cmd = popen(command, "r");
    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
        ;
      pclose(cmd);

      g_numberOfChunks = atoi(buf);

      if (g_numberOfChunks > 0)
        g_stopChunk = (g_numberOfChunks - 1);

      snprintf(command, sizeof(command) - 1, "cat %s", chunkSize);

      FILE *cmd = popen(command, "r");
      if (cmd) {
        while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
          ;
        pclose(cmd);

        g_chunkSize = atoi(buf);
      } else {
        rv = false;
      }
    } else {
      rv = false;
    }
  }

  return rv;
}

/* Scan at field default parameters - may need to change defaults */
int setParameterDefaults(void) {
  int rv = NO_ERROR_DETECTED;
  int cpuArray[MAX_CPUS];
  int numberOfLogicalProcessors = get_nprocs_conf();

  for (int i = 0; i < MAX_CPUS; i++) {
    if (i < numberOfLogicalProcessors)
      cpuArray[i] = i;
    else
      cpuArray[i] = -1;
  }

  if (readChunkInformation() != false) {
    if ((rv = writeCPUsArray(cpuArray, numberOfLogicalProcessors)) ==
        NO_ERROR_DETECTED)
      if ((rv = writeScanParameterValue(stop, 1)) == NO_ERROR_DETECTED)
        if ((rv = writeScanParameterValue(quiet, 1)) == NO_ERROR_DETECTED)
          if ((rv = writeScanParameterValue(thread_wait, 1)) ==
              NO_ERROR_DETECTED)
            if ((rv = writeScanParameterValue(core_delay, 1)) ==
                NO_ERROR_DETECTED)
              if ((rv = writeScanParameterValue(cycle_wait_time, 0)) ==
                  NO_ERROR_DETECTED)
                rv = writeScanParameterValue(noint, 1);
  } else {
    fprintf(ERROR_FILE,
            "ERROR: '%s' couldn't read scan chunk information - "
            "exiting application.\n",
            APPLICATION_NAME);
    fflush(ERROR_FILE);

    rv = INVALID_CHUNK_FILE;
  }

  // If no errors detected, return # of LPs
  if (rv == NO_ERROR_DETECTED) {
    rv = numberOfLogicalProcessors;
  } else {
    if (rv != INVALID_CHUNK_FILE) {
      fprintf(ERROR_FILE,
              "ERROR: '%s' couldn't update scan parameter(s) - "
              "exiting application.\n",
              APPLICATION_NAME);
      fflush(ERROR_FILE);
    }
  }

  // Return result
  return rv;
}

/* check for optarg */
bool checkForOptArg(int argc, char **argv, char targetArg) {
  char c;
  bool argumentFound = false;

  optind = 1;
  while ((c = getopt(argc, argv, "q:s:t:d:w:p:l:f:i:a:z:rhDIEWG")) != -1) {
    if ((char)c == targetArg) {
      argumentFound = true;
      break;
    }
  }

  return argumentFound;
}

/* Process any/all command line parameters */
void processCommandLineParameters(int argc, char **argv,
                                  int numberOfLogicalProcessors, int *rv) {
  if (argc > 1) {
    int c = 0;
    int value = 0;
    int cpuArray[MAX_CPUS];
    int numberOfTargetedCPUs = 0;
    bool pFound, lFound;
    char cpuString[4096] = EMPTY_STRING;
    char cliArgs[4096] = EMPTY_STRING;
    char *usage =
           " -h  :   display usage parameters\n"
           " -r  :   reload scan blob into each cpu scan processor's memory\n"
           " -q  :   verbose/quiet mode (0/1 - default = 1)\n"
           " -s  :   stop all scans and exit app (0/1 - default = 0)\n"
           " -t  :   thread wait (1-500) - in milliseconds (default = 1)\n"
           " -d  :   core delay (1-1000) - in milliseconds (default = 1)\n"
           " -w  :   cycle wait timer (0-1440) - in minutes (default = 0)\n"
           " -p  :   CSV list of all cpu to test (-1 means all)\n"
           " -l  :   scan lp0 or lp1 on each core in all sockets (0 for LP0 1 for LP1) \n"
           " -f  :   additional items on failure results (0 to 3)\n"
           "         1 = add clock time, 2 = add iterations, 3 = add both\n"
           " -i  :   noint (1:no interrupts during scan, 0:interrupts ok)\n"
           " -a  :   start chunk (default = 0)\n"
           " -z  :   stop chunk (blob dependent - default read from sysfs)\n"
           " -D  :   display iteration time and count\n"
           " -I  :   inject random error on random core on each iteration\n"
           " -E  :   display chunk, core, and error/warning code information\n"
           " -W  :   display excessive time to complete warning\n";
//    char *usage =
//        "[-h][-r][-q (0/1)][-s (0/1)][t (1-500)][-d (1-1000)]"
//        "[-w (e.g. 0-512600)][-p (-1 for all cpus, csv of targets)]"
//        "[-l (0 for LP0, 1 for LP1 on each core)]"
//        "[-f (1-3)][-i (0/1)][-a (0-n)][-z (0-n)][-D][-I][-E][-W]\n\n";

    for (int i = 1; i < argc; i++) {
      strncat(cliArgs, argv[i], strnlen(argv[i], 512));
      strncat(cliArgs, " ", 2);
    }

    pFound = checkForOptArg(argc, argv, 'p');
    lFound = checkForOptArg(argc, argv, 'l');

    if (pFound && lFound) {
      *rv = INVALID_CMDLINE_VALUE;

      fprintf(ERROR_FILE, "CLI args  : %s %s", APPLICATION_NAME, cliArgs);
      fflush(ERROR_FILE);

      fprintf(ERROR_FILE,
              "\nCLI args -p and "
              "-l are incompatable!"
              " Please choose one - "
              "exiting application.\n ",
              APPLICATION_NAME, cliArgs);
      fflush(ERROR_FILE);

      return;
    }

    g_addTime = false;
    g_addIterations = false;
    g_exitApplication = false;
    g_injectRandomError = false;
    g_displayInterationInformation = false;
    g_displayWarningsAndErrors = false;
    g_displayTimeToCompleteWarning = false;
    g_testOneThread = false;

    optind = 1;
    while ((c = getopt(argc, argv, "q:s:t:d:w:p:l:f:i:a:z:rhDIEWG")) != -1) {
      switch ((char)c) {
      case 'q':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 0)
            value = 0;
          else if (value >= 1)
            value = 1;
          *rv = writeScanParameterValue(quiet, value);
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 's':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 0)
            value = 0;
          else if (value >= 1)
            value = 1;
          *rv = writeScanParameterValue(stop, value);
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 't':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 1)
            value = 1;
          else if (value >= 500)
            value = 500;
          *rv = writeScanParameterValue(thread_wait, value);
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'd':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 1)
            value = 1;
          else if (value >= 1000)
            value = 1000;
          *rv = writeScanParameterValue(core_delay, value);
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'w':
        if (convertOptArgToInt(optarg, &value)) {
          if (value < 0)
            value = 0;
          if ((value > 0) && (value < MIN_SCAN_INTERVAL)) {
            value = MIN_SCAN_INTERVAL;
            fprintf(OUTPUT_FILE, "WARNING - Scan repeat interval limited to "
                    "the minimum of %d minutes.\n\n", value);
            fflush(OUTPUT_FILE);
          }
          else if (value > MAX_SCAN_INTERVAL) {
            value = MAX_SCAN_INTERVAL;
            fprintf(OUTPUT_FILE, "WARNING - Scan repeat interval limited to "
                    "the maximum of %d minutes.\n\n", value);
            fflush(OUTPUT_FILE);
          }
          *rv = writeScanParameterValue(cycle_wait_time, value);
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'p':
        if (atoi(optarg) != -1) {
          removeLeadingSpaces(optarg);

          if (strpos(optarg, ",") >= 0) {
            strncpy(cpuString, optarg, sizeof(cpuString) - 1);

            if (cpuString[0] == ',')
              cpuString[0] = ' ';

            removeLeadingSpaces(cpuString);
            removeTrailingComma(cpuString);

            getArrayOfCPUs(cpuString, cpuArray, &numberOfTargetedCPUs);

            if (numberOfTargetedCPUs > 0) {
              char buf[256] = EMPTY_STRING;
              char temp[256] = EMPTY_STRING;

              strncpy(buf, "Invalid targeted cpu value(s) - ", sizeof(buf) - 1);

              for (int i = 0; i < numberOfTargetedCPUs; i++) {
                if ((cpuArray[i] < 0) ||
                    (cpuArray[i] > (numberOfLogicalProcessors - 1))) {
                  snprintf(temp, sizeof(temp) - 1, "%d,", cpuArray[i]);
                  strncat(buf, temp, 10);
                  *rv = INVALID_CMDLINE_PARAM;
                }
              }
              if (*rv == INVALID_CMDLINE_PARAM) {
                removeTrailingComma(buf);
                fprintf(ERROR_FILE, "\n%s\n", buf);
                fflush(ERROR_FILE);
              }
            }
          } else {
            int result = atoi(optarg);
            if ((result < 0) || (result > (numberOfLogicalProcessors - 1))) {
              fprintf(ERROR_FILE, "\nInvalid targeted cpu number - %d.\n",
                      result);
              fflush(ERROR_FILE);
              *rv = INVALID_CMDLINE_PARAM;
            } else {
              cpuArray[0] = result;
              numberOfTargetedCPUs = 1;
            }
          }
          if (*rv != INVALID_CMDLINE_PARAM)
            *rv = writeCPUsArray(cpuArray, numberOfTargetedCPUs);
        }
        break;
      case 'l':
        if (convertOptArgToInt(optarg, &value)) {
          if (systemIsHyperthreaded()) {
            if (value <= 0)
              value = 0;
            else if (value >= 1)
              value = 1;

            *rv = writeLPUsArray(value);

            g_testOneThread = true;
          }
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'f':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 0)
            value = 0;
          else if (value >= 3)
            value = 3;

          switch (value) {
          case 0:
            g_addTime = false;
            g_addIterations = false;
            break;
          case 1:
            g_addTime = true;
            break;
          case 2:
            g_addIterations = true;
            break;
          case 3:
            g_addTime = true;
            g_addIterations = true;
            break;
          }
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'i':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 0)
            value = 0;
          else if (value >= 1)
            value = 1;
          *rv = writeScanParameterValue(noint, value);
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'a':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 0)
            value = 0;
          else if (value >= (g_numberOfChunks - 1))
            value = (g_numberOfChunks - 1);

          if (value >= 0)
            g_startChunk = value;
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'z':
        if (convertOptArgToInt(optarg, &value)) {
          if (value <= 0)
            value = 0;
          else if (value >= (g_numberOfChunks - 1))
            value = (g_numberOfChunks - 1);

          if (value > 0)
            g_stopChunk = value;
        } else
          *rv = INVALID_CMDLINE_VALUE;
        break;
      case 'r':
        *rv = reloadScanBlob();
        break;
      case 'h':
        *rv = DISPLAY_USAGE;
        break;
      case 'D':
        g_displayInterationInformation = true;
        break;
      case 'I':
        g_injectRandomError = true;
        break;
      case 'E':
        g_displayWarningsAndErrors = true;
        break;
      case 'W':
        g_displayTimeToCompleteWarning = true;
        break;
      case 'G':
        g_displayDebug = true;
        break;
      default:
        *rv = INVALID_CMDLINE_PARAM;
        break;
      }

      if (*rv != NO_ERROR_DETECTED)
        break;
    }

    if (*rv == INVALID_FILE) {
      fprintf(ERROR_FILE, "\n%s - A required parameter file is missing.\n",
              APPLICATION_NAME);
      fflush(ERROR_FILE);
    } else if (*rv == INVALID_FILE_PERMISSIONS) {
      fprintf(ERROR_FILE,
              "\n%s - A required file has invalid R/W permissions.\n",
              APPLICATION_NAME);
      fflush(ERROR_FILE);
    }

    if (g_startChunk > g_stopChunk) {
      fprintf(ERROR_FILE, "\n%s - scan chunk range error.\n", APPLICATION_NAME);
      fflush(ERROR_FILE);
      *rv = SCAN_CHUNK_RANGE_ERROR;
    }

    if (*rv != NO_ERROR_DETECTED) {
      fprintf(ERROR_FILE, "CLI args  : %s %s", APPLICATION_NAME, cliArgs);
      fflush(ERROR_FILE);

      fprintf(ERROR_FILE, "\nCLI usage : %s %s", APPLICATION_NAME, usage);
      fflush(ERROR_FILE);
    }
  }
}

/* Read the stop scanning file */
bool readStopScanFile(void) {
  char buf[8] = EMPTY_STRING;
  char dir[256] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;

  snprintf(dir, sizeof(dir) - 1, "%s", stopAllScansFile);

  // On error set buf to '1' to stop current scan

  if (!fileExists(dir)) {
    strncat(buf, "1", 2);
  } else {
    snprintf(command, sizeof(command) - 1, "cat %s", dir);
    FILE *cmd = popen(command, "r");
    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
        ;
      pclose(cmd);
    } else {
      strncat(buf, "1", 2);
    }
  }

  if ((atoi(buf) == 1) && (g_stopScanning == 0))
    g_stopScanning = 1;

  return ((bool)g_stopScanning);
}

/* check global looping variables */
bool exitLoopVariablesCheck(void) {
  return ((g_cycleWaitTime == 0) || (g_stopScanning != 0) || g_exitApplication);
}

/* Update chunks files */
int updateChunksFiles(void) {
  // static bool executedOnce = false;
  int rv = NO_ERROR_DETECTED;

  char startChunk[256] = EMPTY_STRING;
  char stopChunk[256] = EMPTY_STRING;
  char cmd[256] = EMPTY_STRING;

  for (int cpu = 0; cpu < g_cpuArrayLength; cpu++) {
    snprintf(startChunk, sizeof(startChunk) - 1, "%s%d%s", scanOneCpuDirectory,
             g_cpuArray[cpu], "/scan/start_chunk");

    snprintf(stopChunk, sizeof(stopChunk) - 1, "%s%d%s", scanOneCpuDirectory,
             g_cpuArray[cpu], "/scan/stop_chunk");

    if ((!fileExists(startChunk)) || (!fileExists(stopChunk))) {
      rv = INVALID_FILE;
      break;
    } else {
      snprintf(cmd, sizeof(cmd) - 1, "echo %d > %s", g_startChunk, startChunk);
		  debug(cmd);

      int systemCallResult = system(cmd);

      if ((rv = systemCallResult) != NO_ERROR_DETECTED)
        break;
      else {
        snprintf(cmd, sizeof(cmd) - 1, "echo %d > %s", g_stopChunk, stopChunk);
				debug(cmd);

        int systemCallResult = system(cmd);

        if ((rv = systemCallResult) != NO_ERROR_DETECTED)
          break;
      }
    }
  }

  return rv;
}

/* Write command to run all file */
int startScanOnAllCpus(int startScans) {
  char dir[256] = EMPTY_STRING;
  char cmd[256] = EMPTY_STRING;
  int rv = NO_ERROR_DETECTED;

  snprintf(dir, sizeof(dir) - 1, "%s%s", scanAllCpusDirectory, "run_test_all");

  if (!fileExists(dir)) {
    rv = INVALID_FILE;
  } else {
    snprintf(cmd, sizeof(cmd) - 1, "echo %d > %s", startScans, dir);
		debug(cmd);

    int systemCallResult = system(cmd);
    rv = systemCallResult;
  }

  return rv;
}

/* Start scanning on desired logical processors */
int startRequiredScans(int numberOfLogicalProcessors) {
  char dir[256] = EMPTY_STRING;
  char cmd[256] = EMPTY_STRING;
  int rv = NO_ERROR_DETECTED;
  debug("==========Chunk!!!!================");
  if ((rv = updateChunksFiles()) == NO_ERROR_DETECTED) {
		debug("===========STOP ALL===============");
    if ((rv = writeScanParameterValue(stop, 0)) == NO_ERROR_DETECTED) {
      if (g_cpuArrayLength == numberOfLogicalProcessors) {
				debug("===========START ALL===============");
        rv = startScanOnAllCpus(1);
      } else {
        if (rv == NO_ERROR_DETECTED) {
				  debug("===========START CPUS===============");
          for (int cpu = 0; cpu < g_cpuArrayLength; cpu++) {
            snprintf(dir, sizeof(dir) - 1, "%s%d%s", scanOneCpuDirectory,
                     g_cpuArray[cpu], "/scan/scan_start");

            if (!fileExists(dir)) {
              rv = INVALID_FILE;
              break;
            } else {
              snprintf(cmd, sizeof(cmd) - 1, "echo 1 > %s", dir);
						  debug(cmd);

              int systemCallResult = system(cmd);

              if ((rv = systemCallResult) != NO_ERROR_DETECTED)
                break;
            }
          }
        }
      }
    }
  }
  debug("===========SCAN IS DOING===============");

  return rv;
}

/* Read scan results (-1 = busy, 0 = passed, otherwise = failed) */
int readScanResult(int cpu) {
  char buf[32] = EMPTY_STRING;
  char dir[256] = EMPTY_STRING;
  char command[256] = EMPTY_STRING;
  unsigned long statusRegister;
  char *ptr;

  snprintf(dir, sizeof(dir) - 1, "%s%d%s", scanOneCpuDirectory, cpu,
           "/scan/scan_result");

  g_failedCpu = -1;
  g_failedChunk = -1;
  g_failureCode = 0;

  // On error set buf to error code to indicate a scan failure
	debug(dir);
  if (!fileExists(dir)) {
    strncat(buf, FAILED, 2);
    g_failedCpu = cpu;
    g_failedChunk = 0;
    g_failureCode = NO_RESULTS_FILE;
  } else {
    snprintf(command, sizeof(command) - 1, "cat %s", dir);

    FILE *cmd = popen(command, "r");

    if (cmd) {
      while (fgets(buf, sizeof(buf) - 1, cmd) != NULL)
        ;
      pclose(cmd);

      statusRegister = strtoul(buf, &ptr, 16);

      if ((int)strtol(buf, &ptr, 10) == result_busy) {
        strncpy(buf, BUSY, 3);
      } else if ((g_injectRandomError) && (cpu == g_failureTarget)) {
        strncpy(buf, FAILED, 2);
        g_failedCpu = cpu;
        g_failedChunk = randomNumber(g_startChunk, g_stopChunk);
        g_failureCode = randomNumber(MIN_ERROR_CODE, MAX_ERROR_CODE);
      } else if (statusRegister != result_passed) {
        if ((statusRegister & (unsigned long)0xC000000000000000) != 0) {
          g_failedCpu = cpu;
          g_failedChunk = (int)(statusRegister & 0xFF);
          g_failureCode = (int)((statusRegister >> 62) & 0x3) + FAILURE_OFFSET;
          strncpy(buf, FAILED, 2);
        } else {
          g_failureCode = (int)((statusRegister >> 32) & 0xFF);
          if (g_failureCode != 0) {
            g_failedCpu = cpu;
            g_failedChunk = (int)(statusRegister & 0xFF);
            strncpy(buf, FAILED, 2);
          } else {
            strncpy(buf, PASSED, 2);
          }
        }
      } else {
        strncpy(buf, PASSED, 2);
      }
    } else {
      strncpy(buf, FAILED, 2);
      g_failedCpu = cpu;
      g_failedChunk = 0;
      g_failureCode = NO_RESULTS_FILE;
    }
  }

  return atoi(buf);
}

/* Print warning on std out */
void displayWarning(void) {
    char targetString[512] = EMPTY_STRING;
    snprintf(targetString, sizeof(targetString) - 1,
            "WARNING: Chunk %4d on CPU # %3d, "
            "Warning code = 0x%02X: %s",
            g_failedChunk, g_failedCpu, g_failureCode,
            warningCodeStructureArray[g_failureCode].description);

    if (g_addTime)
    fprintf(OUTPUT_FILE, "\n%27s%s", " ", targetString);
    else
    fprintf(OUTPUT_FILE, "\n%s", targetString);

    fflush(OUTPUT_FILE);   
}

/* Print failure on std err */
void displayFailure(void) {
    char targetString[512] = EMPTY_STRING;
    snprintf(targetString, sizeof(targetString) - 1,
        "FAILURE: Chunk %4d on CPU # %3d, "
        "Failure code = 0x%02X: %s",
        g_failedChunk, g_failedCpu, g_failureCode,
        errorCodeStructureArray[g_failureCode].description);

    if (g_addTime)
    fprintf(ERROR_FILE, "\n%27s%s", " ", targetString);
    else
    fprintf(ERROR_FILE, "\n%s", targetString);

    fflush(ERROR_FILE);
}

/* Poll result files until it is time to stop */
void loopUntilScansHaveCompleted(int numberOfLogicalProcessors, int *rv) {
  // Local variables for time
  time_t t;
  struct tm *local;
  char timeString[256] = EMPTY_STRING;

  // Other local variables
  char scanResults[8192] = EMPTY_STRING;
  char coreErrors[1024] = EMPTY_STRING;
  char socketErrors[1024] = EMPTY_STRING;
  char temp[32] = EMPTY_STRING;
  char coreTempResult[512] = EMPTY_STRING;
  char tempResult[512] = EMPTY_STRING;
  char warningText[512] = EMPTY_STRING;
  char iterationsString[256] = EMPTY_STRING;
  int loopErrorDetected = NO_ERROR_DETECTED;
  int *socketErrorArray = NULL;
  int iterationCount = 0;
  int cpuFailureLength = 0;
  int coreFailureLength = 0;
  int savedFailedCpu = 0;
  uint alarmTime = (uint)(ONE_MINUTE * g_cycleWaitTime);
  unsigned long long *socketPpinArray = NULL;

  // Register signal handler for signals
  if (!setSignals())
    return;

  // Get number of physical sockets
  int numberOfSockets = getPhysicalSocketCount();

  // Limit number of sockets
  if (numberOfSockets > 63)
    numberOfSockets = 63;

  // Allocate space for a socket error array
  socketErrorArray = (int *)calloc(numberOfSockets, sizeof(int));

  // Allocate space for a socket ppin array
  socketPpinArray = (unsigned long long *)calloc(numberOfSockets, sizeof(int));

  // Register signal handler to start next cycle
  if (g_cycleWaitTime > 0)
    alarm(alarmTime);

  // Check results of memory allocations
  if (socketErrorArray && socketPpinArray) {
    // Loop on g_cycleWaitTime (0 means oneshot)
    do {
      // Print executing message if necessary
      if (g_displayInterationInformation) {
        // Get time string
        if (g_addTime) {
          t = time(NULL);
          local = gmtime(&t);

          strncpy(timeString, EMPTY_STRING, sizeof(timeString) - 1);

          if (local) {
            snprintf(timeString, sizeof(timeString) - 1, "%s", asctime(local));
            removeCharFromString('\n', timeString);
            strncat(timeString, " - ", 4);
          }
        }

        fprintf(OUTPUT_FILE, "%sExecuting Scan at Field - Iteration #: %d",
                timeString, (iterationCount + 1));
        fflush(OUTPUT_FILE);
      }

      // Initialize results strings
      strncpy(tempResult, EMPTY_STRING, sizeof(tempResult) - 1);
      strncpy(scanResults, EMPTY_STRING, sizeof(scanResults) - 1);
      strncpy(socketErrors, EMPTY_STRING, sizeof(socketErrors) - 1);

      // Initialize failure strings
      if (g_addTime) {
        snprintf(tempResult, sizeof(tempResult) - 1,
                 "%27sFailing logical cpu(s)     = ", " ");

        cpuFailureLength = 55;
      } else {
        snprintf(tempResult, sizeof(scanResults) - 1, 
                 "Failing logical cpu(s)     = ");

        cpuFailureLength = 29;
      }

      if (g_addTime) { 
        snprintf(coreTempResult, (sizeof(coreTempResult) - 1),
                 "\n%27sFailing physical core(s)   = ", " ");

        coreFailureLength = 55;
      } else { 
          snprintf(coreTempResult, sizeof(coreTempResult) - 1,
                   "\nFailing physical core(s)   = ");

          coreFailureLength = 29;
      }

      strncat(scanResults, tempResult, sizeof(scanResults) - 1);
      strncat(coreErrors, coreTempResult, sizeof(coreErrors) - 1);

      // Clear GP buffer
      strncpy(temp, EMPTY_STRING, sizeof(temp) - 1);

      // Set target cpu if injecting a random error
      if (g_injectRandomError)
        g_failureTarget = g_cpuArray[randomNumber(0, (g_cpuArrayLength - 1))];
      else
        g_failureTarget = -1;

      // Variables used by polling loop
      int completionLoopCounter = 0;
      bool completionWarningDisplayed = false;

      // Poll results files and check results
      for (int cpu = 0; cpu < g_cpuArrayLength; cpu++) {
        int cpuScanResult = result_busy;
				
				char dbgString[256] = EMPTY_STRING;
        snprintf(dbgString, sizeof(dbgString) - 1, "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\nChecking [%d]:cpu%d scan", cpu, g_cpuArray[cpu]);
				debug(dbgString);

        while ((cpuScanResult = readScanResult(g_cpuArray[cpu])) ==
               result_busy) {
          usleep(POLLING_DWELL);

          if (g_displayTimeToCompleteWarning) {
            if (completionLoopCounter++ >= DELAY_WARNING_TIME) {
              if (!completionWarningDisplayed) {
                snprintf(warningText, sizeof(warningText) - 1, "%s%s%s",
                         "WARNING: One or more CPUs", " is taking longer than",
                         " expected to complete a scan");

                if (g_addTime)
                  fprintf(OUTPUT_FILE, "\n%27s%s", " ", warningText);
                else
                  fprintf(OUTPUT_FILE, "\n%s", warningText);

                fflush(OUTPUT_FILE);

                completionWarningDisplayed = true;
              }
            }
          }
        }

        snprintf(dbgString, sizeof(dbgString) - 1, "Checking cpu%d: result:%d failureCode:%d", 
								g_cpuArray[cpu], cpuScanResult, g_failureCode);
				debug(dbgString);
        if (cpuScanResult != result_passed) {
          savedFailedCpu = g_failedCpu;
          if ((g_failureCode < FAILURE_OFFSET) && (g_failureCode != 0)) {
            if (g_displayWarningsAndErrors) {
              displayWarning();
              // Sibling result is the same (core warning)
              if (g_testOneThread) {
                int targetCpu = cpu;
                for (int i = 0 ; i < g_cpuSiblings[targetCpu].Number; i++) {

                  if ((g_cpuSiblings[targetCpu].Siblings[i] != g_failedCpu) &&
                      (g_cpuSiblings[targetCpu].Siblings[i] != -1)) {
                      g_failedCpu = g_cpuSiblings[targetCpu].Siblings[i];
                      displayWarning();
                      g_failedCpu = savedFailedCpu;
                  }
                }
              }
            }
          }

          if (g_failureCode >= FAILURE_OFFSET) {
            g_failureCode -= FAILURE_OFFSET;

            if (g_displayWarningsAndErrors) {
                displayFailure();
              // Sibling result is the same (core failure)
              if (g_testOneThread) {
                int targetCpu = cpu;
                for (int i = 0 ; i < g_cpuSiblings[targetCpu].Number; i++) {
                  if ((g_cpuSiblings[targetCpu].Siblings[i] != g_failedCpu) &&
                      (g_cpuSiblings[targetCpu].Siblings[i] != -1)) {
                      g_failedCpu = g_cpuSiblings[targetCpu].Siblings[i];
                      displayFailure();
                      g_failedCpu = savedFailedCpu;
                  }
                }
              }
            }

            *rv = SCAN_FAILURES_DETECTED;

            g_failedCpu = savedFailedCpu;

            int physicalPackageOfCpu = getPhysicalPackageId(g_failedCpu);

            int physicalCoreOfCpu = g_cpuSiblings[cpu].CoreID;

            int numaNodeValue = numaNodeOfCpu(g_failedCpu);

            if (physicalPackageOfCpu >= 0)
              socketErrorArray[physicalPackageOfCpu] = 1;
            else if (numaNodeValue >= 0)
              socketErrorArray[numaNodeValue] = 1;

            socketPpinArray[physicalPackageOfCpu] =
                getPhysicalPackagePPIN(g_failedCpu);

            snprintf(temp, sizeof(temp) - 1, "%d,", g_cpuArray[cpu]);
            strncat(scanResults, temp, sizeof(scanResults) - 1);

            if (g_testOneThread) {
              int targetCpu = cpu;
              for (int i = 0 ; i < g_cpuSiblings[targetCpu].Number; i++) {
                if ((g_cpuSiblings[targetCpu].Siblings[i] != g_failedCpu) &&
                    (g_cpuSiblings[targetCpu].Siblings[i] != -1)) {
                  g_failedCpu = g_cpuSiblings[targetCpu].Siblings[i];
                  snprintf(temp, sizeof(temp) - 1, "%d,", g_failedCpu);
                  strncat(scanResults, temp, sizeof(scanResults) - 1);
                  g_failedCpu = savedFailedCpu;
                }
              }
            }

            if (g_cpuArray[cpu] < 10)
              cpuFailureLength += 2;
            else if (g_cpuArray[cpu] < 100)
              cpuFailureLength += 3;
            else if (g_cpuArray[cpu] < 1000)
              cpuFailureLength += 4;
            else
              cpuFailureLength += 5;

            if (cpuFailureLength >= 135) {
              strncat(scanResults, "\n", sizeof(scanResults) - 1);

              if (g_addTime) {
                snprintf(tempResult, (sizeof(tempResult) - 1), "%56s", " ");

                cpuFailureLength = 55;
              } else {
                snprintf(tempResult, (sizeof(tempResult) - 1), "%30s", " ");

                cpuFailureLength = 29;
              }

              strncat(scanResults, tempResult, sizeof(scanResults) - 1);
            }

            char cmpOne[32] = EMPTY_STRING;
            char cmpTwo[32] = EMPTY_STRING;
            snprintf(cmpOne, sizeof(cmpOne) - 1, " %d:%d,", 
                     physicalPackageOfCpu, physicalCoreOfCpu);
            snprintf(cmpTwo, sizeof(cmpTwo) - 1, ",%d:%d,", 
                     physicalPackageOfCpu, physicalCoreOfCpu);
            snprintf(temp, sizeof(temp) - 1, "%d:%d,", 
                     physicalPackageOfCpu, physicalCoreOfCpu);

            if ((strpos(coreErrors, cmpOne) < 0) && 
                (strpos(coreErrors, cmpTwo) < 0)) { 
              strncat(coreErrors, temp, sizeof(coreErrors) - 1);

              if (physicalCoreOfCpu < 10)
                coreFailureLength += 2;
              else if (physicalCoreOfCpu < 100)
                coreFailureLength += 3;
              else if (physicalCoreOfCpu < 1000)
                coreFailureLength += 4;
              else
                coreFailureLength += 5;

              if (coreFailureLength >= 135) {
                strncat(coreErrors, "\n", sizeof(coreErrors) - 1);

                if (g_addTime) {
                  snprintf(coreTempResult, (sizeof(coreTempResult) - 1), "%56s", " ");
                  strncat(coreErrors, coreTempResult, (sizeof(coreErrors) - 1));

                  coreFailureLength = 55;
                } else {
                  snprintf(coreTempResult, (sizeof(coreTempResult) - 1), "%30s", " ");
                  strncat(coreErrors, coreTempResult, (sizeof(coreErrors) - 1));

                  coreFailureLength = 29;
                }
              }
            }
          }
        }
        snprintf(dbgString, sizeof(dbgString) - 1, "$$$$$$$$$$$$$$$$$$$$$$Checking cpu%d scan Done$$$$$$$$$$$$$$$$$$$$$$$", cpu);
				debug(dbgString);
      }

      // Bump iteration count
      iterationCount += 1;

      // Display any errors detected
      if (*rv == SCAN_FAILURES_DETECTED) {
        removeTrailingComma(scanResults);
        removeTrailingComma(coreErrors);

        strncat(scanResults, coreErrors, sizeof(scanResults) - 1);

        memset(&coreErrors[0], 0, sizeof(coreErrors));

        if (g_addTime)
          snprintf(tempResult, (sizeof(tempResult) - 1),
                   "\n%27sFailing physical socket(s) = ", " ");
        else
          snprintf(tempResult, sizeof(tempResult) - 1,
                   "\nFailing physical socket(s) = ");

        strncat(socketErrors, tempResult, sizeof(socketErrors) - 1);

        for (int socket = 0; socket < numberOfSockets; socket++) {
          if (socketErrorArray[socket] != 0) {
            snprintf(temp, sizeof(temp) - 1, "%d:", socket);

            strncat(socketErrors, temp, sizeof(socketErrors) - 1);

            if (socketPpinArray[socket] != 0xFFFFFFFFFFFFFFFF) {
              snprintf(temp, sizeof(temp) - 1, "0x%016llX,",
                       socketPpinArray[socket]);
            } else {
              snprintf(temp, sizeof(temp) - 1, "NO PPIN,");
            }

            strncat(socketErrors, temp, sizeof(socketErrors) - 1);

            socketErrorArray[socket] = 0;

            socketPpinArray[socket] = 0xFFFFFFFFFFFFFFFF;
          }
        }

        strncat(scanResults, socketErrors, sizeof(scanResults) - 1);

        removeTrailingComma(scanResults);

        if (g_addTime) {
          t = time(NULL);
          local = gmtime(&t);

          strncpy(timeString, EMPTY_STRING, sizeof(timeString) - 1);

          if (local) {
            snprintf(timeString, sizeof(timeString) - 1, "%s", asctime(local));

            removeCharFromString('\n', timeString);

            strncat(timeString, " - ", 4);
          }
        }

        if (g_addIterations) {
          snprintf(iterationsString, sizeof(iterationsString) - 1,
                   "(iteration # %05d, "
                   "cycle time = minute %07d)",
                   iterationCount, ((iterationCount - 1) * g_cycleWaitTime));
        }

        if ((g_addTime) || (g_addIterations))
          fprintf(ERROR_FILE, "\n");

        fprintf(ERROR_FILE, "%s%s\n%s\n", timeString, iterationsString,
                scanResults);

        fflush(ERROR_FILE);

        loopErrorDetected = SCAN_FAILURES_DETECTED;
        *rv = NO_ERROR_DETECTED;
      } else {
        fprintf(OUTPUT_FILE, "\n");
      }

      // Exit do loop if necessary (or sleep until next cycle)
      if (exitLoopVariablesCheck()) {
        // Exit while loop
        *rv = loopErrorDetected;
        break;
      } else {
        // Exit loop on alarm or requested stop
        int dummyVariable = 0;
        while (true) {
          if (g_alarmSignal || g_exitApplication || readStopScanFile())
            break;
          else
            usleep(500000);
        }

        // Reset variable for next cycle
        if (g_cycleWaitTime > 0) {
          g_alarmSignal = false;
          alarm(alarmTime);
        }

        // Exit function if stop requested
        if (exitLoopVariablesCheck()) {
          *rv = loopErrorDetected;
          break;
        } else {
          // Start another scan
          if ((*rv = startRequiredScans(numberOfLogicalProcessors)) !=
              NO_ERROR_DETECTED) {
            break;
          }
        }
      }
    } while (true);
  } else {
    *rv = NO_MEMORY;
  }

  // Cancel all alarms
  alarm(0);

  // Free malloc'd arrays
  if (g_cpuArray)
    free(g_cpuArray);
  if (g_cpuSiblings)
    free(g_cpuSiblings);
  if (socketErrorArray)
    free(socketErrorArray);
  if (socketPpinArray)
    free(socketPpinArray);
}

/* Check for file and create if necessary */
int createIndividualFile(char *fileName) {
  // Local variables
  int fd;
  int rv = NO_ERROR_DETECTED;
  char command[256] = EMPTY_STRING;

  // Delete file if it exists
  if (fileExists(fileName))
    remove(fileName);

  // Try to create file
  fd = open(fileName, O_RDWR | O_CREAT, 0644);

  // Check result
  if (fd != -1)
    close(fd);
  else
    rv = fd;

  // Return result
  return rv;
}

/* Create files used to repeat scans */
int createRequiredUserFiles(void) {
  // Local variables
  int rv = NO_ERROR_DETECTED;
  char cmd[512] = EMPTY_STRING;
  char cpuFile[512] = EMPTY_STRING;
  char stopFile[512] = EMPTY_STRING;
  char cycleWaitTimeFile[512] = EMPTY_STRING;

  strncpy(cpuFile, SAF_USER_FILES, sizeof(cpuFile) - 1);
  strncat(cpuFile, "/cpus", sizeof(cpuFile) - 1);

  strncpy(stopFile, SAF_USER_FILES, sizeof(stopFile) - 1);
  strncat(stopFile, "/stop_test_all", sizeof(stopFile) - 1);

  strncpy(cycleWaitTimeFile, SAF_USER_FILES, sizeof(cycleWaitTimeFile) - 1);
  strncat(cycleWaitTimeFile, "/cycle_wait_time", sizeof(cycleWaitTimeFile) - 1);

  // Delete directory
  if (directoryExists(SAF_USER_FILES)) {
    snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", SAF_USER_FILES);
    rv = system(cmd);
  }

  // Make required directory
  if (rv == NO_ERROR_DETECTED) {
    if (!directoryExists(SAF_USER_FILES)) {
      mode_t old_mask = umask(0);
      rv = mkdir(SAF_USER_FILES, 0644);
      umask(old_mask);
    }
  }

  // Make required files
  if (rv == NO_ERROR_DETECTED) {
    if ((rv = createIndividualFile(cpuFile)) == NO_ERROR_DETECTED) {
      if ((rv = createIndividualFile(stopFile)) == NO_ERROR_DETECTED) {
        rv = createIndividualFile(cycleWaitTimeFile);
      }
    }
  }

  // Return result
  return rv;
}

/* Application entry point */
int main(int argc, char **argv) {
  // Local variables
  int rv = NO_ERROR_DETECTED;
  char clp[1024] = EMPTY_STRING;

  // Get command line parameters
  for (int i = 1; i < argc; i++) {
    strncat(clp, argv[i], sizeof(clp) - 1);
    strncat(clp, " ", sizeof(clp) - 1);
  }

  // Print splash lines
  fprintf(OUTPUT_FILE, "\nScan at Field (SAF) Application - ");
  fprintf(OUTPUT_FILE, "Version: %s", VERSION);
  fprintf(OUTPUT_FILE, "\nIntel Corporation - Copyright (c) 2021\n");
  fprintf(OUTPUT_FILE, "\nCommand Line      = %s", clp);
  fprintf(OUTPUT_FILE, "\nScan Blob Version = 0x%08X", getScanBlobVersion());
  fprintf(OUTPUT_FILE, "\nMicrocode Version = 0x%08X\n\n",
          getMicrocodeVersion());
  fflush(OUTPUT_FILE);

  // This application must be executed with sudo permissions
  if ((int)geteuid() == ROOT) {
    // Open numa library and get function pointer
    if (openNumaLibrary()) {
      // Make sure kernel module is loaded
      if (kernelModuleIsLoaded()) {
        // Save errors in a file if necessary
        if (g_storeErrorsInFile) {
          // Delete errorFile if it exists
          if (fileExists("./errorFile"))
            system("rm ./errorFile");

          // Tee stderr to errorFile
          FILE *pFile = popen("tee ./errorFile", "w");
          dup2(fileno(pFile), STDERR_FILENO);
        }

        // Seed random number generator
        srand(time(NULL));

        // Create user files to repeat scans if necessary
        if (createRequiredUserFiles() == NO_ERROR_DETECTED) {
          // Default parameters for scan at field
          int numberOfLogicalProcessors = setParameterDefaults();

          // Process all command line arguments
          if (numberOfLogicalProcessors > 0) {
            // Set defaults executed correctly
            processCommandLineParameters(argc, argv, 
                                         numberOfLogicalProcessors,
                                         &rv);

            // Allocate memory for thread siblings data
            g_cpuSiblings = (cpuSiblings *)
              calloc(g_cpuArrayLength, sizeof(cpuSiblings));

            // Get thread siblings and core ids for displays  
            for (int i = 0; i < g_cpuArrayLength; i++) {
              strncpy(g_cpuSiblings[i].List, EMPTY_STRING, 255);
              g_cpuSiblings[i].Number = -1;
              for (int j = 0; j < 4; j++)
                  g_cpuSiblings[i].Siblings[j] = -1;
              g_cpuSiblings[i].CoreID = -1;
              getcpuSiblings(i);
            }
          } else {
            // Return error from setting defaults
            rv = numberOfLogicalProcessors;
          }

          // Check for errors
          if ((rv == NO_ERROR_DETECTED) && (g_stopScanning == 0)) {
            // Start scanning on cpus
            rv = startRequiredScans(numberOfLogicalProcessors);

            // Check return valie
            if (rv == NO_ERROR_DETECTED) {
              // Poll files until time to stop scanning
              loopUntilScansHaveCompleted(numberOfLogicalProcessors, &rv);
            } else {
              // Display file creation error
              fprintf(ERROR_FILE,
                      "ERROR: '%s' could not start the first "
                      "scan - exiting application.\n",
                      APPLICATION_NAME);

              fflush(ERROR_FILE);
            }
          }
        } else {
          // Display file creation error
          fprintf(ERROR_FILE,
                  "ERROR: '%s' could not create required files - "
                  "exiting application.\n",
                  APPLICATION_NAME);

          fflush(ERROR_FILE);

          rv = INVALID_FILE;
        }
      } else {
        // Display kernel module error
        fprintf(ERROR_FILE,
                "ERROR: '%s.ko' is not loaded - "
                "exiting application.\n",
                LKM_NAME);

        fflush(ERROR_FILE);

        rv = LKM_ERROR;
      }
    } else {
      // Display failure to open numa library
      fprintf(ERROR_FILE,
              "ERROR: '%s' failed to open NUMA library - "
              "exiting application.\n",
              APPLICATION_NAME);

      fflush(ERROR_FILE);

      rv = LIBRARY_OPEN_FAILED;
    }
  } else {
    // Display execute permissions error
    fprintf(ERROR_FILE,
            "ERROR: '%s' requires root permissions - "
            "exiting application.\n",
            APPLICATION_NAME);

    fflush(ERROR_FILE);

    rv = INVALID_EXECUTE_PERMISSIONS;
  }

  // Make sure all scans stop
  writeScanParameterValue(stop, 1);

  // Print a newline before final prompt
  fprintf(OUTPUT_FILE, "\n");
  fflush(OUTPUT_FILE);

  // Return exit code
  exit(rv);
}
