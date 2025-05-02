# Encryption Detector Library - Documentation

This document provides basic instructions for building and running the Encryption Detector library and its example program on Linux and macOS.

## Prerequisites

*   A C++17 compliant compiler (e.g., GCC, Clang)
*   Make
*   [Premake5](https://raw.githubusercontent.com/premake/premake-core/refs/heads/master/BUILD.txt)

_Note for Windows users: While this project might compile on Windows with appropriate tooling (like MinGW/MSYS2 Make or generating Visual Studio solutions via `premake5 vs20XX`), these instructions focus on Linux/macOS. You'll need to adapt the build and run commands accordingly - deal with the pain yourself._

## Building the Project

1.  **Generate Build Files:**
    Open a terminal in the project's root directory and run Premake to generate the necessary Makefiles:
    ```bash
    premake5 gmake2 
    # Or: premake5 gmake (if gmake2 action is deprecated on your version)
    ```

2.  **Compile:**
    Use Make to build both the static library (`EncryptionDetectorLib`) and the example program (`BasicUsageExample`):
    ```bash
    make
    ```
    This will create output in the `bin/` and `obj/` directories (specifically under `bin/Debug` and `obj/Debug` by default).

## Running the Example Program

The example program (`BasicUsageExample`) demonstrates how to use the library. It's located in `bin/Debug/` after building.

**Usage:**

```
Usage: BasicUsageExample [options] <file_path>
   or: BasicUsageExample [options] -d <directory_path> [-r]
   or: BasicUsageExample --help | -h
```

**Examples:**

*   **Show help:**
    ```bash
    ./bin/Debug/BasicUsageExample --help
    ```
*   **Analyze a single file (default text output):**
    ```bash
    ./bin/Debug/BasicUsageExample AES.md.enc
    ```
*   **Analyze a single file (JSON output):**
    ```bash
    ./bin/Debug/BasicUsageExample AES.md.enc --format json 
    # Other formats: --format yaml, --format xml
    ```
*   **Analyze all files in the current directory:**
    ```bash
    ./bin/Debug/BasicUsageExample -d .
    ```
*   **Analyze files recursively in a directory (YAML output):**
    ```bash
    ./bin/Debug/BasicUsageExample -d src --recursive --format yaml
    ```

## Cleaning Build Files

To remove generated Makefiles, object files, and binaries:

```bash
make clean
```

## Test File Generation

The `premake5.lua` file includes custom actions for generating test files.

*   **Encrypt AES.md:** (Requires `openssl` command)
    ```bash
    premake5 encrypt
    ```
    This creates `AES.md.enc`.

*   **Clean generated test files:**
    ```bash
    premake5 clean_testfiles
    ```
    This removes `AES.md.enc`. 