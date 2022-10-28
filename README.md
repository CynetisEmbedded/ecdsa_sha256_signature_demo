### Prerequisites

- CMake (project built/tested using CMake 3.23.3)
- Linux distro (project built/tested on Ubuntu 20.04 LTS on Windows Subsystem for Linux (WSL2))

### Project architecture

- main.c : main entrypoint
- lib/common : common files for CycloneCRYPTO (Open)
- lib/core : core files for CycloneCRYPTO (Open)
- lib/cyclone_crypto : complete source code for CycloneCRYPTO (Open)
- lib/crypto_config.h : used to enable/disable different CRYPTO modules
- lib/os_port_config.h : contains information about the target platform

### Build

- create a 'build' directory at the project root.
- From within 'build' directory, execute the following commands:
  - cmake ..
  - cmake --build .
- ./ecdsa_sha_demo will run the demo.
  M -pubout -out my_rsa_public.key
- Build the demo using the steps in the previous step.

### Note:

#### About lib/ folder

This folder contains all the files/folders available for CycloneCRYPTO suite. Naturally, not all files/folders are used for this demo.
lib/CMakeLists.txt contains a list of dependencies for the current project.
