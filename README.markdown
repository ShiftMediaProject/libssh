ShiftMediaProject libssh
=============
[![Build status](https://ci.appveyor.com/api/projects/status/da9c0l125dfvsl75?svg=true)](https://ci.appveyor.com/project/Sibras/libssh)
[![Github All Releases](https://img.shields.io/github/downloads/ShiftMediaProject/libssh/total.svg)](https://github.com/ShiftMediaProject/libssh/releases)
[![GitHub release](https://img.shields.io/github/release/ShiftMediaProject/libssh.svg)](https://github.com/ShiftMediaProject/libssh/releases/latest)
[![GitHub issues](https://img.shields.io/github/issues/ShiftMediaProject/libssh.svg)](https://github.com/ShiftMediaProject/libssh/issues)
[![license](https://img.shields.io/github/license/ShiftMediaProject/libssh.svg)](https://github.com/ShiftMediaProject/libssh)
[![donate](https://img.shields.io/badge/donate-link-brightgreen.svg)](https://shiftmediaproject.github.io/8-donate/)
## ShiftMediaProject

Shift Media Project aims to provide native Windows development libraries for libssh and associated dependencies to support simpler creation and debugging of rich media content directly within Visual Studio. [https://shiftmediaproject.github.io/](https://shiftmediaproject.github.io/)

## libssh

Mulitplatform C library implementing the SSHv2 and SSHv1 protocol for client and server implementations. [https://www.libssh.org/](https://www.libssh.org/)

## Downloads

Development libraries are available from the [releases](https://github.com/ShiftMediaProject/libssh/releases) page. These libraries are available for each supported Visual Studio version with a different download for each version. Each download contains both static and dynamic libraries to choose from in both 32bit and 64bit versions.

## Code

This repository contains code from the corresponding upstream project with additional modifications to allow it to be compiled with Visual Studio. New custom Visual Studio projects are provided within the 'SMP' sub-directory. Refer to the 'readme' contained within the 'SMP' directory for further details.

## Issues

Any issues related to the ShiftMediaProject specific changes should be sent to the [issues](https://github.com/ShiftMediaProject/libssh/issues) page for the repository. Any issues related to the upstream project should be sent upstream directly (see the issues information of the upstream repository for more details).

## License

ShiftMediaProject original code is released under [LGPLv2.1](https://www.gnu.org/licenses/lgpl-2.1.html). All code from the upstream repository remains under its original license (see the license information of the upstream repository for more details).

## Copyright

As this repository includes code from upstream project(s) it includes many copyright owners. ShiftMediaProject makes NO claim of copyright on any upstream code. However, all original ShiftMediaProject authored code is copyright ShiftMediaProject. For a complete copyright list please checkout the source code to examine license headers. Unless expressly stated otherwise all code submitted to the ShiftMediaProject project (in any form) is licensed under [LGPLv2.1](https://www.gnu.org/licenses/lgpl-2.1.html) and copyright is donated to ShiftMediaProject. If you submit code that is not your own work it is your responsibility to place a header stating the copyright.

## Contributing

Patches related to the ShiftMediaProject specific changes should be sent as pull requests to the main repository. Any changes related to the upstream project should be sent upstream directly (see the contributing information of the upstream repository for more details).