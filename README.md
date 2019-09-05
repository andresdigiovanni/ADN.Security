# Security Library for .NET

ADN.Security is a cross-platform open-source library which provides security functions to .NET developers.

[![Build Status](https://travis-ci.org/andresdigiovanni/ADN.Security.svg?branch=master)](https://travis-ci.org/andresdigiovanni/ADN.Security)
[![NuGet](https://img.shields.io/nuget/v/ADN.Security.svg)](https://www.nuget.org/packages/ADN.Security/)
[![BCH compliance](https://bettercodehub.com/edge/badge/andresdigiovanni/ADN.Security?branch=master)](https://bettercodehub.com/)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=andresdigiovanni_ADN.Security&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=andresdigiovanni_ADN.Security)
[![Quality](https://sonarcloud.io/api/project_badges/measure?project=andresdigiovanni_ADN.Security&metric=alert_status)](https://sonarcloud.io/dashboard?id=andresdigiovanni_ADN.Security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Basic usage

Example CRC16:

```csharp
var text = "this is a test";
var bytes = Encoding.ASCII.GetBytes(text);
var crc = new CRC16_ANSI();
var result = crc.ComputeChecksum(bytes);
```

## Installation

ADN.Security runs on Windows, Linux, and macOS.

Once you have an app, you can install the ADN.Security NuGet package from the NuGet package manager:

```
Install-Package ADN.Security
```

Or alternatively you can add the ADN.Security package from within Visual Studio's NuGet package manager.

## Examples

Please find examples and the documentation at the [wiki](https://github.com/andresdigiovanni/ADN.Security/wiki) of this repository.

## Contributing

We welcome contributions! Please review our [contribution guide](CONTRIBUTING.md).

## License

ADN.Helpers is licensed under the [MIT license](LICENSE).
