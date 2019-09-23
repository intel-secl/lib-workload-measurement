# Intel<sup>®</sup> Security Libraries for Data Center  - Workload Measurement Library
#### This library is responsible for performing the measurement of files/symlinks/directories installed as part of an application.

## Key features
- Provides an interface to get the measurements corresponding to a set of files/symlinks/directories
- Provides a cumulative hash of all the measurements

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- maven (v3.3.1)
- ant (v1.9.10 or more)

# Step By Step Build Instructions
## Install required shell commands
Please make sure that you have the right `http proxy` settings if you are behind a proxy
```shell
export HTTP_PROXY=http://<proxy>:<port>
export HTTPS_PROXY=https://<proxy>:<port>
```
### Install tools from `yum`
```shell
$ sudo yum install -y wget git zip unzip ant gcc patch gcc-c++ openssl-devel makeself
```

## Direct dependencies
Following repositories needs to be build before building this repository,

| Name                       | Repo URL                                                 |
| -------------------------- | -------------------------------------------------------- |
| common-java                | https://github.com/intel-secl/common-java                |

## Build Workload Measurement Library

- Git clone the `Worklaod Measurement Library`
- Run scripts to build the `Workload Measurement Library`

```shell
$ git clone https://github.com/intel-secl/lib-workload-measurement.git
$ cd lib-workload-measurement
$ ant
```

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)
