                     OCTEON SNORTXL LINUX 3.1.0
                     ==========================

This release contains SnortXL software sources for OCTEON 70XX running
Linux. SnortXL takes advantage of a host of OCTEON features to accelerate
Snort Intrusion Detection System. The OCTEON HFA pattern search engine
is utilized by SnortXL to offload snort pattern search processing to 
HFA in asynchronous mode. It also utilizes OCTEON packet engines for
flow distribution and error checking.

This README lists the software dependencies of this release and provides
details on how to install OCTEON SnortXL 3.1.0.

Installation 
------------

Please ensure that following prerequisites are met prior to installation.
The preferred host operating systems are RHEL 5.6 and RHEL 6.0. The
release has the following package dependencies:
    o OCTEON-SDK-3.1.0-534.i386.rpm (patch_release4)
    o OCTEON-LINUX-3.1.0-534.i386.rpm (patch_release4)
    o OCTEON-HFA-SDK-3.1.0-10.i386.rpm
    o libgcrypt-devel-1.4.4-7
    o libgpg-error-devel-1.4-2
    o libpcap-devel-0.9.4-15

The following command can be used to install the RPM, where XX refers
to the build number: 
    # rpm -ivh OCTEON-SNORTXL-LINUX-3.1.0-XX.i386.rpm

OCTEON SnortXL will be installed by default at
/usr/local/Cavium_Networks/OCTEON-SDK/components/snortxl

Please refer to docs/html/index.html at the above location for detailed
instructions on how to build and run SnortXL on OCTEON.
