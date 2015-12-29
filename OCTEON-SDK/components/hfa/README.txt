                        OCTEON-HFA-SDK 3.1.0

This Cavium HFA SDK contains software development tools and libraries to use
Cavium HFA devices namely: OCTEON II/III CN60/61XX, CN62/63XX, CN66XX, CN68XX &
CN70/71XX. Given a set of patterns, the HFA engines find those patterns 
in the input payload. The patterns should be pre-compiled using Cavium hfac 
compiler into a graph and loaded into memory attached to the HFA device.

This document provides details on how to install HFA-SDK.

Installation
------------
Please ensure that the following pre-requisites are met prior to installation

     For OCTEON II/III CN6XXX & CN70/71XX devices:
     This release requires the following OCTEON RPM's
     o OCTEON-SDK-3.1.0-XXX
     o OCTEON-LINUX-3.1.0-XXX

     This release requires following OCTEON SDK patch to be applied
     o patch_release2.tar.bz2

Prior to installation, please uninstall previous installations of the OCTEON
HFA SDK, if any.

The following command can be used to install the RPM, where XX refers to the
build number:
     # rpm -ihv OCTEON-HFA-SDK-3.1.0-XX.i386.rpm

The OCTEON HFA SDK will be installed by default at
/usr/local/Cavium_Networks/OCTEON-SDK/components/hfa

Please also refer to docs/html/index.html at the above location for detailed
usage instructions of OCTEON HFA SDK. You can also find instructions to compile
and run HFA SDK apps on different Cavium HFA devices in the same document.

The Release_Notes.txt document provides details on changes since last release.

Known Issues:
=============
1. Use of Ctrl-C to abort SEUM applications is generally handled gracefully by
   the applications. However, sometimes the applications may not behave well
   under load. For instance, the performance application may misbehave if
   Ctrl-C use when ingress traffic is on. It is recommended to stop all traffic
   before terminating applications. Please note that this limitation is with
   reference applications and not with the HFA SDK Library.
2. OCTEON CN68XX earlier than PASS 2.0 version will show abnormal behavior with
    hfa-se/seum-flow.c and hfa-se/seum-flow-wqe.c applications (ERRATA:
   "SSO-16306").  However OCTEON CN68XX PASS 2.0 revision or more works fine.
3. Unloading OCTEON Ethernet driver module after running HFA LINUX Kernel 
   performance application is unstable. 
4. The HFA RegEx compiler's option "--compfactor" is not functional in this
   release.  
5. Compilation of HFA SDK library and applications for OCTEON CN70XX/CN71XX
   will throw warnings as HFA reference applications are compiled with
   -mhard-float option for OCTEON CN70XX/CN71XX but Post processing libraries
   are pre-compiled with -msoft-float option. Warning are seen while linking
   reference application with Post processing library.
