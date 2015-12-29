#
# Copyright (C) 2009-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

ARCH:=mips64
BOARD:=cn71xx
BOARDNAME:=Cavium Networks Octeon CN71XX
FEATURES:=targz pci usb
CPU_TYPE:=octeon
CFLAGS:=-O3 -pipe -mno-branch-likely -march=octeon -mabi=64 -DOCTEON_MODEL=OCTEON_CN70XX -Wno-unused-parameter -DUSE_RUNTIME_MODEL_CHECKS=1 -DCVMX_ENABLE_PARAMETER_CHECKING=0 -DCVMX_ENABLE_CSR_ADDRESS_CHECKING=0 -DCVMX_ENABLE_POW_CHECKS=0 -DCVMX_USE_1_TO_1_TLB_MAPPINGS=0 -DOCTEON_TARGET=cvmx_64

MAINTAINER:=Abhijit Ayarekar <abhijit.ayarekar@caviumnetworks.com>

LINUX_VERSION:=3.10.20

include $(INCLUDE_DIR)/target.mk

define Target/Description
	Build firmware images for Cavium Networks Octeon 71XX based boards.
endef

$(eval $(call BuildTarget))

