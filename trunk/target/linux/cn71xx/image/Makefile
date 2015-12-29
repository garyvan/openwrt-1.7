#
# Copyright (C) 2009-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

#define Image/BuildKernel
#	$(CP) $(LINUX_DIR)/vmlinux $(BIN_DIR)/$(IMG_PREFIX)-vmlinux
#endef

define Image/Build/Initramfs
	$(CP) $(KERNEL_BUILD_DIR)/vmlinux-initramfs.elf $(BIN_DIR)/$(IMG_PREFIX)-vmlinux-initramfs
endef

define Image/Build
	$(CP) $(KERNEL_BUILD_DIR)/vmlinux-initramfs.elf $(BIN_DIR)/$(IMG_PREFIX)-vmlinux-initramfs
#ifeq ($(CONFIG_TARGET_ROOTFS_INITRAMFS),y)
#	$(call Image/Build/Initramfs)
#endif
endef

$(eval $(call BuildImage))