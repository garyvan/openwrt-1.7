#ifndef KVM__KVM_ARCH_H
#define KVM__KVM_ARCH_H

#define KVM_PCI_MMIO_AREA	0x10000000
#define KVM_VIRTIO_MMIO_AREA	0x18000000

#define VIRTIO_DEFAULT_TRANS	VIRTIO_PCI

#include <stdbool.h>

#include "linux/types.h"

struct kvm_arch {
	u64 entry_point;
	u64 argc;
	u64 argv;
	bool is64bit;
};

#endif /* KVM__KVM_ARCH_H */
