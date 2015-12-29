#include "kvm/irq.h"
#include "kvm/kvm.h"

#include <stdlib.h>

int irq__add_msix_route(struct kvm *kvm, struct msi_msg *msg)
{
	pr_warning("irq__add_msix_route");
	return 1;
}

static int allocated_irqnum = 1;

int irq__register_device(u32 dev, u8 *pin, u8 *line)
{
	*pin = 1;
	*line = allocated_irqnum;
	allocated_irqnum++;

	return 0;
}
