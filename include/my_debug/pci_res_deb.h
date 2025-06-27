#ifndef __PCI_RES_DEB__
#define __PCI_RES_DEB__
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/printk.h>
static void __attribute__((unused))
print_one_resource_prefix(struct resource *res, char *prefix)
{
	pr_info("%s name(%s) start(%llx) end(%llx) parent(%lx)\n",
			prefix ? prefix : "",
			res->name,
			res->start,
			res->end,
			(unsigned long)res->parent);
}

#define print_one_resource(_res)  print_one_resource_prefix(_res, NULL)

static void  __attribute__((unused))
print_resource_sibling(struct pci_dev *dev, int resno)
{
	struct resource *child_res = dev->bus->resource[resno]->child;

	while (child_res) {
		print_one_resource(child_res);
		child_res = child_res->sibling;
	}
}


#endif
