// SPDX-License-Identifier: GPL-2.0
/*
 * Serial Port driver for ACPI platform devices
 *
 * This driver is for generic 16550 compatible UART enumerated via ACPI
 * platform bus instead of PNP bus like PNP0501. This is not a full
 * driver but mostly provides the ACPI wrapper and uses generic
 * 8250 framework for rest of the functionality.
 */

#include <linux/acpi.h>
#include <linux/serial_reg.h>
#include <linux/serial_8250.h>

#include "8250.h"

struct acpi_serial_info {
	int	line;
};

static int acpi_platform_serial_probe(struct platform_device *pdev)
{
	struct acpi_serial_info *data;
	struct uart_8250_port port8250;
	struct device *dev = &pdev->dev;
	struct resource *regs;

	int ret, irq;

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!regs) {
		dev_err(dev, "no registers defined\n");
		return -EINVAL;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	memset(&port8250, 0, sizeof(port8250));

	spin_lock_init(&port8250.port.lock);

	port8250.port.mapbase           = regs->start;
	port8250.port.irq               = irq;
	port8250.port.type              = PORT_16550A;
	port8250.port.flags             = UPF_SHARE_IRQ | UPF_BOOT_AUTOCONF | UPF_FIXED_PORT |
					  UPF_IOREMAP | UPF_FIXED_TYPE;
	port8250.port.dev               = dev;
	port8250.port.mapsize           = resource_size(regs);
	port8250.port.iotype            = UPIO_MEM;
	port8250.port.irqflags          = IRQF_SHARED;

	port8250.port.membase = devm_ioremap(dev, port8250.port.mapbase, port8250.port.mapsize);
	if (!port8250.port.membase)
		return -ENOMEM;

	ret = uart_read_and_validate_port_properties(&port8250.port);
	if (ret)
		return -EINVAL;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->line = serial8250_register_8250_port(&port8250);
	if (data->line < 0)
		return data->line;

	platform_set_drvdata(pdev, data);
	return 0;
}

static void acpi_platform_serial_remove(struct platform_device *pdev)
{
	struct acpi_serial_info *data = platform_get_drvdata(pdev);

	serial8250_unregister_port(data->line);
}

static const struct acpi_device_id acpi_platform_serial_table[] = {
	{ "RSCV0003", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, acpi_platform_serial_table);

static struct platform_driver acpi_platform_serial_driver = {
	.driver = {
		.name			= "acpi_serial",
		.acpi_match_table	= ACPI_PTR(acpi_platform_serial_table),
	},
	.probe			= acpi_platform_serial_probe,
	.remove_new		= acpi_platform_serial_remove,
};

builtin_platform_driver(acpi_platform_serial_driver);
