#ifndef __BRONYA_H__
#define __BRONYA_H__

#include <linux/module.h>
#include <linux/kernel.h>

#define BRONYA_INFO(fmt, arg...) \
	printk("bronya_info: " fmt, ##arg)
#define BRONYA_WARN(fmt, arg...) \
	printk("bronya_warn: " fmt, ##arg)
#define BRONYA_ERR(fmt, arg...) \
	printk("bronya_err: " fmt, ##arg)

#endif

