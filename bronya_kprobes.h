#ifndef __BRONYA_KPROBES_H__
#define __BRONYA_KPROBES_H__

#include "bronya.h"

#include <linux/kprobes.h>

int bronya_kprobes_init(void);
void bronya_kprobes_exit(void);

#endif
