#include "bronya.h"
#include "bronya_kprobes.h"

MODULE_AUTHOR("xiaoguai0992");
MODULE_LICENSE("GPL");

int bronya_init(void)
{
	int ret = 0;

	/* init kprobes */
	ret = bronya_kprobes_init();
	if (ret < 0) {
		BRONYA_ERR("Bronya kprobes init failed!\n");
		return -EINVAL;
	}

	BRONYA_INFO("----------------\n");
	BRONYA_INFO("Bronya online!\n");
	BRONYA_INFO("----------------\n");
	return 0;
}

void bronya_exit(void)
{
	/* exit kprobes */
	bronya_kprobes_exit();

	BRONYA_INFO("----------------\n");
	BRONYA_INFO("Bronya offline.\n");
	BRONYA_INFO("----------------\n");
}

module_init(bronya_init);
module_exit(bronya_exit);

