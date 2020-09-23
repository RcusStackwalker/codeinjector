#include "supported_ecus.h"

struct ecu_description supported_ecus[3] = {
	{
		ECU_MMC_SH2,
		"mmc-sh2",
		"[sh-",
		4,
	}, {
		ECU_MMC_M32R,
		"mmc-m32r",
		"[m32r-",
		2,
	},
	{}
};
