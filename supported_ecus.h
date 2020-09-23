#ifndef SUPPORTED_ECUS_H
#define SUPPORTED_ECUS_H

enum ecu_type
{
	ECU_INVALID = 0,
	ECU_MMC_SH2,
	ECU_MMC_M32R
};

struct ecu_description
{
	enum ecu_type ecu_type;
	const char *name;
	const char *patch_method_prefix;
	unsigned short_pointer_size;
};

struct ecu_description supported_ecus[3];

#endif /*SUPPORTED_ECUS_H*/
