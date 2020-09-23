#include <bfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <unistd.h>

#include "supported_ecus.h"

static char *get_data_desc_string(asymbol *sym);

void usage()
{
	printf("Usage: codeinjector ecu_name original_file injection_file [output_file]\n");
	printf("\tecu_name - one of supported ecu names: mmc-sh2, mmc-m32r\n");
	printf("\toriginal_file - binary file of stock ROM\n");
	printf("\tinjection_file - ELF container with override code\n");
	exit(1);
}

static int original_fd;
static int injection_fd;
static int output_fd;

static bfd *injection_bfd;

unsigned char *ori_buffer;
unsigned char *obuffer;
unsigned flash_size;

const struct ecu_description *current_ecu;

static void print_section(bfd *abfd, asection *sect, void *obj)
{
	if (!sect)
		printf("NULL Section\n");
	else
		printf("%d[%d] %s\n", sect->index, sect->id, sect->name);
}

void print_table()
{
	long storage_needed;
	asymbol **symbol_table;
	long number_of_symbols;
	long i;

	if (!(bfd_get_file_flags (injection_bfd) & HAS_SYMS))
	{
		printf("File has no syms\n");
		usage();
	}

	storage_needed = bfd_get_symtab_upper_bound (injection_bfd);

	if (storage_needed < 0) {
		printf("Negative storage wtf\n");
		usage();
	}

	if (storage_needed == 0) {
		printf("Zero storage wtf\n");
		return;
	}
	printf("Storage needed %ld\n", storage_needed);

	symbol_table = (asymbol **)malloc (storage_needed);
	printf("Storage table ptr %p\n", symbol_table);
	number_of_symbols =
	 bfd_canonicalize_symtab (injection_bfd, symbol_table);

	printf("Number of symbols: %ld\n", number_of_symbols);
}

static void hexprintf(unsigned char *data, unsigned size)
{
	unsigned i;
	for (i = 0; i < size; ++i) {
		printf("%02x", data[i]);
	}
}

static const uint8_t sh_nop_opcode[] = { 0x00, 0x09 };

enum patch_method {
	M32R_BL = 0,
	M32R_LD24_R0,
	M32R_LD24_R4,
	M32R_LDUH_R1,
	M32R_SPLICE_INTO_FUNCTION,
	M32R_RELOCATE_SECTION,
	SH_JUMP_TO_BODY,
	SH_SPLICE_INTO_FUNCTION,
	SH_RELOCATE_SECTION,
	PATCH_GENERIC,
};

static const char *const patch_markers[] = {
	"[m32r-bl]",
	"[m32r-ld24-r0]",
	"[m32r-ld24-r4]",
	"[m32r-lduh-r1]",
	"[m32r-splice-into-function]",
	"[m32r-relocate-section]",
	"[sh-jump-to-body]",
	"[sh-splice-into-function]",
	"[sh-relocate-section]",
};

static enum patch_method get_patch_method(const char *name)
{
	int i;
	for (i = 0; i < PATCH_GENERIC; ++i) {
		if (strstr(name, patch_markers[i]))
			return (enum patch_method)i;
	}
	return PATCH_GENERIC;
}

long storage_needed;
asymbol **symbol_table;
long number_of_symbols;

asymbol *get_symbol(const char *name)
{
	long i;

	for (i = 0; i < number_of_symbols; ++i) {
		if (!strcmp(bfd_asymbol_name(symbol_table[i]), name))
			return symbol_table[i];
	}
	return NULL;
}

asymbol *get_data_symbol(asymbol *desc_sym)
{
	long i;
	char buf[256];
	if (!desc_sym)
		return NULL;

	if (strlen(bfd_asymbol_name(desc_sym)) < 3)
		return NULL;

	return get_symbol(&bfd_asymbol_name(desc_sym)[2]);
}

#define AXIS_HEADER_SIZE	(2 * current_ecu->short_pointer_size + sizeof(uint16_t))
unsigned get_axis_size(unsigned _ptr)
{
	const uint16_t *ptr = (const uint16_t *)(ori_buffer + _ptr + 2 * current_ecu->short_pointer_size);
	return be16toh(*ptr);
}

static void emit_axis_ex_desc(const char *axis_sym_name, const char *axis_type)
{
	char *type, *username, *scaling, *size;
	asymbol *desc_sym = get_symbol(axis_sym_name);
	asymbol *data_sym = get_data_symbol(desc_sym);

	if (!desc_sym || !data_sym) {
		printf("\t<table name=\"%s\" type=\"%s Axis\"/>\n", axis_sym_name, axis_type);
		return;
	}

	char *str = get_data_desc_string(desc_sym);
	type = strtok(str, ";");
	username = strtok(NULL, ";");
	scaling = strtok(NULL, ";");
	


	printf("\t<table name=\"%s\" type=\"%s Axis\" address=\"%x\" elements=\"%u\" scaling=\"%s\"/>\n",
		username,
		axis_type,
		(unsigned)bfd_asymbol_value(data_sym) + AXIS_HEADER_SIZE,
		get_axis_size((unsigned)bfd_asymbol_value(data_sym)),
		scaling);

	free(str);
}


static void emit_axis_desc(const char *axis_sym_name, const char *axis_type)
{
	char *type, *username, *scaling, *size;
	asymbol *desc_sym = get_symbol(axis_sym_name);
	asymbol *data_sym = get_data_symbol(desc_sym);

	if (axis_sym_name[1] == 'X') {
		emit_axis_ex_desc(axis_sym_name, axis_type);
		return;
	}

	if (!desc_sym || !data_sym) {
		printf("\t<table name=\"%s\" type=\"%s Axis\"/>\n", axis_sym_name, axis_type);
		return;
	}

	char *str = get_data_desc_string(desc_sym);
	type = strtok(str, ";");
	username = strtok(NULL, ";");
	scaling = strtok(NULL, ";");
	size = strtok(NULL, ";");
	


	printf("\t<table name=\"%s\" type=\"%s Axis\" address=\"%x\" elements=\"%s\" scaling=\"%s\"/>\n",
		username,
		axis_type,
		(unsigned)bfd_asymbol_value(data_sym) + AXIS_HEADER_SIZE,
		size,
		scaling);

	free(str);
}

static void emit_3dmap_data_desc(const char *_str, symvalue data_symbol_value)
{
	char *str = strdup(_str);
	char *type, *category, *username, *scaling, *xaxisname, *yaxisname;

	type = strtok(str, ";");
	category = strtok(NULL, ";");
	username = strtok(NULL, ";");
	scaling = strtok(NULL, ";");
	xaxisname = strtok(NULL, ";");
	yaxisname = strtok(NULL, ";");

	printf("<table name=\"%s\" category=\"%s\" address=\"%x\" type=\"3D\" scaling=\"%s\" swapxy=\"true\">\n",
		username, category, (unsigned)data_symbol_value, scaling);

	emit_axis_desc(xaxisname, "X");
	emit_axis_desc(yaxisname, "Y");

	printf("</table>\n\n");
}

static void emit_2dmap_data_desc(const char *_str, symvalue data_symbol_value)
{
	char *str = strdup(_str);
	char *type, *category, *username, *scaling, *axisname;

	type = strtok(str, ";");
	category = strtok(NULL, ";");
	username = strtok(NULL, ";");
	scaling = strtok(NULL, ";");
	axisname = strtok(NULL, ";");

	printf("<table name=\"%s\" category=\"%s\" address=\"%x\" type=\"2D\" scaling=\"%s\">\n",
		username, category, (unsigned)data_symbol_value, scaling);

	emit_axis_desc(axisname, "Y");

	printf("</table>\n\n");
}


static void emit_array_data_desc(const char *_str, symvalue data_symbol_value)
{
	char *str = strdup(_str);
	char *type, *category, *username, *scaling, *axisdesc;

	type = strtok(str, ";");
	category = strtok(NULL, ";");
	username = strtok(NULL, ";");
	scaling = strtok(NULL, ";");
	axisdesc = strtok(NULL, ";");

	printf("<table name=\"%s\" category=\"%s\" address=\"%x\" type=\"2D\" scaling=\"%s\">\n\t%s\n</table>\n\n",
		username, category, (unsigned)data_symbol_value, scaling, axisdesc);

	free(str);
}

static void emit_3darray_data_desc(const char *_str, symvalue data_symbol_value)
{
	char *str = strdup(_str);
	char *type, *category, *username, *scaling, *xaxisdesc, *yaxisdesc;

	type = strtok(str, ";");
	category = strtok(NULL, ";");
	username = strtok(NULL, ";");
	scaling = strtok(NULL, ";");
	xaxisdesc = strtok(NULL, ";");
	yaxisdesc = strtok(NULL, ";");

	printf("<table name=\"%s\" category=\"%s\" address=\"%x\" type=\"3D\" scaling=\"%s\">\n\t%s\n\t%s\n</table>\n\n",
		username, category, (unsigned)data_symbol_value, scaling, xaxisdesc, yaxisdesc);

	free(str);
}

static void emit_value_data_desc(const char *_str, symvalue data_symbol_value)
{
	char *str = strdup(_str);
	char *type, *category, *username, *scaling;

	type = strtok(str, ";");
	category = strtok(NULL, ";");
	username = strtok(NULL, ";");
	scaling = strtok(NULL, ";");

	printf("<table name=\"%s\" category=\"%s\" address=\"%x\" type=\"1D\" scaling=\"%s\"/>\n",
		username, category, (unsigned)data_symbol_value, scaling);

	free(str);
}

enum data_desc_type
{
	DESC_UNKNOWN,
	DESC_VALUE,
	DESC_ARRAY,
	DESC_3DARRAY,
	DESC_2DMAP8,
	DESC_3DMAP8,
	DESC_2DMAP16,
	DESC_3DMAP16,
	DESC_AXIS,
	DESC_AXISEX,
};

enum data_desc_type get_data_desc_type(const char *_str)
{
	char *str = strdup(_str);
	char *type = strtok(str, ";");
	enum data_desc_type dt = DESC_UNKNOWN;

	if (!strcmp(type, "value")) {
		dt = DESC_VALUE;
	}
	else if (!strcmp(type, "array")) {
		dt = DESC_ARRAY;
	}
	else if (!strcmp(type, "3darray")) {
		dt = DESC_3DARRAY;
	}
	else if (!strcmp(type, "2dmap8")) {
		dt = DESC_2DMAP8;
	}
	else if (!strcmp(type, "3dmap8")) {
		dt = DESC_3DMAP8;
	}
	else if (!strcmp(type, "2dmap16")) {
		dt = DESC_2DMAP16;
	}
	else if (!strcmp(type, "3dmap16")) {
		dt = DESC_3DMAP16;
	}
	else if (!strcmp(type, "axis")) {
		dt = DESC_AXIS;
	}
	else if (!strcmp(type, "axisex")) {
		dt = DESC_AXISEX;
	}

	free(str);

	return dt;
}

static char *get_data_desc_string(asymbol *sym)
{
	long sectsize = bfd_get_section_size(sym->section);
	char *ret = malloc(sectsize);
	bfd_get_section_contents(sym->section->owner, sym->section, ret, sym->value, sectsize - sym->value);
	return ret;
}

static int compare_symbols_by_name(const void *_l, const void *_r)
{
	asymbol *l = *((asymbol **)_l);
	asymbol *r = *((asymbol **)_r);
	return strcmp(l->name, r->name);
}

static void data_desc_generator(bfd *abfd, asection *sect, void *obj)
{
	long i;
	storage_needed = bfd_get_symtab_upper_bound (abfd);

	if (storage_needed < 0)
		return;
	if (storage_needed == 0) {
		return;
	}
	symbol_table = (asymbol **) malloc (storage_needed);

	number_of_symbols =
	bfd_canonicalize_symtab (abfd, symbol_table);
	if (number_of_symbols < 0)
		return;

	qsort(symbol_table, number_of_symbols, sizeof(asymbol *), compare_symbols_by_name);

	for (i = 0; i < number_of_symbols; i++) {
		asymbol *sym = symbol_table[i];
		if (bfd_get_section(sym) != sect)
			continue;

		if (sym->flags & BSF_SECTION_SYM)
			continue;
		
		char *str = get_data_desc_string(sym);
		asymbol *data_symbol = get_data_symbol(sym);
		if (!str) {
			printf("<comment>That's strange: unable to find desc string for %s</comment>\n", sym->name);
			continue;
		}
		if (!data_symbol) {
			printf("<comment>That's strange: unable to find data symbol for %s</comment>\n", sym->name);
			continue;
		}
		switch (get_data_desc_type(str)) {
		case DESC_VALUE:
			emit_value_data_desc(str, bfd_asymbol_value(data_symbol));
			break;
		case DESC_ARRAY:
			emit_array_data_desc(str, bfd_asymbol_value(data_symbol));
			break;
		case DESC_3DARRAY:
			emit_3darray_data_desc(str, bfd_asymbol_value(data_symbol));
			break;
		case DESC_3DMAP8:
			emit_3dmap_data_desc(str, bfd_asymbol_value(data_symbol) +
				(sizeof(uint8_t)*3 + 2 * current_ecu->short_pointer_size));
			break;
		case DESC_3DMAP16:
			emit_3dmap_data_desc(str, bfd_asymbol_value(data_symbol) +
				(sizeof(uint16_t)*3 + 2 * current_ecu->short_pointer_size));
			break;
		case DESC_AXIS:
		case DESC_AXISEX:
			//axes are skipped explicitly
			break;
		case DESC_2DMAP8:
			emit_2dmap_data_desc(str, bfd_asymbol_value(data_symbol) +
				(2 * sizeof(uint8_t) + current_ecu->short_pointer_size));
			break;
		case DESC_2DMAP16:
			emit_2dmap_data_desc(str, bfd_asymbol_value(data_symbol) +
				(2 * sizeof(uint16_t) + current_ecu->short_pointer_size));
			break;
		default:
			printf("<comment name=\"%s\">%s</comment>\n", sym->name, str);
			break;
		}
		free(str);
	}

}

static void inject_section(bfd *abfd, asection *sect, void *obj)
{
	if (!strcmp(sect->name, "data_desc")) {
		data_desc_generator(abfd, sect, obj);
		return;
	}
	if (!(sect->flags & SEC_LOAD))
		return;

	char scaling_name[128];
	char *c;
	snprintf(scaling_name, sizeof(scaling_name), "%s _scaling", sect->name);
	for (c = scaling_name; *c; ++c)
		if (*c == '.')  *c = '_';

	unsigned patch_size = sect->size;
	unsigned patch_method = get_patch_method(sect->name);
	unsigned patch_address = sect->vma;

	if (patch_method != PATCH_GENERIC) {
		if (!strstr(sect->name, current_ecu->patch_method_prefix)) {
			printf("patch_method incompatible with arch at %s\n", sect->name);
			usage();
		}
	}

	switch (patch_method) {
	case M32R_BL: {
		if (sect->size != 4) {
			printf("Invalid bl injection instruction section size\n");
			usage();
		}
		unsigned target;
		bfd_get_section_contents(abfd, sect, &target, 0, 4);
		target = be32toh(target);
		unsigned pc = sect->vma;
		unsigned patch = 0xfe000000 + (((target - pc) / 4) & 0x00ffffff);
		patch = htobe32(patch);
		memcpy(&obuffer[sect->vma], &patch, 4);
	} break;
	case M32R_LD24_R0:
	case M32R_LD24_R4: {
		if (sect->size != 4) {
			printf("Invalid ld24 injection instruction section size\n");
			usage();
		}
		unsigned target;
		bfd_get_section_contents(abfd, sect, &target, 0, 4);
		target = be32toh(target);
		unsigned patch = 0xe0000000 + target;
		if (patch_method == M32R_LD24_R4) {
			patch += 4 << 24;
		}
		patch = htobe32(patch);
		memcpy(&obuffer[sect->vma], &patch, 4);
	} break;
	case M32R_LDUH_R1: {
		if (sect->size != 4) {
			printf("Invalid lduh injection instruction section size\n");
			usage();
		}
		unsigned target;
		unsigned dst_register = 1;
		bfd_get_section_contents(abfd, sect, &target, 0, 4);
		target = be32toh(target);
		uint16_t disp16 = target - 0x80008000;
		unsigned patch = 0xa0bd0000 + (dst_register << 24) + disp16;
		patch = htobe32(patch);
		memcpy(&obuffer[sect->vma], &patch, 4);
	} break;
	case SH_JUMP_TO_BODY: {
		int nop_in_beginning = 0;
		if ((sect->vma % 4) == 2) {
			nop_in_beginning = 1;
		} else if ((sect->vma % 4)) {
			printf("Invalid vma in [sh-jump-to-body]\n");
			usage();
			/*wtf?*/
		}
/*we need space for 4 instructions, 1 address and optional padding*/
		uint8_t patch_body[] = { 0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09, 0, 0, 0, 0 };
		bfd_get_section_contents(abfd, sect, &patch_body[8], 0, 4);
		if (nop_in_beginning) {
			memcpy(&obuffer[sect->vma], sh_nop_opcode, sizeof(sh_nop_opcode));
		}
		memcpy(&obuffer[sect->vma + (nop_in_beginning ? 2 : 0)], patch_body, sizeof(patch_body));
		patch_size = (nop_in_beginning ? 2 : 0) + sizeof(patch_body);
	} break;
	case M32R_SPLICE_INTO_FUNCTION: {
/*wee need space for 8 instructions, 2 addresses and optional nop*/
		uint8_t patch_body[8] = { };
		{
			unsigned target;
			bfd_get_section_contents(abfd, sect, &target, 0, 4);
			target = be32toh(target);
			unsigned pc = sect->vma;
			unsigned patch = 0xfe000000 + (((target - pc) / 4) & 0x00ffffff);
			patch = htobe32(patch);
			memcpy(patch_body, &patch, 4);
		}
		{
			unsigned target;
			bfd_get_section_contents(abfd, sect, &target, 4, 4);
			target = be32toh(target);
			unsigned pc = sect->vma + 4;
			unsigned patch = 0xff000000 + (((target - pc) / 4) & 0x00ffffff);
			patch = htobe32(patch);
			memcpy(patch_body + 4, &patch, 4);
		}
		memcpy(&obuffer[sect->vma], patch_body, sizeof(patch_body));
		patch_size = sizeof(patch_body);
	} break;
	case SH_SPLICE_INTO_FUNCTION: {
		int nop_in_beginning = 0;
		if ((sect->vma % 4) == 2) {
			nop_in_beginning = 1;
		} else if ((sect->vma % 4)) {
			printf("Invalid vma in [sh-jump-to-body]\n");
			usage();
			/*wtf?*/
		}
/*wee need space for 8 instructions, 2 addresses and optional nop*/
		uint8_t patch_body[] = { 0xda, 0x03,
			0x4a, 0x0b,
			0x00, 0x09,
			0x00, 0x09,
			0xd0, 0x02,
			0x40, 0x2b,
			0x00, 0x09,
			0x00, 0x09,
			0, 0, 0, 0,
			0, 0, 0, 0 };
		bfd_get_section_contents(abfd, sect, &patch_body[16], 0, 8);
		if (nop_in_beginning) {
			memcpy(&obuffer[sect->vma], sh_nop_opcode, sizeof(sh_nop_opcode));
		}
		memcpy(&obuffer[sect->vma + (nop_in_beginning ? 2 : 0)], patch_body, sizeof(patch_body));
		patch_size = (nop_in_beginning ? 2 : 0) + sizeof(patch_body);
	} break;
	case M32R_RELOCATE_SECTION:
	case SH_RELOCATE_SECTION: {
		unsigned target;
		bfd_get_section_contents(abfd, sect, &target, 0, 4);
		target = be32toh(target);
		bfd_get_section_contents(abfd, sect, &obuffer[target], 0, sect->size);
		patch_address = target;
	} break;
	case PATCH_GENERIC:
	default:
		bfd_get_section_contents(abfd, sect, &obuffer[sect->vma], 0, sect->size);
	}

	printf("<scaling name=\"%s\" storagetype=\"bloblist\">\n", scaling_name);
	printf("\t<data name=\"Original\" value=\"");
	hexprintf(&ori_buffer[patch_address], patch_size);
	printf("\" />\n");
	printf("\t<data name=\"Patched\" value=\"");
	hexprintf(&obuffer[patch_address], patch_size);
	printf("\" />\n</scaling>\n\n");
	printf("<table name=\"%s\" address=\"%x\" category=\"Patches\" type=\"1D\" scaling=\"%s\" />\n\n", sect->name, patch_address, scaling_name);
	//printf("<comment>%s</comment>\n", patch_method == PATCH_GENERIC ? "generic" : patch_markers[patch_method]);
}


int main(int argc, char **argv)
{
	int ret;

	if (argc < 4)
		usage();
	current_ecu = supported_ecus;
	while (strcmp(current_ecu->name, argv[1])) {
		++current_ecu;
		if (!current_ecu->name) {
			printf("%s ecu not supported\n", argv[1]);
			usage();
		}
	}
	original_fd = open(argv[2], O_RDONLY);
	if (original_fd == -1) {
		printf("No original_file\n");
		usage();
	}
	struct stat stat;
	ret = fstat(original_fd, &stat);
	if (ret == -1) {
		printf("Can't get original_file size\n");
		usage();
	}
	obuffer = malloc(stat.st_size);
	ori_buffer = malloc(stat.st_size);
	if (!obuffer || !ori_buffer) {
		printf("Not enough memory for original_file\n");
		usage();
	}
	flash_size = stat.st_size;
	ret = read(original_fd, obuffer, flash_size);
	if (ret != flash_size) {
		printf("Can't read contents of original_file\n");
		usage();
	}
	memcpy(ori_buffer, obuffer, flash_size);

	injection_fd = open(argv[3], O_RDONLY);
	if (injection_fd == -1) {
		printf("No injection_file\n");
		usage();
	}

	if (argc > 3) {
		mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		output_fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC, mode);
		if (output_fd == -1) {
			printf("Can't create output_file\n");
			usage();
		}
	} else {
		output_fd = 0;
	}

	bfd_init();

	injection_bfd = bfd_fdopenr(argv[2], "elf32-big", injection_fd);
	if (!injection_bfd) {
		printf("Can't BFD open injection_file\n");
		const char **bfd_targets = bfd_target_list();
		while (*bfd_targets) {
			printf("%s\n", bfd_targets[0]);
			++bfd_targets;
		}
		usage();
	}

	if (!bfd_check_format(injection_bfd, bfd_object)) {
		printf("injection_file isn't BFD object\n");
		usage();
	}

	bfd_map_over_sections(injection_bfd, inject_section, NULL);
	/*rebuild crc*/

	ret = write(output_fd, obuffer, flash_size);
	if (ret != flash_size) {
		perror("Unable to write contents to output\n");
	}
}
