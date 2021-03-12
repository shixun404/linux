#include "hypsec.h"

/*
 * PageIndex
 */

u64 __hyp_text get_s2_page_index(u64 addr)
{
	u32 region_index = mem_region_search(addr);
	u64 ret = INVALID64;
	if (region_index != INVALID_MEM) {
		u64 page_index = get_mem_region_index(region_index);
		if (page_index != INVALID64) {
			u64 base = get_mem_region_base(region_index);
			ret = page_index + (addr - base) / PAGE_SIZE;
		}
	}
	return ret;
}
