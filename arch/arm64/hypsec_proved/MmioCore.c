#include "hypsec.h"
#include "MmioOps.h"

u32 __hyp_text check_smmu_pfn(u64 pfn, u32 vmid)
{
	u32 owner;
	owner = get_pfn_owner(pfn);
	if (owner != INVALID_MEM && owner && owner != vmid)
		return 0;

	return 1;
}

void __hyp_text handle_smmu_write(u32 hsr, u64 fault_ipa, u32 len, u32 index)
{
	u32 ret;
	//u64 offset = fault_ipa & ARM_SMMU_OFFSET_MASK;
	u64 offset = read_sysreg_el2(SYS_FAR) & ARM_SMMU_OFFSET_MASK;
	u32 write_val = 0;

	//if (offset < ARM_SMMU_GLOBAL_BASE) {
	if (offset < (get_smmu_size(index) >> 1)) {
		ret = handle_smmu_global_access(hsr, fault_ipa, 
						offset, index);
		if (ret == 0) {
			print_string("\rsmmu invalid write: global access\n");
			v_panic();
		} else {
			__handle_smmu_write(hsr, fault_ipa, len, 0UL, write_val);
		}
	} else {
		ret = handle_smmu_cb_access(hsr, fault_ipa,
					    offset, index);
		if (ret == 0) {
			print_string("\rsmmu invalid write: cb access\n");
			v_panic();	
		} else {
			if (ret == 2) {
				u64 cbndx = smmu_get_cbndx(offset);
				u64 val = get_smmu_cfg_hw_ttbr(cbndx, index);
				u64 data = host_get_mmio_data(hsr);
				write_val = 1;
				__handle_smmu_write(hsr, fault_ipa, len, val, write_val);
				print_string("\rwrite TTBR0\n");
				print_string("\roffset\n");
				printhex_ul(offset);
				print_string("\rcbndx\n");
				printhex_ul(cbndx);
				print_string("\rindex\n");
				printhex_ul(index);
				print_string("\rTTBR0\n");
				printhex_ul(val);
				print_string("\rHOST TTBR0\n");
				printhex_ul(data);
			} else if (ret == 3) {
				u64 data = host_get_mmio_data(hsr);
				print_string("\rHOST TTBCR\n");
				printhex_ul(data);
				__handle_smmu_write(hsr, fault_ipa, len, 0UL, write_val);
			} else {
				__handle_smmu_write(hsr, fault_ipa, len, 0UL, write_val);
			}
		}
	}
}

void __hyp_text handle_smmu_read(u32 hsr, u64 fault_ipa, u32 len, u32 index)
{
	u64 offset = fault_ipa & ARM_SMMU_OFFSET_MASK;

	if (offset < ARM_SMMU_GLOBAL_BASE) {
	    __handle_smmu_read(hsr, fault_ipa, len);
	} else {
	    __handle_smmu_read(hsr, fault_ipa, len);
	}	
}
