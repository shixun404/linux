#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_mmio.h>
#include <asm/kvm_emulate.h>
#include <asm/virt.h>
#include <asm/kernel-pgtable.h>
#include <asm/hypsec_host.h>
#include <asm/spinlock_types.h>
#include <linux/serial_reg.h>

void init_el2_data_page(void)
{
	int i = 0, index = 0;
	struct el2_data *el2_data;
	struct memblock_region *r;
	u64 pool_start;

	el2_data = (void *)kvm_ksym_ref(el2_data_start);
	el2_data->installed = false;

	/* We copied memblock_regions to the EL2 data structure*/
	for_each_memblock(memory, r) {
		el2_data->regions[i] = *r;
		if (!(r->flags & MEMBLOCK_NOMAP)) {
			el2_data->s2_memblock_info[i].index = index;
			index += (r->size >> PAGE_SHIFT);
		} else
			el2_data->s2_memblock_info[i].index = S2_PFN_SIZE;
		i++;
	}
	el2_data->regions_cnt = i;

	el2_data->used_pages = 0;
	el2_data->page_pool_start = (u64)__pa(stage2_pgs_start);

	el2_data->s2pages_lock.lock = 0;
	el2_data->abs_lock.lock = 0;
	el2_data->el2_pt_lock.lock = 0;
	el2_data->console_lock.lock = 0;

	el2_data->ram_start_pfn = el2_data->regions[0].base >> PAGE_SHIFT;

	pool_start = el2_data->page_pool_start;

	/* We init intermediate data structure here. */
	//el2_shared_data_init();

	BUG_ON(num_online_cpus() > HYPSEC_MAX_CPUS);
	for (i = 0; i < num_online_cpus(); i++) {
		;
	}

	return;
}

phys_addr_t host_alloc_stage2_page(unsigned int num)
{
	u64 p_addr, start, unaligned, append, used_pages;
	struct el2_data *el2_data;

	if (!num)
		return 0;

	el2_data = kvm_ksym_ref(el2_data_start);
	stage2_spin_lock(&el2_data->abs_lock);

	/* Check if we're out of memory in the reserved area */
	BUG_ON(el2_data->used_pages >= STAGE2_NUM_CORE_PAGES);

	/* Start allocating memory from the normal page pool */
	start = el2_data->vm_info[COREVISOR].page_pool_start;
	used_pages = el2_data->vm_info[COREVISOR].used_pages;
	p_addr = (u64)start + (PAGE_SIZE * used_pages);

	unaligned = p_addr % (PAGE_SIZE * num);
	/* Append to make p_addr aligned with (PAGE_SIZE num) */
	if (unaligned) {
		append = num - (unaligned >> PAGE_SHIFT);
		p_addr += append * PAGE_SIZE;
		num += append;
	}

	el2_data->vm_info[COREVISOR].used_pages += num;

	stage2_spin_unlock(&el2_data->abs_lock);
	return (phys_addr_t)p_addr;
}
