/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * MMU support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

/*
 * We need the mmu code to access both 32-bit and 64-bit guest ptes,
 * so the code in this file is compiled twice, once per pte size.
 */

#if PTTYPE == 64
	#define pt_element_t u64
	#define guest_walker guest_walker64
	#define FNAME(name) paging##64_##name
	#define PT_BASE_ADDR_MASK PT64_BASE_ADDR_MASK
	#define PT_DIR_BASE_ADDR_MASK PT64_DIR_BASE_ADDR_MASK
	#define PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define PT_LEVEL_MASK(level) PT64_LEVEL_MASK(level)
	#define PT_PTE_COPY_MASK PT64_PTE_COPY_MASK
	#define PT_NON_PTE_COPY_MASK PT64_NON_PTE_COPY_MASK
#elif PTTYPE == 32
	#define pt_element_t u32
	#define guest_walker guest_walker32
	#define FNAME(name) paging##32_##name
	#define PT_BASE_ADDR_MASK PT32_BASE_ADDR_MASK
	#define PT_DIR_BASE_ADDR_MASK PT32_DIR_BASE_ADDR_MASK
	#define PT_INDEX(addr, level) PT32_INDEX(addr, level)
	#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)
	#define PT_LEVEL_MASK(level) PT32_LEVEL_MASK(level)
	#define PT_PTE_COPY_MASK PT32_PTE_COPY_MASK
	#define PT_NON_PTE_COPY_MASK PT32_NON_PTE_COPY_MASK
#else
	#error Invalid PTTYPE value
#endif

/*
 * The guest_walker structure emulates the behavior of the hardware page
 * table walker.
 */
struct guest_walker {
	int level;			//the CURRENT level of guest walker
	pt_element_t *table;		//the pgtable of the level, and mask some 
					//guest bit of CR3_FLAGS_MASK 

	pt_element_t inherited_ar;	/* see intel sdm 4.10.2.2 "Caching Translations 
					 * in TLBs", inherited_ar like certain permission 
					 * attributes in TLBs entries, calculated by all 
					 * level pgtable entries to execute logical-AND/OR.
					 * 
					 * why we only need to  pay attention to R/W && U/S
					 * flags(see FNAME(init_walker) for more information)
					 * because we need to use these bits during the page 
					 * fault to handle page faults reasonably.(see 
					 * FNAME(page_fault) for more information. Saving this 
					 * information will prevent us from walking the guest
					 * page table again.
					 */
};

static void FNAME(init_walker)(struct guest_walker *walker,
			       struct kvm_vcpu *vcpu)
{
	hpa_t hpa;
	struct kvm_memory_slot *slot;
	/*
	 * set walker->level to vcpu->mmu.root_level initialized in 
	 * FNAME(init_context)
	 */
	walker->level = vcpu->mmu.root_level;
	slot = gfn_to_memslot(vcpu->kvm,
			      (vcpu->cr3 & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT);
	hpa = safe_gpa_to_hpa(vcpu, vcpu->cr3 & PT64_BASE_ADDR_MASK);
	walker->table = kmap_atomic(pfn_to_page(hpa >> PAGE_SHIFT), KM_USER0);

	/*
	 * pae mode cr3 format has checked the reserved bit in function
	 * `pdptrs_have_reserved_bits_set()`
	 */
	ASSERT((!kvm_arch_ops->is_long_mode(vcpu) && is_pae(vcpu)) ||
	       (vcpu->cr3 & ~(PAGE_MASK | CR3_FLAGS_MASK)) == 0);

	/*
	 * NOTE
	 *
	 * Pae pdpte page is a partial page because the base of pdpte requires
	 * 32-byte align not 4K-byte, The walker->table here just points to base
	 * address of the page.
	 */
	walker->table = (pt_element_t *)( (unsigned long)walker->table |
		(unsigned long)(vcpu->cr3 & ~(PAGE_MASK | CR3_FLAGS_MASK)) );
	/* only need pay attention to U/S and R/W flag*/
	walker->inherited_ar = PT_USER_MASK | PT_WRITABLE_MASK;
}

static void FNAME(release_walker)(struct guest_walker *walker)
{
	kunmap_atomic(walker->table, KM_USER0);
}

static void FNAME(set_pte)(struct kvm_vcpu *vcpu, u64 guest_pte,
			   u64 *shadow_pte, u64 access_bits)
{
	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pte;
	*shadow_pte = (guest_pte & PT_PTE_COPY_MASK);
	set_pte_common(vcpu, shadow_pte, guest_pte & PT_BASE_ADDR_MASK,
		       guest_pte & PT_DIRTY_MASK, access_bits);
}
/*
 * copy guest pde attr to shadow pte
 */
static void FNAME(set_pde)(struct kvm_vcpu *vcpu, u64 guest_pde,
			   u64 *shadow_pte, u64 access_bits,
			   int index)
{
	gpa_t gaddr;

	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pde;
	gaddr = (guest_pde & PT_DIR_BASE_ADDR_MASK) + PAGE_SIZE * index;
	if (PTTYPE == 32 && is_cpuid_PSE36())
		gaddr |= (guest_pde & PT32_DIR_PSE36_MASK) <<
			(32 - PT32_DIR_PSE36_SHIFT);
	*shadow_pte = (guest_pde & (PT_NON_PTE_COPY_MASK | PT_GLOBAL_MASK)) |
		          ((guest_pde & PT_DIR_PAT_MASK) >>
			            (PT_DIR_PAT_SHIFT - PT_PAT_SHIFT));
	set_pte_common(vcpu, shadow_pte, gaddr,
		       guest_pde & PT_DIRTY_MASK, access_bits);
}

/*
 * Fetch a guest pte from a specific level in the paging hierarchy.
 */
static pt_element_t *FNAME(fetch_guest)(struct kvm_vcpu *vcpu,
					struct guest_walker *walker,
					int level,
					gva_t addr)
{

	ASSERT(level > 0  && level <= walker->level);

	for (;;) {
		int index = PT_INDEX(addr, walker->level);
		hpa_t paddr;

		ASSERT(((unsigned long)walker->table & PAGE_MASK) ==
		       ((unsigned long)&walker->table[index] & PAGE_MASK));
		/*
		 * If one of the following conditions is met, can return:
		 *   + reach the specified level
		 *   + higher level to specified level is NOT present, break walk
		 *   + (level is PT_DIRECTORY_LEVEL && pgtable entry has PS bit)
		 *     && (in 64 bit mode || 
		 *     (
		 *       in 32 bit mode && open PSE feature -- (CR4.PSE = 1) 
		 *     )
		 *
		 *     In 32-bit paging mode, only C4.PSE=1 AND PDE's PS flag =1,
		 *     the PDE can map a 4-MByte page, otherwise mapping a 4-Byte 
		 *     Page.
		 *
		 *     see intel sdm "4.3 32-BIT PAGING" for more information about
		 *     how the page size is determined.
		 */
		if (level == walker->level ||
		    !is_present_pte(walker->table[index]) ||
		    (walker->level == PT_DIRECTORY_LEVEL &&
		     (walker->table[index] & PT_PAGE_SIZE_MASK) &&
		     (PTTYPE == 64 || is_pse(vcpu))))
			return &walker->table[index];
		/*
		 * PDPTEs in PAE mode has not U/S && R/W flag, so skip it.
		 */
		if (walker->level != 3 || kvm_arch_ops->is_long_mode(vcpu))
			walker->inherited_ar &= walker->table[index];
		/*
		 * It is not considered here that the pae page is a partial page.
		 * Instead, it is assumed that pdpte must be at the base address
		 * of the page. I think it is a mistake. But Avi has fix it on patch
		 *    1342d3536d6a12541ceb276da15f043db90716eb
		 *    KVM: MMU: Load the pae pdptrs on cr3 change like the processor does
		 *
		 *    1b0973bd8f788178f21d9eebdd879203464f8528
		 *    KVM: MMU: Use the guest pdptrs instead of mapping cr3 in pae mode
		 *
		 * This patch works like a CPU, loading pdpte from memory to "register"
		 * (vcpu->pdptrs[]) at certain times. When loading each entry from the page
		 * where pdpte is located, offset will be calculated correctly.
		 *
		 * And in walk_addr()(I.E., fetch_guest) function, this will use vcpu->pdptrs[]
		 * directly instead mapping cr3.
		 */
		paddr = safe_gpa_to_hpa(vcpu, walker->table[index] & PT_BASE_ADDR_MASK);
		/*
		 * no longer requires to access this level pgtable, so unmap it.
		 */
		kunmap_atomic(walker->table, KM_USER0);
		walker->table = kmap_atomic(pfn_to_page(paddr >> PAGE_SHIFT),
					    KM_USER0);
		--walker->level;
	}
}

/*
 * Fetch a shadow pte for a specific level in the paging hierarchy.
 */
/*
 * We need to know, what information to abtain for walking guest 
 * pgtable ?
 *
 * The pgtable attr! The next level pt or page phyiscal address is not 
 * key information. So we can found that in paging32_fetch, the
 * shadow_root_level is PT32E_ROOT_LEVEL, root_level is PT32_ROOT_LEVEL.
 * shadow_root_level is ONE greater that root_level.
 *
 * We just need to make the attr of level 2 && 3  shadow pgtable consistent 
 * with the level2 of the guest pgtable.
 *
 * > NOTE
 * > 
 * > No matter what mode the guest is in except 64-bit mode, guest cr4 will 
 * > set PAE. So the shadow_root_level is always PT32E_ROOT_LEVEL except 
 * > 64-bit mode.
 */
static u64 *FNAME(fetch)(struct kvm_vcpu *vcpu, gva_t addr,
			      struct guest_walker *walker)
{
	hpa_t shadow_addr;
	int level;
	u64 *prev_shadow_ent = NULL;

	shadow_addr = vcpu->mmu.root_hpa;
	level = vcpu->mmu.shadow_root_level;

	for (; ; level--) {
		/*
		 * Whether it is paging32_fetch or paging64_fetch, SHADOW_PT_INDEX
		 * is all PT64_INDEX.
		 */
		u32 index = SHADOW_PT_INDEX(addr, level);
		u64 *shadow_ent = ((u64 *)__va(shadow_addr)) + index;
		pt_element_t *guest_ent;

		if (is_present_pte(*shadow_ent) || is_io_pte(*shadow_ent)) {
			if (level == PT_PAGE_TABLE_LEVEL)
				return shadow_ent;
			shadow_addr = *shadow_ent & PT64_BASE_ADDR_MASK;
			prev_shadow_ent = shadow_ent;
			continue;
		}
		/*
		 * see paging32_init_context()
		 * it will set 
		 *
		 *   context::shadow_root_level --> PT32E_ROOT_LEVEL
		 *   context->root_level        --> PT32_ROOT_LEVEL
		 *
		 * So when we set level 3 && 2 shadow pgtable, we all
		 * fetch guest level 2 pgtable.
		 */
		if (PTTYPE == 32 && level > PT32_ROOT_LEVEL) {
			ASSERT(level == PT32E_ROOT_LEVEL);
			guest_ent = FNAME(fetch_guest)(vcpu, walker,
						       PT32_ROOT_LEVEL, addr);
		} else
			guest_ent = FNAME(fetch_guest)(vcpu, walker,
						       level, addr);

		/*
		 * guest pgtable entry is not present, need inject PF except to 
		 * notify guest.
		 */
		if (!is_present_pte(*guest_ent))
			return NULL;

		/* Don't set accessed bit on PAE PDPTRs */
		/*
		 * PAE PDPTE have not ACCESSED bit.
		 *
		 * "root_level" not equal to 3 means guest does not enable PAE.
		 *
		 * "root_level == 3 && walker->level !=3" means guest enable PAE,
		 * but the level is not PDPTE.
		 */
		if (vcpu->mmu.root_level != 3 || walker->level != 3)
			*guest_ent |= PT_ACCESSED_MASK;

		/*
		 * Already walked to the last level shadow pgtable -- 
		 *   PT_PAGE_TABLE_LEVEL
		 */
		if (level == PT_PAGE_TABLE_LEVEL) {
			/* 
			 * Although when we called fetch_guest() earlier, the level passed 
			 * in was PT_PAGE_TABLE_LEVEL, it may be cause early return due to
			 * PT_DIRECTORY_LEVEL pgtable entry having PT_PAGE_SIZE_MASK. 
			 *
			 * In this case, walker->level is 2.
			 *
			 * But the kvm don't set PS flag in shadow pgtable entry anytime.
			 * I guest it cannot to be guaranteed that the memslot must be aligned
			 * to the size of hugepage. See kvm_dev_ioctl_set_memory_region for more
			 * information about the kvm_memory_region->memory_size checking.
			 */
			if (walker->level == PT_DIRECTORY_LEVEL) {
				if (prev_shadow_ent)
					*prev_shadow_ent |= PT_SHADOW_PS_MARK;
				FNAME(set_pde)(vcpu, *guest_ent, shadow_ent,
					       walker->inherited_ar,
				          PT_INDEX(addr, PT_PAGE_TABLE_LEVEL));
			} else {
				ASSERT(walker->level == PT_PAGE_TABLE_LEVEL);
				FNAME(set_pte)(vcpu, *guest_ent, shadow_ent, walker->inherited_ar);
			}
			return shadow_ent;
		}
		/*
		 * 
		 */
		shadow_addr = kvm_mmu_alloc_page(vcpu, shadow_ent);
		if (!VALID_PAGE(shadow_addr))
			return ERR_PTR(-ENOMEM);
		// 32 bit mode && PDPTE
		if (!kvm_arch_ops->is_long_mode(vcpu) && level == 3)
			*shadow_ent = shadow_addr |
				(*guest_ent & (PT_PRESENT_MASK | PT_PWT_MASK | PT_PCD_MASK));
		else {
			*shadow_ent = shadow_addr |
				(*guest_ent & PT_NON_PTE_COPY_MASK);
			*shadow_ent |= (PT_WRITABLE_MASK | PT_USER_MASK);
		}
		prev_shadow_ent = shadow_ent;
	}
}

/*
 * The guest faulted for write.  We need to
 *
 * - check write permissions
 * - update the guest pte dirty bit
 * - update our own dirty page tracking structures
 */
/*
 * return 0, means we cannot fix this write pf, we need to further process 
 * in `FNAME(page_fault)`
 */
static int FNAME(fix_write_pf)(struct kvm_vcpu *vcpu,
			       u64 *shadow_ent,
			       struct guest_walker *walker,
			       gva_t addr,
			       int user)
{
	pt_element_t *guest_ent;
	int writable_shadow;
	gfn_t gfn;

	/*
	 * It seems to have been triggered for other reasons.
	 * e.g., not present.
	 */
	if (is_writeble_pte(*shadow_ent))
		return 0;

	writable_shadow = *shadow_ent & PT_SHADOW_WRITABLE_MASK;
	//cannot fix if use mode access to a kernel page or write a read-only
	//page.
	if (user) {
		/*
		 * User mode access.  Fail if it's a kernel page or a read-only
		 * page.
		 */
		if (!(*shadow_ent & PT_SHADOW_USER_MASK) || !writable_shadow)
			return 0;
		ASSERT(*shadow_ent & PT_USER_MASK);
	} else
		/*
		 * Kernel mode access.  Fail if it's a read-only page and
		 * supervisor write protection is enabled.
		 */
		if (!writable_shadow) {
			/*
			 * Set CR4.WP, inhibits supervisor from writing into read-only
			 * pages. Cannot fix.
			 */
			if (is_write_protection(vcpu))
				return 0;
			/* clear CR4.WP, WP is disable, shadow user pages as kernel page ? 
			 * 
			 * We need to read `vmx_set_cr0`, it will set GUEST_CRO in vmcs guest state
			 * to the value always masked KVM_VM_CR0_ALWAYS_ON that mask include 
			 * CR0_PE_MASK. So we want to clear PT_WRITABLE_MASK to prevent next page fault
			 * due to supervisor mode writing to this page. But check we need to avoid user mode 
			 * to write successfully. So we clear user mask to shadow user pages as kernel page.
			 *
			 * And let's think about why we need always set PT_WRITABLE_MASK of GUEST_CR4 ?
			 * Because we need to tracking supervisor write to read only page. If PT_WRITABLE_MASK
			 * set, we will lose it because guest will not trap to host when supervisor write to 
			 * read only page lead to there is no chance to update the guest pgtable entry dirty 
			 * flag.
			 *
			 * * When the next user mode read access user mode page occurs after we change user page
			 *   to kernel page in this case:
			 *       see `fix_read_pf`.
			 *
			 * * write access:
			 *      the judgment condition value is as follows
			 *         + !(*shadow_ent & PT_SHADOW_USER_MASK): false
			 *         + !(writable_shadow) is true
			 *      so return to indicating that we cannot fix this pf.
			 */
			*shadow_ent &= ~PT_USER_MASK;
		}

	guest_ent = FNAME(fetch_guest)(vcpu, walker, PT_PAGE_TABLE_LEVEL, addr);

	if (!is_present_pte(*guest_ent)) {
		*shadow_ent = 0;
		return 0;
	}

	gfn = (*guest_ent & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT;
	mark_page_dirty(vcpu->kvm, gfn);
	*shadow_ent |= PT_WRITABLE_MASK;
	*guest_ent |= PT_DIRTY_MASK;

	return 1;
}

/*
 * Page fault handler.  There are several causes for a page fault:
 *   - there is no shadow pte for the guest pte
 *   - write access through a shadow pte marked read only so that we can set
 *     the dirty bit
 *   - write access to a shadow pte marked read only so we can update the page
 *     dirty bitmap, when userspace requests it
 *   - mmio access; in this case we will never install a present shadow pte
 *   - normal guest page fault due to the guest pte marked not present, not
 *     writable, or not executable
 *
 *  Returns: 1 if we need to emulate the instruction, 0 otherwise
 */
static int FNAME(page_fault)(struct kvm_vcpu *vcpu, gva_t addr,
			       u32 error_code)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int pte_present = error_code & PFERR_PRESENT_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	struct guest_walker walker;
	u64 *shadow_pte;
	int fixed;

	/*
	 * Look up the shadow pte for the faulting address.
	 */
	for (;;) {
		FNAME(init_walker)(&walker, vcpu);
		shadow_pte = FNAME(fetch)(vcpu, addr, &walker);
		if (IS_ERR(shadow_pte)) {  /* must be -ENOMEM */
			nonpaging_flush(vcpu);
			FNAME(release_walker)(&walker);
			continue;
		}
		break;
	}

	/*
	 * The page is not mapped by the guest.  Let the guest handle it.
	 */
	/*
	 * See the return(NULL) code in FNAME(fetch)  for more information
	 */
	if (!shadow_pte) {
		inject_page_fault(vcpu, addr, error_code);
		FNAME(release_walker)(&walker);
		return 0;
	}

	/*
	 * Update the shadow pte.
	 */
	/*
	 * This KVM process allows guests to intentionally trigger page 
	 * faults to track their write behavior in order to correctly 
	 * set dirty flags.
	 */
	if (write_fault)
		fixed = FNAME(fix_write_pf)(vcpu, shadow_pte, &walker, addr,
					    user_fault);
	else
		fixed = fix_read_pf(shadow_pte);

	FNAME(release_walker)(&walker);

	/*
	 * mmio: emulate if accessible, otherwise its a guest fault.
	 */
	/*
	 * When it is not accessible, trigger guest fault even if the
	 * address is in a MMIO page.
	 */
	if (is_io_pte(*shadow_pte)) {
		if (may_access(*shadow_pte, write_fault, user_fault))
			return 1;
		pgprintk("%s: io work, no access\n", __FUNCTION__);
		inject_page_fault(vcpu, addr,
				  error_code | PFERR_PRESENT_MASK);
		return 0;
	}

	/*
	 * pte not present, guest page fault.
	 */
	/*
	 * If page fault reason is pte present and it cannot fix 
	 * by above step. The fault was caused by a page-level 
	 * protection violation. (See intel sdm 4.7 page-fault 
	 * exception). Under the correct configuration of KVM, 
	 * it may be due to incorrect configuration and access 
	 * of page table entry by guest.
	 */
	if (pte_present && !fixed) {
		inject_page_fault(vcpu, addr, error_code);
		return 0;
	}

	++kvm_stat.pf_fixed;

	return 0;
}

static gpa_t FNAME(gva_to_gpa)(struct kvm_vcpu *vcpu, gva_t vaddr)
{
	struct guest_walker walker;
	pt_element_t guest_pte;
	gpa_t gpa;

	FNAME(init_walker)(&walker, vcpu);
	guest_pte = *FNAME(fetch_guest)(vcpu, &walker, PT_PAGE_TABLE_LEVEL,
					vaddr);
	FNAME(release_walker)(&walker);

	if (!is_present_pte(guest_pte))
		return UNMAPPED_GVA;

	if (walker.level == PT_DIRECTORY_LEVEL) {
		ASSERT((guest_pte & PT_PAGE_SIZE_MASK));
		ASSERT(PTTYPE == 64 || is_pse(vcpu));

		gpa = (guest_pte & PT_DIR_BASE_ADDR_MASK) | (vaddr &
			(PT_LEVEL_MASK(PT_PAGE_TABLE_LEVEL) | ~PAGE_MASK));

		if (PTTYPE == 32 && is_cpuid_PSE36())
			gpa |= (guest_pte & PT32_DIR_PSE36_MASK) <<
					(32 - PT32_DIR_PSE36_SHIFT);
	} else {
		gpa = (guest_pte & PT_BASE_ADDR_MASK);
		gpa |= (vaddr & ~PAGE_MASK);
	}

	return gpa;
}

#undef pt_element_t
#undef guest_walker
#undef FNAME
#undef PT_BASE_ADDR_MASK
#undef PT_INDEX
#undef SHADOW_PT_INDEX
#undef PT_LEVEL_MASK
#undef PT_PTE_COPY_MASK
#undef PT_NON_PTE_COPY_MASK
#undef PT_DIR_BASE_ADDR_MASK
