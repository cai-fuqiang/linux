/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Tracepoints for CVE-2026-31431 verification.
 *
 * Covers the splice → TSGL → RSGL copy/chain → scatterwalk write data path
 * through the AF_ALG AEAD socket layer and authencesn crypto algorithm.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM crypto_splice

#if !defined(_TRACE_CRYPTO_SPLICE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CRYPTO_SPLICE_H

#include <linux/tracepoint.h>

/* Source type for pages in TSGL (TP4) */
enum {
	SOURCE_USER_PAGE = 0,
	SOURCE_PAGE_CACHE = 1,
	SOURCE_PIPE_BUF = 2,
};

/* Copy type for RSGL entries (TP5) */
enum {
	COPY_TYPE_AAD = 0,
	COPY_TYPE_CIPHERTEXT = 1,
	COPY_TYPE_TAG = 2,
};

/* RSGL stage (TP5) */
enum {
	STAGE_COPY = 0,
	STAGE_CHAIN = 1,
};

/* Scatterwalk direction (TP6, TP7) */
enum {
	SW_DIR_READ = 0,
	SW_DIR_WRITE = 1,
};

/*
 * TP1: algif_aead_sendmsg_pages
 *
 * Traces SG entries from MSG_SPLICE_PAGES data added to TSGL during sendmsg.
 */
TRACE_EVENT(algif_aead_sendmsg_pages,

	TP_PROTO(unsigned long socket_ino, int op, unsigned int assoclen,
		 int sg_index, unsigned long page_ptr, unsigned long pfn,
		 unsigned int page_offset, unsigned int len, bool is_user_page),

	TP_ARGS(socket_ino, op, assoclen, sg_index, page_ptr, pfn,
		page_offset, len, is_user_page),

	TP_STRUCT__entry(
		__field(unsigned long, socket_ino)
		__field(int, op)
		__field(unsigned int, assoclen)
		__field(int, sg_index)
		__field(unsigned long, page_ptr)
		__field(unsigned long, pfn)
		__field(unsigned int, page_offset)
		__field(unsigned int, len)
		__field(bool, is_user_page)
	),

	TP_fast_assign(
		__entry->socket_ino = socket_ino;
		__entry->op = op;
		__entry->assoclen = assoclen;
		__entry->sg_index = sg_index;
		__entry->page_ptr = page_ptr;
		__entry->pfn = pfn;
		__entry->page_offset = page_offset;
		__entry->len = len;
		__entry->is_user_page = is_user_page;
	),

	TP_printk("sock=%lu op=%s assoclen=%u sg[%d] page=0x%lx pfn=0x%lx offset=%u len=%u user=%d",
		__entry->socket_ino,
		__entry->op ? "dec" : "enc",
		__entry->assoclen,
		__entry->sg_index, __entry->page_ptr, __entry->pfn,
		__entry->page_offset, __entry->len,
		__entry->is_user_page)
);

/*
 * TP2: splice_folio_to_pipe
 *
 * Traces splice(file→pipe) putting a file page cache folio into pipe ring buffer.
 */
TRACE_EVENT(splice_folio_to_pipe,

	TP_PROTO(unsigned long inode_ino, const char *filp_path,
		 unsigned long page_ptr, unsigned long pfn,
		 int pipe_idx, unsigned int offset_in_folio,
		 unsigned int len, unsigned int refcount),

	TP_ARGS(inode_ino, filp_path, page_ptr, pfn,
		pipe_idx, offset_in_folio, len, refcount),

	TP_STRUCT__entry(
		__field(unsigned long, inode_ino)
		__string(path, filp_path)
		__field(unsigned long, page_ptr)
		__field(unsigned long, pfn)
		__field(int, pipe_idx)
		__field(unsigned int, offset)
		__field(unsigned int, len)
		__field(unsigned int, refcount)
	),

	TP_fast_assign(
		__entry->inode_ino = inode_ino;
		__assign_str(path);
		__entry->page_ptr = page_ptr;
		__entry->pfn = pfn;
		__entry->pipe_idx = pipe_idx;
		__entry->offset = offset_in_folio;
		__entry->len = len;
		__entry->refcount = refcount;
	),

	TP_printk("ino=%lu path=%s page=0x%lx pfn=0x%lx pipe[%d] offset=%u len=%u ref=%u",
		__entry->inode_ino, __get_str(path),
		__entry->page_ptr, __entry->pfn,
		__entry->pipe_idx, __entry->offset,
		__entry->len, __entry->refcount)
);

/*
 * TP3: splice_pipe_to_socket
 *
 * Traces splice(pipe→socket) passing pipe buffer pages to socket as bvec entries.
 */
TRACE_EVENT(splice_pipe_to_socket,

	TP_PROTO(unsigned long socket_ino, int pipe_idx,
		 unsigned long page_ptr, unsigned long pfn,
		 unsigned int page_offset, unsigned int len, int bvec_index),

	TP_ARGS(socket_ino, pipe_idx, page_ptr, pfn,
		page_offset, len, bvec_index),

	TP_STRUCT__entry(
		__field(unsigned long, socket_ino)
		__field(int, pipe_idx)
		__field(unsigned long, page_ptr)
		__field(unsigned long, pfn)
		__field(unsigned int, page_offset)
		__field(unsigned int, len)
		__field(int, bvec_index)
	),

	TP_fast_assign(
		__entry->socket_ino = socket_ino;
		__entry->pipe_idx = pipe_idx;
		__entry->page_ptr = page_ptr;
		__entry->pfn = pfn;
		__entry->page_offset = page_offset;
		__entry->len = len;
		__entry->bvec_index = bvec_index;
	),

	TP_printk("sock=%lu pipe[%d] page=0x%lx pfn=0x%lx offset=%u len=%u bvec=%d",
		__entry->socket_ino, __entry->pipe_idx,
		__entry->page_ptr, __entry->pfn,
		__entry->page_offset, __entry->len, __entry->bvec_index)
);

/*
 * TP4: tsgl_composition
 *
 * Dumps full TSGL after af_alg_pull_tsgl(). Each SG entry classified by source.
 */
TRACE_EVENT(tsgl_composition,

	TP_PROTO(unsigned long socket_ino, int sg_index,
		 unsigned long page_ptr, unsigned long pfn,
		 unsigned int offset, unsigned int length,
		 int source_type, unsigned long inode_ino,
		 const char *filp_path, unsigned long tsgl_base),

	TP_ARGS(socket_ino, sg_index, page_ptr, pfn,
		offset, length, source_type, inode_ino, filp_path,
		tsgl_base),

	TP_STRUCT__entry(
		__field(unsigned long, socket_ino)
		__field(int, sg_index)
		__field(unsigned long, page_ptr)
		__field(unsigned long, pfn)
		__field(unsigned int, offset)
		__field(unsigned int, length)
		__field(int, source_type)
		__field(unsigned long, inode_ino)
		__string(path, filp_path)
		__field(unsigned long, tsgl_base)
	),

	TP_fast_assign(
		__entry->socket_ino = socket_ino;
		__entry->sg_index = sg_index;
		__entry->page_ptr = page_ptr;
		__entry->pfn = pfn;
		__entry->offset = offset;
		__entry->length = length;
		__entry->source_type = source_type;
		__entry->inode_ino = inode_ino;
		__assign_str(path);
		__entry->tsgl_base = tsgl_base;
	),

	TP_printk("sock=%lu sg[%d] page=0x%lx pfn=0x%lx offset=%u len=%u src=%s ino=%lu path=%s tsgl=0x%lx",
		__entry->socket_ino, __entry->sg_index,
		__entry->page_ptr, __entry->pfn,
		__entry->offset, __entry->length,
		__print_symbolic(__entry->source_type,
			{ SOURCE_USER_PAGE, "USER" },
			{ SOURCE_PAGE_CACHE, "PAGE_CACHE" },
			{ SOURCE_PIPE_BUF, "PIPE_BUF" }),
		__entry->inode_ino, __get_str(path), __entry->tsgl_base)
);

/*
 * TP5: rsgl_copy_and_chain
 *
 * Traces RSGL construction: COPY (memcpy_sglist of AAD/CT) and CHAIN (sg_chain of tag).
 */
TRACE_EVENT(rsgl_copy_and_chain,

	TP_PROTO(unsigned long socket_ino, int stage, int sg_index,
		 unsigned long page_ptr, unsigned long pfn,
		 unsigned int offset, unsigned int length,
		 int copy_type, unsigned long dst_inode,
		 const char *dst_path, unsigned long sg_list_base),

	TP_ARGS(socket_ino, stage, sg_index, page_ptr, pfn,
		offset, length, copy_type, dst_inode, dst_path,
		sg_list_base),

	TP_STRUCT__entry(
		__field(unsigned long, socket_ino)
		__field(int, stage)
		__field(int, sg_index)
		__field(unsigned long, page_ptr)
		__field(unsigned long, pfn)
		__field(unsigned int, offset)
		__field(unsigned int, length)
		__field(int, copy_type)
		__field(unsigned long, dst_inode)
		__string(path, dst_path)
		__field(unsigned long, sg_list_base)
	),

	TP_fast_assign(
		__entry->socket_ino = socket_ino;
		__entry->stage = stage;
		__entry->sg_index = sg_index;
		__entry->page_ptr = page_ptr;
		__entry->pfn = pfn;
		__entry->offset = offset;
		__entry->length = length;
		__entry->copy_type = copy_type;
		__entry->dst_inode = dst_inode;
		__assign_str(path);
		__entry->sg_list_base = sg_list_base;
	),

	TP_printk("sock=%lu stage=%s sg[%d] page=0x%lx pfn=0x%lx offset=%u len=%u type=%s dst_ino=%lu dst_path=%s sglist=0x%lx",
		__entry->socket_ino,
		__print_symbolic(__entry->stage,
			{ STAGE_COPY, "COPY" },
			{ STAGE_CHAIN, "CHAIN" }),
		__entry->sg_index,
		__entry->page_ptr, __entry->pfn,
		__entry->offset, __entry->length,
		__print_symbolic(__entry->copy_type,
			{ COPY_TYPE_AAD, "AAD" },
			{ COPY_TYPE_CIPHERTEXT, "CT" },
			{ COPY_TYPE_TAG, "TAG" }),
		__entry->dst_inode, __get_str(path),
		__entry->sg_list_base)
);

/*
 * TP6: scatterwalk_write
 *
 * Fires when scatterwalk maps a new page for a write. Detects page cache membership.
 */
TRACE_EVENT(scatterwalk_write,

	TP_PROTO(unsigned long page_ptr, unsigned long pfn,
		 unsigned int page_offset, unsigned int write_offset,
		 unsigned int nbytes, bool is_pagecache,
		 unsigned long inode_ino, const char *filp_path,
		 unsigned long sg_entry_ptr),

	TP_ARGS(page_ptr, pfn, page_offset, write_offset, nbytes,
		is_pagecache, inode_ino, filp_path, sg_entry_ptr),

	TP_STRUCT__entry(
		__field(unsigned long, page_ptr)
		__field(unsigned long, pfn)
		__field(unsigned int, page_offset)
		__field(unsigned int, write_offset)
		__field(unsigned int, nbytes)
		__field(bool, is_pagecache)
		__field(unsigned long, inode_ino)
		__string(path, filp_path)
		__field(unsigned long, sg_entry_ptr)
	),

	TP_fast_assign(
		__entry->page_ptr = page_ptr;
		__entry->pfn = pfn;
		__entry->page_offset = page_offset;
		__entry->write_offset = write_offset;
		__entry->nbytes = nbytes;
		__entry->is_pagecache = is_pagecache;
		__entry->inode_ino = inode_ino;
		__assign_str(path);
		__entry->sg_entry_ptr = sg_entry_ptr;
	),

	TP_printk("page=0x%lx pfn=0x%lx page_off=%u write_off=%u nbytes=%u is_pgcache=%d ino=%lu path=%s sg=0x%lx",
		__entry->page_ptr, __entry->pfn,
		__entry->page_offset, __entry->write_offset,
		__entry->nbytes, __entry->is_pagecache,
		__entry->inode_ino, __get_str(path),
		__entry->sg_entry_ptr)
);

/*
 * TP7: authencesn_decrypt_step
 *
 * Traces each scatterwalk operation in crypto_authenc_esn_decrypt().
 */
TRACE_EVENT(authencesn_decrypt_step,

	TP_PROTO(bool src_eq_dst, unsigned int assoclen,
		 unsigned int cryptlen, unsigned int authsize,
		 int step, const char *step_name,
		 unsigned int start, unsigned int nbytes,
		 int direction, unsigned long target_page_ptr,
		 unsigned long target_pfn),

	TP_ARGS(src_eq_dst, assoclen, cryptlen, authsize,
		step, step_name, start, nbytes,
		direction, target_page_ptr, target_pfn),

	TP_STRUCT__entry(
		__field(bool, src_eq_dst)
		__field(unsigned int, assoclen)
		__field(unsigned int, cryptlen)
		__field(unsigned int, authsize)
		__field(int, step)
		__string(name, step_name)
		__field(unsigned int, start)
		__field(unsigned int, nbytes)
		__field(int, direction)
		__field(unsigned long, page_ptr)
		__field(unsigned long, pfn)
	),

	TP_fast_assign(
		__entry->src_eq_dst = src_eq_dst;
		__entry->assoclen = assoclen;
		__entry->cryptlen = cryptlen;
		__entry->authsize = authsize;
		__entry->step = step;
		__assign_str(name);
		__entry->start = start;
		__entry->nbytes = nbytes;
		__entry->direction = direction;
		__entry->page_ptr = target_page_ptr;
		__entry->pfn = target_pfn;
	),

	TP_printk("src_eq_dst=%d assoclen=%u cryptlen=%u authsize=%u step=%d name=%s start=%u nbytes=%u dir=%s page=0x%lx pfn=0x%lx",
		__entry->src_eq_dst,
		__entry->assoclen, __entry->cryptlen, __entry->authsize,
		__entry->step, __get_str(name),
		__entry->start, __entry->nbytes,
		__print_symbolic(__entry->direction,
			{ SW_DIR_READ, "R" },
			{ SW_DIR_WRITE, "W" }),
		__entry->page_ptr, __entry->pfn)
);

#endif /* _TRACE_CRYPTO_SPLICE_H */

/* This part must be outside the include guard */
#include <trace/define_trace.h>
