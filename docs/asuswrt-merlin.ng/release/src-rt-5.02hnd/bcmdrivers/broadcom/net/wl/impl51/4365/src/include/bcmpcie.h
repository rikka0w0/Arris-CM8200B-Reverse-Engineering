/*
 * Broadcom PCIE
 * Software-specific definitions shared between device and host side
 * Explains the shared area between host and dongle
 * Copyright (C) 2017, Broadcom. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: bcmpcie.h 661371 2016-09-25 01:54:17Z $
 */

#ifndef	_bcmpcie_h_
#define	_bcmpcie_h_

#include <bcmutils.h>

#define ADDR_64(x)			(x.addr)
#define HIGH_ADDR_32(x)     ((uint32) (((sh_addr_t) x).high_addr))
#define LOW_ADDR_32(x)      ((uint32) (((sh_addr_t) x).low_addr))

typedef struct {
	uint32 low_addr;
	uint32 high_addr;
} sh_addr_t;



#ifdef BCMPCIE_SUPPORT_TX_PUSH_RING
#define BCMPCIE_PUSH_TX_RING	1
#else
#define BCMPCIE_PUSH_TX_RING	0
#endif /* BCMPCIE_SUPPORT_TX_PUSH_RING */

/* May be overridden by 43xxxxx-roml.mk */
#if !defined(BCMPCIE_MAX_TX_FLOWS)
#define BCMPCIE_MAX_TX_FLOWS	40
#endif /* ! BCMPCIE_MAX_TX_FLOWS */

#define PCIE_SHARED_VERSION		0x00005
#define PCIE_SHARED_VERSION_MASK	0x000FF
#define PCIE_SHARED_ASSERT_BUILT	0x00100
#define PCIE_SHARED_ASSERT		0x00200
#define PCIE_SHARED_TRAP		0x00400
#define PCIE_SHARED_IN_BRPT		0x00800
#define PCIE_SHARED_SET_BRPT		0x01000
#define PCIE_SHARED_PENDING_BRPT	0x02000
#define PCIE_SHARED_TXPUSH_SPRT		0x04000
#define PCIE_SHARED_EVT_SEQNUM		0x08000
#define PCIE_SHARED_DMA_INDEX		0x10000

/* D2H M2M DMA Complete Sync mechanism: Modulo-253-SeqNum or XORCSUM */
#define PCIE_SHARED_D2H_SYNC_SEQNUM     0x20000
#define PCIE_SHARED_D2H_SYNC_XORCSUM    0x40000
#define PCIE_SHARED_D2H_SYNC_MODE_MASK \
	(PCIE_SHARED_D2H_SYNC_SEQNUM | PCIE_SHARED_D2H_SYNC_XORCSUM)
#define PCIE_SHARED_IDLE_FLOW_RING      0x80000
#define PCIE_SHARED_2BYTE_INDICES       0x100000
#define PCIE_SHARED_DHDHDR              0x200000 /* BCM_DHDHDR */

/* BCM_DHDHDR: DHD can offload a maximum of 3072 * 256 Byte Txheaders. */
#define BCM_DHDHDR_MAXIMUM         3072
#define BCM_DHDHDR_SIZE            256


#define PCIE_SHARED_D2H_MAGIC		0xFEDCBA09
#define PCIE_SHARED_H2D_MAGIC		0x12345678

#define BCMPCIE_H2D_MSGRING_CONTROL_SUBMIT		0
#define BCMPCIE_H2D_MSGRING_RXPOST_SUBMIT		1
#define BCMPCIE_D2H_MSGRING_CONTROL_COMPLETE		2
#define BCMPCIE_D2H_MSGRING_TX_COMPLETE			3
#define BCMPCIE_D2H_MSGRING_RX_COMPLETE			4
#define BCMPCIE_COMMON_MSGRING_MAX_ID			4

/* Added only for single tx ring */
#define BCMPCIE_H2D_TXFLOWRINGID			5

#define BCMPCIE_H2D_COMMON_MSGRINGS			2
#define BCMPCIE_D2H_COMMON_MSGRINGS			3
#define BCMPCIE_COMMON_MSGRINGS				5

#define BCMPCIE_H2D_MSGRINGS(max_tx_flows) \
	(BCMPCIE_H2D_COMMON_MSGRINGS + (max_tx_flows))

/**
 * H2D and D2H, WR and RD index, are maintained in the following arrays:
 * - Array of all H2D WR Indices
 * - Array of all H2D RD Indices
 * - Array of all D2H WR Indices
 * - Array of all D2H RD Indices
 *
 * The offset of the WR or RD indexes (for common rings) in these arrays are
 * listed below. Arrays ARE NOT indexed by a ring's id.
 *
 * D2H common rings WR and RD index start from 0, even though their ringids
 * start from BCMPCIE_H2D_COMMON_MSGRINGS
 */

#define BCMPCIE_H2D_RING_IDX(h2d_ring_id) (h2d_ring_id)

enum h2dring_idx {
	/* H2D Common Rings */
	BCMPCIE_H2D_MSGRING_CONTROL_SUBMIT_IDX =
		BCMPCIE_H2D_RING_IDX(BCMPCIE_H2D_MSGRING_CONTROL_SUBMIT),
	BCMPCIE_H2D_MSGRING_RXPOST_SUBMIT_IDX =
		BCMPCIE_H2D_RING_IDX(BCMPCIE_H2D_MSGRING_RXPOST_SUBMIT),

	/* First TxPost's WR or RD index starts after all H2D common rings */
	BCMPCIE_H2D_MSGRING_TXFLOW_IDX_START =
		BCMPCIE_H2D_RING_IDX(BCMPCIE_H2D_COMMON_MSGRINGS)
};

#define BCMPCIE_D2H_RING_IDX(d2h_ring_id) \
	((d2h_ring_id) - BCMPCIE_H2D_COMMON_MSGRINGS)

enum d2hring_idx {
	/* D2H Common Rings */
	BCMPCIE_D2H_MSGRING_CONTROL_COMPLETE_IDX =
		BCMPCIE_D2H_RING_IDX(BCMPCIE_D2H_MSGRING_CONTROL_COMPLETE),
	BCMPCIE_D2H_MSGRING_TX_COMPLETE_IDX =
		BCMPCIE_D2H_RING_IDX(BCMPCIE_D2H_MSGRING_TX_COMPLETE),
	BCMPCIE_D2H_MSGRING_RX_COMPLETE_IDX =
		BCMPCIE_D2H_RING_IDX(BCMPCIE_D2H_MSGRING_RX_COMPLETE)
};

/**
 * Macros for managing arrays of RD WR indices:
 * rw_index_sz:
 *    - in dongle, rw_index_sz is known at compile time
 *    - in host/DHD, rw_index_sz is derived from advertized pci_shared flags
 *
 *  ring_idx: See h2dring_idx and d2hring_idx
 */

/** Offset of a RD or WR index in H2D or D2H indices array */
#define BCMPCIE_RW_INDEX_OFFSET(rw_index_sz, ring_idx) \
	((rw_index_sz) * (ring_idx))

/** Fetch the address of RD or WR index in H2D or D2H indices array */
#define BCMPCIE_RW_INDEX_ADDR(indices_array_base, rw_index_sz, ring_idx) \
	(void *)((uint32)(indices_array_base) + \
	BCMPCIE_RW_INDEX_OFFSET((rw_index_sz), (ring_idx)))

/** H2D DMA Indices array size: given max flow rings */
#define BCMPCIE_H2D_RW_INDEX_ARRAY_SZ(rw_index_sz, max_tx_flows) \
	((rw_index_sz) * BCMPCIE_H2D_MSGRINGS(max_tx_flows))

/** D2H DMA Indices array size */
#define BCMPCIE_D2H_RW_INDEX_ARRAY_SZ(rw_index_sz) \
	((rw_index_sz) * BCMPCIE_D2H_COMMON_MSGRINGS)


typedef struct ring_mem {
	uint16		idx;
	uint8		type;
	uint8		rsvd;
	uint16		max_item;
	uint16		len_items;
	sh_addr_t	base_addr;
} ring_mem_t;

#define RINGSTATE_INITED	1

typedef struct ring_state {
	uint8 idx;
	uint8 state;
	uint16 r_offset;
	uint16 w_offset;
	uint16 e_offset;
} ring_state_t;


typedef struct ring_info {
	/* locations in the TCM where the ringmem is and ringstate are defined */
	uint32		ringmem_ptr; /* ring mem location in dongle memory */

	/* Following arrays are indexed using h2dring_idx and d2hring_idx, and not
	 * by a ringid.
	 */

	/* 32bit ptr to arrays of WR or RD indices for all rings in dongle memory */
	uint32		h2d_w_idx_ptr;
	uint32		h2d_r_idx_ptr;
	uint32		d2h_w_idx_ptr;
	uint32		d2h_r_idx_ptr;

	/* PCIE_DMA_INDEX feature: Dongle uses mem2mem DMA to sync arrays in host.
	 * Host may directly fetch WR and RD indices from these host-side arrays.
	 *
	 * 64bit ptr to arrays of WR or RD indices for all rings in host memory.
	 */
	sh_addr_t	h2d_w_idx_hostaddr;
	sh_addr_t	h2d_r_idx_hostaddr;
	sh_addr_t	d2h_w_idx_hostaddr;
	sh_addr_t	d2h_r_idx_hostaddr;

	uint16		max_sub_queues; /* Max number of h2d rings incld common rings */
	uint16		rsvd;
} ring_info_t;

typedef struct {
	/* shared area version captured at flags 7:0 */
	uint32	flags;

	uint32  trap_addr;
	uint32  assert_exp_addr;
	uint32  assert_file_addr;
	uint32  assert_line;
	uint32	console_addr;		/* Address of hnd_cons_t */

	uint32  msgtrace_addr;

	uint32  fwid;

	/* Used for debug/flow control */
	uint16  total_lfrag_pkt_cnt;
	uint16  max_host_rxbufs; /* rsvd in spec */

	uint32 dma_rxoffset; /* rsvd in spec */

	/* these will be used for sleep request/ack, d3 req/ack */
	uint32  h2d_mb_data_ptr;
	uint32  d2h_mb_data_ptr;

	/* information pertinent to host IPC/msgbuf channels */
	/* location in the TCM memory which has the ring_info */
	uint32	rings_info_ptr;

	/* block of host memory for the scratch buffer */
	uint32		host_dma_scratch_buffer_len;
	sh_addr_t	host_dma_scratch_buffer;

	/* block of host memory for the dongle to push the status into */
	uint32		device_rings_stsblk_len;
	sh_addr_t	device_rings_stsblk;

	uint32	buzzz;	/* BUZZZ state format strings and trace buffer */

} pciedev_shared_t;


/* H2D mail box Data */
#define H2D_HOST_D3_INFORM	0x00000001
#define H2D_HOST_DS_ACK		0x00000002
#define H2D_HOST_DS_NAK		0x00000004
#define H2D_HOST_CONS_INT	0x80000000	/* h2d int for console cmds  */

#define H2D_HOST_D0_INFORM_IN_USE		0x00000008
#define H2D_HOST_D0_INFORM	0x00000010

/* D2H mail box Data */
#define D2H_DEV_D3_ACK		0x00000001
#define D2H_DEV_DS_ENTER_REQ	0x00000002
#define D2H_DEV_DS_EXIT_NOTE	0x00000004
#define D2H_DEV_FWHALT		0x10000000


extern pciedev_shared_t pciedev_shared;
#define NEXTTXP(i, d)           ((((i)+1) >= (d)) ? 0 : ((i)+1))
#define NEXTNTXP(i, n, d)       ((((i)+(n)) >= (d)) ? 0 : ((i)+(n)))
#define NTXPACTIVE(r, w, d)     (((r) <= (w)) ? ((w)-(r)) : ((d)-(r)+(w)))
#define NTXPAVAIL(r, w, d)      (((d) - NTXPACTIVE((r), (w), (d))) > 1)

/* Function can be used to notify host of FW halt */
#define READ_AVAIL_SPACE(w, r, d)		\
			((w >= r) ? (w - r) : (d - r))

#define WRT_PEND(x)	((x)->wr_pending)
#define DNGL_RING_WPTR(msgbuf)		(*((msgbuf)->tcm_rs_w_ptr))
#define BCMMSGBUF_RING_SET_W_PTR(msgbuf, a)	(DNGL_RING_WPTR(msgbuf) = (a))

#define DNGL_RING_RPTR(msgbuf)		(*((msgbuf)->tcm_rs_r_ptr))
#define BCMMSGBUF_RING_SET_R_PTR(msgbuf, a)	(DNGL_RING_RPTR(msgbuf) = (a))

#define MODULO_RING_IDX(x, y)	((x) % (y)->bitmap_size)

#define  RING_READ_PTR(x)	((x)->ringstate->r_offset)
#define  RING_WRITE_PTR(x)	((x)->ringstate->w_offset)
#define  RING_START_PTR(x)	((x)->ringmem->base_addr.low_addr)
#define  RING_MAX_ITEM(x)	((x)->ringmem->max_item)
#define  RING_LEN_ITEMS(x)	((x)->ringmem->len_items)
#define	 HOST_RING_BASE(x)	((x)->ring_base.va)
#define	 HOST_RING_END(x)	((uint8 *)HOST_RING_BASE((x)) + \
			 ((RING_MAX_ITEM((x))-1)*RING_LEN_ITEMS((x))))

#define WRITE_SPACE_AVAIL_CONTINUOUS(r, w, d)		((w >= r) ? (d - w) : (r - w))
#define WRITE_SPACE_AVAIL(r, w, d)	(d - (NTXPACTIVE(r, w, d)) - 1)
#define CHECK_WRITE_SPACE(r, w, d)	\
	((r) > (w)) ? ((r) - (w) - 1) : ((r) == 0 || (w) == 0) ? ((d) - (w) - 1) : ((d) - (w))
#define CHECK_NOWRITE_SPACE(r, w, d)	\
	(((r) == (w) + 1) || (((r) == 0) && ((w) == ((d) - 1))))

#endif	/* _bcmpcie_h_ */
