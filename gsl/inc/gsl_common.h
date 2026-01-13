#ifndef GSL_COMMON_H
#define GSL_COMMON_H
/**
 * \file gsl_common.h
 *
 * \brief
 *      Common header file used by GSL modules.
 *
 * \copyright
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "ar_osal_types.h"
#include "ar_osal_log.h"
#include "ar_osal_file_io.h"
#include "ar_osal_mutex.h"
#include "ar_osal_signal.h"
#include "ar_osal_heap.h"
#include "ar_osal_mem_op.h"
#include "ar_osal_servreg.h"
#include "gpr_ids_domains.h"
#include "gpr_packet.h"
#include "gsl_spf_timeout.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define GSL_TIMEOUT_NS(x)  ((x) * (1000LL) * (1000LL))
#define GSL_TIMEOUT_US(x)  ((x) * (1000LL))
#define GSL_ALIGN_8BYTE(x) (((x) + 7) & (~7))
#define GSL_PADDING_8BYTE_ALIGN(x)  ((((x) + 7) & 7) ^ 7)
#define GSL_GPR_SRC_DOMAIN_ID GPR_IDS_DOMAIN_ID_APPS_V
#ifdef MDSP_PROC
#define GSL_GPR_DST_DOMAIN_ID GPR_IDS_DOMAIN_ID_MODEM_V
#else
#define GSL_GPR_DST_DOMAIN_ID GPR_IDS_DOMAIN_ID_ADSP_V
#endif
#define GSL_EXT_MEM_HDL_NOT_ALLOCD 0

#define DEBUG_TOKEN_MASK 0xFFFFF000
#define DEBUG_TOKEN_SHIFT 12
#define INSERT_DEBUG_TOKEN(x, value) (x) = (x) | ((value) << DEBUG_TOKEN_SHIFT)
#define GET_DEBUG_TOKEN(x, value) (value) = ((x) & DEBUG_TOKEN_MASK) \
	>> DEBUG_TOKEN_SHIFT
#define REMOVE_DEBUG_TOKEN(x) (x) = ((x) & ~DEBUG_TOKEN_MASK)

#define GSL_GET_SPF_SS_MASK(OSAL_SYS_ID) (1<<(OSAL_SYS_ID - 1))
#define GSL_TEST_SPF_SS_BIT(SPF_SS_MASK, OSAL_SYS_ID) \
((OSAL_SYS_ID) && ((SPF_SS_MASK) \
& GSL_GET_SPF_SS_MASK(OSAL_SYS_ID))>>(OSAL_SYS_ID - 1))

#define GSL_LOG_TAG  "gsl"
#define GSL_ERR(...) AR_LOG_ERR(GSL_LOG_TAG, __VA_ARGS__)

#if defined(GSL_LOG_PKT_ENABLE) || defined(GSL_LOG_DATA_ENABLE)
// packet & data logging general
/* for now both data and control are logged to same file */

extern ar_fhandle pkt_log_fd;
extern char *gsl_str;
extern ar_osal_mutex_t log_mutex;
static uint32_t log_file_ref_count;

#ifndef GSL_PKT_LOG_PATH
#define GSL_PKT_LOG_PATH "gsl_log.bin"
#endif

#define GSL_PKT_LOG_INIT() \
do {\
log_file_ref_count = 0; \
ar_osal_mutex_create(&log_mutex); \
} while (0)

#define GSL_PKT_LOG_OPEN(FILE_ACCESS) \
do {\
GSL_MUTEX_LOCK(log_mutex); \
log_file_ref_count++; \
if (pkt_log_fd == NULL && log_file_ref_count == 1) {\
ar_fopen(&pkt_log_fd, GSL_PKT_LOG_PATH, FILE_ACCESS);\
} \
GSL_MUTEX_UNLOCK(log_mutex); \
} while (0)


#define GSL_PKT_LOG_CLOSE() \
do {\
GSL_MUTEX_LOCK(log_mutex); \
if (log_file_ref_count > 0) \
log_file_ref_count--; \
if (pkt_log_fd != NULL && log_file_ref_count == 0) {\
ar_fclose(pkt_log_fd); \
pkt_log_fd = NULL; \
} \
GSL_MUTEX_UNLOCK(log_mutex); \
} while (0)

/*
 * @param DST_FD File descriptor where logs will be logged to
 * @param ID_STR MUST be exactly 8 chars, string that will be placed in the log
 *					  before BUFF to help in parsing
 * @param META_DATA 4-byte meta-data field that caller can set to anything
 * @param DATA_BUFF pointer to buffer that will be written to log
 * @param DATA_SIZE size of the buffer above
 * @param OOB_BUFF optional out-of-band or second buffer to also write to log
 * @param OOB_SIZE size of the second buffer above
 */
#define GSL_PKT_LOG_TO_FILE(DST_FD, ID_STR, META_DATA, DATA_BUFF, DATA_SIZE, \
OOB_BUFF, OOB_SIZE)\
do {\
GSL_MUTEX_LOCK(log_mutex); \
if (pkt_log_fd != NULL) {\
size_t bytes_written; \
char *id_str = ID_STR; \
uint32_t metadata = META_DATA; \
uint32_t metadata_size = sizeof(metadata); \
uint32_t packet_size = DATA_SIZE + OOB_SIZE + metadata_size \
+ sizeof(metadata_size); \
ar_fwrite(DST_FD, gsl_str, strlen(gsl_str), &bytes_written); \
ar_fwrite(DST_FD, id_str, strlen(id_str), &bytes_written); \
ar_fwrite(DST_FD, &packet_size, sizeof(packet_size), &bytes_written); \
ar_fwrite(DST_FD, &metadata_size, sizeof(metadata_size), &bytes_written); \
ar_fwrite(DST_FD, &metadata, metadata_size, &bytes_written); \
if (0 != DATA_SIZE) \
ar_fwrite(DST_FD, DATA_BUFF, DATA_SIZE, &bytes_written); \
if (0 != OOB_SIZE) \
ar_fwrite(DST_FD, OOB_BUFF, OOB_SIZE, &bytes_written); \
} \
GSL_MUTEX_UNLOCK(log_mutex); \
} while (0)

#define GSL_PKT_LOG_DEINIT() \
do { \
if (pkt_log_fd != NULL) {\
ar_fclose(pkt_log_fd); \
pkt_log_fd = NULL; \
} \
ar_osal_mutex_destroy(log_mutex); \
} while (0)
#else
#define GSL_PKT_LOG_INIT()
#define GSL_PKT_LOG_DEINIT()
#define GSL_PKT_LOG_OPEN(FILE_ACCESS)
#define GSL_PKT_LOG_CLOSE()
#endif

#ifdef GSL_LOG_PKT_ENABLE
#define GSL_LOG_PKT(ID_STR, META_DATA, PKT_BUFF, PKT_SIZE, \
OOB_BUFF, OOB_SIZE) \
GSL_PKT_LOG_TO_FILE(pkt_log_fd, ID_STR, META_DATA, PKT_BUFF, PKT_SIZE, \
OOB_BUFF, OOB_SIZE)
#else
#define GSL_LOG_PKT(ID_STR, META_DATA, PKT_BUFF, PKT_SIZE, OOB_BUFF, OOB_SIZE)
#endif //GSL_LOG_PKT_ENABLE

#ifdef GSL_LOG_DATA_ENABLE
#define GSL_PKT_LOG_DATA(ID_STR, META_DATA, BUFF, SIZE) \
GSL_PKT_LOG_TO_FILE(pkt_log_fd, ID_STR, META_DATA, BUFF, SIZE, NULL, 0)
#else
#define GSL_PKT_LOG_DATA(ID_STR, META_DATA, BUFF, SIZE)
#endif // GSL_LOG_DATA_ENABLE

#ifdef GSL_DEBUG_ENABLE
#define GSL_DBG(...)  AR_LOG_DEBUG(GSL_LOG_TAG, __VA_ARGS__)
#define GSL_INFO(...) AR_LOG_INFO(GSL_LOG_TAG, __VA_ARGS__)
#define GSL_VERBOSE(...) AR_LOG_VERBOSE(GSL_LOG_TAG, __VA_ARGS__)

static inline void gsl_print_sg_conn_info(uint32_t *sg_conn_info,
	uint32_t num_sgs)
{
	uint32_t i = 0, num_children = 0;
	uint32_t *p = sg_conn_info;

	GSL_DBG("num_sg_conn = %d", num_sgs);
	for (i = 0; i < num_sgs; ++i) {
		GSL_DBG("sg %x has %d children:", *(p),	num_children = *(p + 1));
		p += 2;
		while (num_children) {
			GSL_DBG("%x, ", *(p++));
			--num_children;
		}
	}
}

#else
#define GSL_LOG_TAG  "gsl"
#define GSL_DBG(...)
#define GSL_INFO(...)
#define GSL_VERBOSE(...)
#define GSL_PRINT_SG_CONN_INFO(SG_CONN_INFO_PTR)
static inline void gsl_print_sg_conn_info(uint32_t *sg_conn_info,
	uint32_t num_sgs)
{ (void) sg_conn_info; (void) num_sgs; /* keep compiler happy */ }
#endif /* GSL_DEBUG_ENABLE */

 /** get container base address given a member from the same structure */
#define get_container_base(p, type, member) ((type *)( \
	(int8_t *)(p)- \
	(uintptr_t)(&((type *)0)->member)))


#define test_bit(var, bit_pos)  ((var) & (1 << (bit_pos)))
#define set_bit(var, bit_pos)  (var = (var) | (1 << (bit_pos)))
#define clear_bit(var, bit_pos)   (var = (var) & (~(1 << (bit_pos))))
#define get_bit(var, bit_pos)   (((var) & (1 << (bit_pos)))>>(bit_pos))

#define GSL_MUTEX_LOCK(lock) \
	do {  \
		if (lock) \
			if (ar_osal_mutex_lock(lock)) \
				GSL_ERR("failed to acquire mutex"); \
	} while (0)

#define GSL_MUTEX_UNLOCK(lock) \
	do {  \
		if (lock) \
			if (ar_osal_mutex_unlock(lock)) \
				GSL_ERR("failed to release mutex"); \
	} while (0)

/* used to decode basic responses from Spf */
struct spf_cmd_basic_rsp {
	uint32_t opcode;
	int32_t status;
};

 /** Graph signal object structure */
struct gsl_signal {
	/** signal object */
	ar_osal_signal_t sig;
	/**
	 * mutex used to synchronize access to below data
	 */
	ar_osal_mutex_t *lock;
	/**
	 * bitmask that indicates which events caused the signal to get set
	 * GSL_GRAPH_SIG_FLAG_SPF_RSP --> response was received from spf
	 * GSL_GRAPH_SIG_FLAG_CLOSE --> close was triggered from client
	 */
	uint32_t flags;
	/** signal status */
	int32_t status;
	/** gpr packet pointer */
	void *gpr_packet;
	/** gpr expected packet token */
	uint32_t expected_packet_token;
};

enum gsl_graph_sig_event_mask {
	GSL_SIG_EVENT_MASK_SPF_RSP = 0x1,
	GSL_SIG_EVENT_MASK_CLOSE = 0x2,
	GSL_SIG_EVENT_MASK_RTGM_DONE = 0x4,
	GSL_SIG_EVENT_CLIENT_OP_DONE = 0x8,
	GSL_SIG_EVENT_MASK_SSR = 0x10
};

struct gsl_servreg_handle_list {
	uint32_t num_handles;
	ar_osal_servreg_t handles[];
};

/** signal functions */
uint32_t gsl_signal_create(struct gsl_signal *sig_p, ar_osal_mutex_t *lock);
uint32_t gsl_signal_destroy(struct gsl_signal *sig_p);
uint32_t gsl_signal_timedwait(struct gsl_signal *sig_p, uint32_t timeout_ms,
	uint32_t *ev_flags, uint32_t *status, gpr_packet_t **gpr_pkt);
uint32_t gsl_signal_set(struct gsl_signal *sig_p, uint32_t ev_flags,
	int32_t status, void *gpr_pkt);
uint32_t gsl_signal_clear(struct gsl_signal *sig_p, uint32_t ev_flags);
int32_t gsl_allocate_gpr_packet(uint32_t opcode, uint32_t src_port,
	uint32_t dst_port, uint32_t payload_size, uint32_t token,
	uint32_t dest_domain, struct gpr_packet_t **alloc_packet);
int32_t gsl_send_spf_cmd(struct gpr_packet_t **packet,
	struct gsl_signal *sig_p, gpr_packet_t **rsp_pkt);
int32_t gsl_send_spf_cmd_wait_for_basic_rsp(gpr_packet_t **packet,
	struct gsl_signal *sig_p);
int32_t gsl_send_spf_satellite_info(uint32_t proc_id,
	uint32_t supported_ss_mask, uint32_t src_port, struct gsl_signal *sig_p);

/** memory allocation helper functions */
static inline void *gsl_mem_zalloc(size_t size)
{
	void *p;

	static ar_heap_info heap_info = {
		.align_bytes = AR_HEAP_ALIGN_DEFAULT,
		.pool_type = AR_HEAP_POOL_DEFAULT,
		.heap_id = AR_HEAP_ID_DEFAULT,
		.tag = AR_HEAP_TAG_DEFAULT
	};

	/* allocate and initialize with 0 */
	p = ar_heap_calloc(size, &heap_info);

	return p;
}

static inline void gsl_mem_free(void *p)
{
	static ar_heap_info heap_info = {
		.align_bytes = AR_HEAP_ALIGN_DEFAULT,
		.pool_type = AR_HEAP_POOL_DEFAULT,
		.heap_id = AR_HEAP_ID_DEFAULT,
		.tag = AR_HEAP_TAG_DEFAULT
	};

	ar_heap_free(p, &heap_info);
}

static inline int32_t gsl_memset(void *p, int32_t val, size_t size)
{
	return ar_mem_set(p, val, size);
}

static inline int32_t gsl_memcpy(void *dst, size_t dst_size, const void *src,
	size_t size)
{
	return ar_mem_cpy(dst, dst_size, src, size);
}

static inline void *gsl_mem_realloc(void *p, size_t old_sz, size_t new_sz)
{
	void *new_p = NULL;
	static ar_heap_info heap_info = {
		.align_bytes = AR_HEAP_ALIGN_DEFAULT,
		.pool_type = AR_HEAP_POOL_DEFAULT,
		.heap_id = AR_HEAP_ID_DEFAULT,
		.tag = AR_HEAP_TAG_DEFAULT
	};

	new_p = ar_heap_malloc(new_sz, &heap_info);
	if (!new_p) {
		GSL_ERR("ar_heap_malloc alloc mem failed!");
	} else {
		gsl_memset(new_p, 0, new_sz);
		gsl_memcpy(new_p, new_sz, p, old_sz);
		ar_heap_free(p, &heap_info);
	}

	return new_p;
}

#endif
