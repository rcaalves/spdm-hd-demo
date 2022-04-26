#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <scsi/scsi_cmnd.h>
#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-virtio.h>
#include <linux/numa.h>

#define SPDM_ENABLED 1
#if SPDM_ENABLED
#include "../../block/blk-mq-sched.h"

// avoiding some annoying compilation warnings
#pragma GCC diagnostic ignored "-Wundef"

#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#endif

#include <spdm_common_lib.h>
#include <library/spdm_requester_lib.h>
#include <library/spdm_transport_mctp_lib.h>
#include <industry_standard/mctp.h>
#include <spdm_requester_lib_internal.h>
#include <spdm_secured_message_lib_internal.h>

#include "spdm_temp_emu.c"
#include "spdm_auth.c"

#pragma GCC diagnostic pop

#endif /* SPDM_ENABLED */

#define PART_BITS 4
#define VQ_NAME_LEN 16

static int major;
static DEFINE_IDA(vd_index_ida);

#define BLK_SPDM_DEBUG 0

#if BLK_SPDM_DEBUG
#define BLK_SPDM_PRINT(format,  ...) printk(format, ##__VA_ARGS__)
#else
#define BLK_SPDM_PRINT(format,  ...)
#endif /*BLK_SPDM_DEBUG*/

static struct workqueue_struct *virtblk_wq;

static spinlock_t spdm_spinlock;

struct virtio_blk_vq {
	struct virtqueue *vq;
	spinlock_t lock;
	char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

struct virtio_blk {
	struct virtio_device *vdev;

	/* The disk structure for the kernel. */
	struct gendisk *disk;

	/* Block layer tags. */
	struct blk_mq_tag_set tag_set;

	/* Process context for config space updates */
	struct work_struct config_work;

	/* What host tells us, plus 2 for header & tailer. */
	unsigned int sg_elems;

	/* Ida index - used to track minor number allocations. */
	int index;

	/* num of vqs */
	int num_vqs;
	struct virtio_blk_vq *vqs;

#if SPDM_ENABLED
	void* spdm_context;
	struct kobject *spdm_sysfs;
	bool ts[10];
	uint32 session_id;
#endif
};

struct virtblk_req {
#ifdef CONFIG_VIRTIO_BLK_SCSI
	struct scsi_request sreq;	/* for SCSI passthrough, must be first */
	u8 sense[SCSI_SENSE_BUFFERSIZE];
	struct virtio_scsi_inhdr in_hdr;
#endif
	struct virtio_blk_outhdr out_hdr;
	u8 status;
	struct scatterlist sg[];
};

#if SPDM_ENABLED
static int virtblk_send_arbitrary_data(struct gendisk *disk, char *buf, size_t size, sector_t pos, unsigned int op, struct request* main_req);
static int virtblk_get_arbitrary_data(struct gendisk *disk, char *buf, size_t *size, sector_t pos, unsigned int op, struct request* main_req);
void* virtblk_init_spdm(void);
#endif /* SPDM_ENABLED */

static inline blk_status_t virtblk_result(struct virtblk_req *vbr)
{
	switch (vbr->status) {
	case VIRTIO_BLK_S_OK:
		return BLK_STS_OK;
	case VIRTIO_BLK_S_UNSUPP:
		return BLK_STS_NOTSUPP;
	default:
		return BLK_STS_IOERR;
	}
}

/*
 * If this is a packet command we need a couple of additional headers.  Behind
 * the normal outhdr we put a segment with the scsi command block, and before
 * the normal inhdr we put the sense data and the inhdr with additional status
 * information.
 */
#ifdef CONFIG_VIRTIO_BLK_SCSI
static int virtblk_add_req_scsi(struct virtqueue *vq, struct virtblk_req *vbr,
		struct scatterlist *data_sg, bool have_data)
{
	struct scatterlist hdr, status, cmd, sense, inhdr, *sgs[6];
	unsigned int num_out = 0, num_in = 0;

	sg_init_one(&hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sgs[num_out++] = &hdr;
	sg_init_one(&cmd, vbr->sreq.cmd, vbr->sreq.cmd_len);
	sgs[num_out++] = &cmd;

	if (have_data) {
		if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT))
			sgs[num_out++] = data_sg;
		else
			sgs[num_out + num_in++] = data_sg;
	}

	sg_init_one(&sense, vbr->sense, SCSI_SENSE_BUFFERSIZE);
	sgs[num_out + num_in++] = &sense;
	sg_init_one(&inhdr, &vbr->in_hdr, sizeof(vbr->in_hdr));
	sgs[num_out + num_in++] = &inhdr;
	sg_init_one(&status, &vbr->status, sizeof(vbr->status));
	sgs[num_out + num_in++] = &status;

	return virtqueue_add_sgs(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
}

static inline void virtblk_scsi_request_done(struct request *req)
{
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
	struct virtio_blk *vblk = req->q->queuedata;
	struct scsi_request *sreq = &vbr->sreq;

	sreq->resid_len = virtio32_to_cpu(vblk->vdev, vbr->in_hdr.residual);
	sreq->sense_len = virtio32_to_cpu(vblk->vdev, vbr->in_hdr.sense_len);
	sreq->result = virtio32_to_cpu(vblk->vdev, vbr->in_hdr.errors);
}

static int virtblk_ioctl(struct block_device *bdev, fmode_t mode,
			     unsigned int cmd, unsigned long data)
{
	struct gendisk *disk = bdev->bd_disk;
	struct virtio_blk *vblk = disk->private_data;

	/*
	 * Only allow the generic SCSI ioctls if the host can support it.
	 */
	if (!virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_SCSI))
		return -ENOTTY;

	return scsi_cmd_blk_ioctl(bdev, mode, cmd,
				  (void __user *)data);
}
#else
static inline int virtblk_add_req_scsi(struct virtqueue *vq,
		struct virtblk_req *vbr, struct scatterlist *data_sg,
		bool have_data)
{
	return -EIO;
}
static inline void virtblk_scsi_request_done(struct request *req)
{
}
#define virtblk_ioctl	NULL
#endif /* CONFIG_VIRTIO_BLK_SCSI */

static int virtblk_add_req(struct virtqueue *vq, struct virtblk_req *vbr,
		struct scatterlist *data_sg, bool have_data)
{
	struct scatterlist hdr, status, *sgs[3];
	unsigned int num_out = 0, num_in = 0;

	sg_init_one(&hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
	sgs[num_out++] = &hdr;

	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM, virt_blk: virtblk_add_req (type = %X, length = %u) ", vbr->out_hdr.type, data_sg->length);
	if (have_data) {
		if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT)) {
			sgs[num_out++] = data_sg;
		}
		else {
			sgs[num_out + num_in++] = data_sg;
		}
	}

	sg_init_one(&status, &vbr->status, sizeof(vbr->status));
	sgs[num_out + num_in++] = &status;

	return virtqueue_add_sgs(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
}

#if SPDM_ENABLED
void spdm_fix_internal_seqno(spdm_context_t *spdm_context, uint8 *msg_buffer) {
    // hax to fix out of order sequence numbers, considering 16-bit overflows
    // the overflow issue was not obseved in the responder -> requester direction,
    // but it does not hurt to be careful
    // considering the "danger zone" += 1/4 of the whole 16-bit range
    const uint64 WRAP_DANGER_OUT = 0x4000;
    const uint64 WRAP_DANGER_IN  = 0xC000;
    // these static variables should be defined one of each per spdm_context (or block device)
    static uint64 remaining_bits = 0;
    static uint8 in_danger = 0;
    static uint8 wrapped = 0;

    spdm_session_info_t *session_info = NULL;
    spdm_secured_message_context_t *secured_message_context = NULL;
    uint64 seqno = 0;
    uint8 seqno_size;
    int i;

    if (spdm_context->transport_decode_message != spdm_transport_mctp_decode_message) {
      printk("%s: Not supported!\n", __func__);
      return;
    }

    // get seqno within the packet
    seqno_size = spdm_mctp_get_sequence_number(0, (uint8_t*)&seqno);
    memcpy(&seqno, msg_buffer + sizeof(mctp_message_header_t) + sizeof(spdm_secured_message_a_data_header1_t), seqno_size);

    if ((seqno & 0xFFFF) == WRAP_DANGER_OUT) {
        wrapped = 0;
        in_danger = 0;
    }

    if ((seqno & 0xFFFF) >= WRAP_DANGER_IN) {
        in_danger = 1;
    }

    if ((seqno & 0xFFFF) == 0xFFFF) {
        remaining_bits += 0x10000;
        wrapped = 1;
    }

    seqno += remaining_bits;

    if (in_danger && !wrapped && ((seqno & 0xFFFF) < WRAP_DANGER_OUT)) {
        seqno += 0x10000;
    }
    if (in_danger && wrapped && ((seqno & 0xFFFF) >= WRAP_DANGER_IN)) {
        seqno -= 0x10000;
    }

    // set seqno in all active sessions
    for (i = 0; i < MAX_SPDM_SESSION_COUNT; i++) {
        if (spdm_context->session_info[i].session_id != INVALID_SESSION_ID) {
            session_info = spdm_get_session_info_via_session_id(spdm_context, spdm_context->session_info[i].session_id);
            secured_message_context = session_info->secured_message_context;
            secured_message_context->application_secret.response_data_sequence_number = seqno;
        }
    }
}
#endif /* SPDM_ENABLED */

static inline void virtblk_request_done(struct request *req)
{
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
#if SPDM_ENABLED
	struct virtio_blk *vblk = req->rq_disk->private_data;
#endif

	switch (req_op(req)) {
	case REQ_OP_SCSI_IN:
	case REQ_OP_SCSI_OUT:
		virtblk_scsi_request_done(req);
		break;
	}

	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM virtblk_request_done: req_op(req): %X %X, len: %u, islast: %lu, %llx %px", req_op(req), vbr->out_hdr.type, vbr->sg->length, sg_is_last(vbr->sg), sg_phys(vbr->sg), sg_virt(vbr->sg));

#if SPDM_ENABLED
	if (req->spdm_original_req) {
		if (req_op(req) == REQ_OP_SPDM || req_op(req) == REQ_OP_SPDM_APP) {
			// original request was a read operation
			unsigned long int index_original, index_copy, copy_len;
			unsigned long long int sector_diff_bytes;
			unsigned char *temp_buffer;
			uintn temp_buffer_size;
			uint32 *session_id;
			boolean is_app_message;
			return_status status;
			uint32_t size;

			struct virtblk_req *vbr2 = blk_mq_rq_to_pdu(req->spdm_original_req);
			struct scatterlist *original_sct = vbr2->sg;
			struct scatterlist *this_sct = vbr->sg;
			index_original = 0;
			index_copy = 0;
			BLK_SPDM_PRINT(KERN_NOTICE "Original request ptr: %px", req->spdm_original_req);
			BLK_SPDM_PRINT (KERN_NOTICE "req_op(req) == REQ_OP_SPDM, blk_rq_pos(req) %lu, blk_rq_pos(req->spdm_original_req) %lu", blk_rq_pos(req), blk_rq_pos(req->spdm_original_req));
			BLK_SPDM_PRINT (KERN_NOTICE "req_op(req) == REQ_OP_SPDM, original_sct->length %u (%lu), vbr->sg->length %u (%lu)", original_sct->length, sg_is_last(original_sct), vbr->sg->length, sg_is_last(vbr->sg));

			// checking if data is encrypted
			if (vblk->spdm_context) {
				temp_buffer = kmalloc(MAX_SPDM_MESSAGE_BUFFER_SIZE, GFP_ATOMIC /*GFP_KERNEL*/); //cant sleep here
				if (temp_buffer == NULL) {
					printk(KERN_ALERT "no mem to allocate decode buffer");
					blk_mq_end_request(req, BLK_STS_IOERR);
					return;
				}
				do {

					size = *((uint32*)sg_virt(this_sct));
					BLK_SPDM_PRINT(KERN_NOTICE "encoded size = %u", size);
					memmove(sg_virt(this_sct), ((uint32*)sg_virt(this_sct)) + 1, size);

					temp_buffer_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

					spdm_fix_internal_seqno(vblk->spdm_context, sg_virt(this_sct));
					status = ((spdm_context_t *)vblk->spdm_context)->transport_decode_message( vblk->spdm_context, &session_id, &is_app_message,
																		FALSE, size, sg_virt(this_sct), &temp_buffer_size, temp_buffer);
					if (RETURN_ERROR(status)) {
						printk(KERN_ALERT "%s: transport_decode_message error status - %llx\n", __func__, status);
					} else {
						this_sct->length = temp_buffer_size - sizeof(mctp_message_header_t);
						memcpy(sg_virt(this_sct), temp_buffer + sizeof(mctp_message_header_t), this_sct->length);
					}

					this_sct = sg_next(this_sct);
				} while (this_sct != NULL);
				kfree(temp_buffer);
				this_sct = vbr->sg;
			} else {
				printk(KERN_ALERT "%s: spdm_context == NULL", __func__);
			}

			// seek original request copy point
			sector_diff_bytes = (blk_rq_pos(req) - blk_rq_pos(req->spdm_original_req))*SECTOR_SIZE;
			do {
				if (sector_diff_bytes - index_original > original_sct->length) {
					index_original += original_sct->length;
					original_sct = sg_next(original_sct);
				} else {
					index_original = sector_diff_bytes - index_original;
					break;
				}
			} while (original_sct != NULL);

			// copy remaining data
			while (original_sct != NULL && this_sct != NULL) {
				copy_len = MIN(original_sct->length - index_original, (this_sct->length) - index_copy);
				memcpy(((unsigned char*)sg_virt(original_sct)) + index_original, ((unsigned char*)sg_virt(this_sct)) + index_copy, copy_len);
				index_copy += copy_len;
				index_original += copy_len;
				if (index_copy == (this_sct->length)) {
					this_sct = sg_next(this_sct);
					index_copy = 0;
				}
				if (index_original == original_sct->length) {
					original_sct = sg_next(original_sct);
					index_original = 0;
				}
			}
		}

		((struct request *)req->spdm_original_req)->active_splits--;
		if (!((struct request *)req->spdm_original_req)->active_splits) {
			BLK_SPDM_PRINT(KERN_NOTICE "Ending original request     %lu %u %u %px", blk_rq_pos(req), blk_rq_bytes(req), ((struct request *)req->spdm_original_req)->active_splits, req->spdm_original_req);
			blk_mq_end_request(req->spdm_original_req, virtblk_result(vbr));
		} else {
			BLK_SPDM_PRINT(KERN_NOTICE "Do not end original request %lu %u %u %px", blk_rq_pos(req), blk_rq_bytes(req), ((struct request *)req->spdm_original_req)->active_splits, req->spdm_original_req);
		}

	}
#endif /* SPDM_ENABLED */
	blk_mq_end_request(req, virtblk_result(vbr));
}

static void virtblk_done(struct virtqueue *vq)
{
	struct virtio_blk *vblk = vq->vdev->priv;
	bool req_done = false;
	int qid = vq->index;
	struct virtblk_req *vbr;
	unsigned long flags;
	unsigned int len;

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((vbr = virtqueue_get_buf(vblk->vqs[qid].vq, &len)) != NULL) {
			struct request *req = blk_mq_rq_from_pdu(vbr);

			blk_mq_complete_request(req);
			req_done = true;
		}
		if (unlikely(virtqueue_is_broken(vq)))
			break;
	} while (!virtqueue_enable_cb(vq));

	/* In case queue is stopped waiting for more buffers. */
	if (req_done)
		blk_mq_start_stopped_hw_queues(vblk->disk->queue, true);
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
}

static blk_status_t virtio_queue_rq(struct blk_mq_hw_ctx *hctx,
			   const struct blk_mq_queue_data *bd)
{
	struct virtio_blk *vblk = hctx->queue->queuedata;
	struct request *req = bd->rq;
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
	unsigned long flags;
	unsigned int num;
	int qid = hctx->queue_num;
	int err;
	bool notify = false;
	u32 type;

#if SPDM_ENABLED
	struct scatterlist *temp_sct;
	char * copied_data;
	size_t copied_size;
	blk_status_t blk_status;
#endif /* SPDM_ENABLED */

	BUG_ON(req->nr_phys_segments + 2 > vblk->sg_elems);

	switch (req_op(req)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		type = 0;
		break;
	case REQ_OP_FLUSH:
		type = VIRTIO_BLK_T_FLUSH;
		break;
	case REQ_OP_SCSI_IN:
	case REQ_OP_SCSI_OUT:
		type = VIRTIO_BLK_T_SCSI_CMD;
		break;
	case REQ_OP_SPDM | REQ_OP_WRITE:
	case REQ_OP_SPDM:
		type = VIRTIO_BLK_T_SPDM;
		break;
	case REQ_OP_SPDM_APP | REQ_OP_WRITE:
	case REQ_OP_SPDM_APP:
		type = VIRTIO_BLK_T_SPDM_APP;
		break;
	case REQ_OP_DRV_IN:
		type = VIRTIO_BLK_T_GET_ID;
		break;
	default:
		WARN_ON_ONCE(1);
		return BLK_STS_IOERR;
	}

	vbr->out_hdr.type = cpu_to_virtio32(vblk->vdev, type);
	vbr->out_hdr.sector = (type!=0 && type!=VIRTIO_BLK_T_SPDM && type!=VIRTIO_BLK_T_SPDM_APP) ?
		0 : cpu_to_virtio64(vblk->vdev, blk_rq_pos(req));
	vbr->out_hdr.ioprio = cpu_to_virtio32(vblk->vdev, req_get_ioprio(req));

	if (type != VIRTIO_BLK_T_SPDM && type != VIRTIO_BLK_T_SPDM_APP)
		req->spdm_original_req = NULL;

	blk_mq_start_request(req);

	num = blk_rq_map_sg(hctx->queue, req, vbr->sg); // num is used as a boolean argument in virtblk_add_req, but may be larger than 1
	BLK_SPDM_PRINT (KERN_NOTICE "NUM: %d, sg_is_last %lu, type %u, sector %llu (%lu), blk_rq_bytes %u, req %px", num, sg_is_last(vbr->sg), type, vbr->out_hdr.sector, (req->__sector), blk_rq_bytes(req), req);

	if (num) {
		if (rq_data_dir(req) == WRITE)
			vbr->out_hdr.type |= cpu_to_virtio32(vblk->vdev, VIRTIO_BLK_T_OUT);
		else
			vbr->out_hdr.type |= cpu_to_virtio32(vblk->vdev, VIRTIO_BLK_T_IN);
	}

#if SPDM_ENABLED
	// magic number. Assuming extra spdm headers take up to 512 bytes. Resulting payload have to be multiple of 512
	#define MAX_SPDM_PLAIN_TEXT_SIZE (MAX_SPDM_MESSAGE_BUFFER_SIZE - 512 + sizeof(mctp_message_header_t))
	// re-encapsulate write requests
	if (vblk->spdm_context && num && req_op(req) == REQ_OP_WRITE) {
		// printk(KERN_ALERT "Write req: %px", req);
		if (vblk->spdm_context) {
			size_t temp_sct_copied_size;
			char * cipher_data;
			uintn cipher_size;
			size_t to_copy_size;
			size_t block_count;
			return_status status;
			bool stop = 0;

			temp_sct = vbr->sg;
			temp_sct_copied_size = 0;
			block_count = 0;
			cipher_data = (char*) kmalloc(MAX_SPDM_MESSAGE_BUFFER_SIZE, GFP_KERNEL);
			if (cipher_data == NULL) {
				printk(KERN_ERR "%s out of mem", __func__);
				return BLK_STS_IOERR;
			}
			copied_data = (char*) kmalloc(MAX_SPDM_MESSAGE_BUFFER_SIZE, GFP_KERNEL);
			if (copied_data == NULL) {
				printk(KERN_ERR "%s out of mem", __func__);
				kfree(cipher_data);
				return BLK_STS_IOERR;
			}

			req->active_splits = 1;
			cipher_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;
			copied_size = sizeof(mctp_message_header_t);
			((mctp_message_header_t*)copied_data)->message_type = MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI;

			do {
				do {
					if (temp_sct != NULL) {
						to_copy_size = min(temp_sct->length - temp_sct_copied_size, MAX_SPDM_PLAIN_TEXT_SIZE - copied_size); // minimum between whats left on the scatterlist and how much the buffer can still acommodate
						BLK_SPDM_PRINT("blk_rq_bytes(req) %u, temp_sct->length %u, to_copy_size %lu", blk_rq_bytes(req), temp_sct->length, to_copy_size);
						BLK_SPDM_PRINT("copied_size %lu, temp_sct_copied_size %lu (before)", copied_size, temp_sct_copied_size);
						memcpy(copied_data + copied_size, sg_virt(temp_sct) + temp_sct_copied_size, to_copy_size);
						copied_size += to_copy_size;
						temp_sct_copied_size += to_copy_size;
					}

					BLK_SPDM_PRINT("copied_size %lu, temp_sct_copied_size %lu, isnull %u", copied_size, temp_sct_copied_size, temp_sct == NULL);
					if (copied_size == MAX_SPDM_PLAIN_TEXT_SIZE || (temp_sct == NULL && copied_size != 0)) {
						BLK_SPDM_PRINT("trying to encode and send");

						// two requests should not use spdm context at the same time, since some variables are now static
						spin_lock_irqsave(&spdm_spinlock, flags);
						status = ((spdm_context_t *)vblk->spdm_context)->transport_encode_message(vblk->spdm_context, &vblk->session_id, TRUE, TRUE, copied_size, copied_data, &cipher_size, cipher_data);
						spin_unlock_irqrestore(&spdm_spinlock, flags);

						if (RETURN_ERROR(status)) {
							printk(KERN_ALERT "transport_encode_message status - %llu\n", status);
							kfree(cipher_data);
							kfree(copied_data);
							return BLK_STS_IOERR;
						}
						if (blk_rq_pos(req) + block_count + (copied_size-sizeof(mctp_message_header_t))/SECTOR_SIZE >= blk_rq_pos(req) + blk_rq_bytes(req)/SECTOR_SIZE) {
							stop = 1;
						}
						BLK_SPDM_PRINT("%lu + %lu = %lu (blk_rq_pos(req) + block_count)", blk_rq_pos(req), block_count, blk_rq_pos(req) + block_count);
						req->active_splits++;
						blk_status = virtblk_send_arbitrary_data(vblk->disk, cipher_data, cipher_size, blk_rq_pos(req) + block_count, REQ_OP_SPDM_APP, req);
						if (blk_status != BLK_STS_OK) {
							printk(KERN_ALERT "Error on virtblk_send_arbitrary_data()");
							kfree(cipher_data);
							kfree(copied_data);
							return blk_status;

						}
						block_count += (copied_size-sizeof(mctp_message_header_t)) / SECTOR_SIZE;
						cipher_size = MAX_SPDM_MESSAGE_BUFFER_SIZE;
						copied_size = sizeof(mctp_message_header_t);
						((mctp_message_header_t*)copied_data)->message_type = MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI;
					}
					BLK_SPDM_PRINT("-----");
				} while (!stop && temp_sct != NULL && temp_sct_copied_size < temp_sct->length);

				temp_sct_copied_size = 0;

				if (!stop && temp_sct) temp_sct = sg_next(temp_sct);
			} while (!stop && (temp_sct != NULL || copied_size != 0));

			req->active_splits--;
			if (!req->active_splits) {
				blk_mq_end_request(req, virtblk_result(vbr));
			}

			kfree(cipher_data);
			kfree(copied_data);

			return BLK_STS_OK;
		} else {
			printk(KERN_ALERT "Spdm context is NULL");
			return BLK_STS_IOERR;
		}
	}

	// re-encapsulate read requests
	if (num && req_op(req) == REQ_OP_READ) {
		#define MAX_SPDM_PLAIN_TEXT_SIZE_RX (MAX_SPDM_MESSAGE_BUFFER_SIZE - 512) // magic number. Assuming extra spdm headers take up to 512 bytes
		size_t temp_sct_copied_size;
		size_t to_copy_size;
		size_t block_count;
		bool stop = 0;

		temp_sct = vbr->sg;
		temp_sct_copied_size = 0;
		block_count = 0;
		copied_size = 0;
		req->active_splits = 1;

		do {
			do {
				if (temp_sct != NULL) {
					to_copy_size = min(temp_sct->length - temp_sct_copied_size, MAX_SPDM_PLAIN_TEXT_SIZE_RX - copied_size); // minimum between whats left on the scatterlist and how much the buffer can still acommodate
					copied_size += to_copy_size;
					temp_sct_copied_size += to_copy_size;
				}

				BLK_SPDM_PRINT("copied_size %lu, temp_sct_copied_size %lu, isnull %u", copied_size, temp_sct_copied_size, temp_sct == NULL);
				if (copied_size == MAX_SPDM_PLAIN_TEXT_SIZE_RX || (temp_sct == NULL && copied_size != 0)) {
					if (blk_rq_pos(req) + block_count + copied_size/SECTOR_SIZE >= blk_rq_pos(req) + blk_rq_bytes(req)/SECTOR_SIZE) {
						stop = 1;
					}
					req->active_splits++;
					blk_status = virtblk_get_arbitrary_data(vblk->disk, NULL, &copied_size, blk_rq_pos(req) + block_count, REQ_OP_SPDM_APP, req);
					if (blk_status != BLK_STS_OK) {
						printk(KERN_ALERT "Error on virtblk_get_arbitrary_data()");
						return blk_status;
					}
					block_count += copied_size / SECTOR_SIZE;
					copied_size = 0;
				}
				BLK_SPDM_PRINT("-----");
			} while (!stop && temp_sct != NULL && temp_sct_copied_size < temp_sct->length);

			temp_sct_copied_size = 0;

			if (!stop && temp_sct) temp_sct = sg_next(temp_sct);
		} while (!stop && (temp_sct != NULL || copied_size != 0));

		req->active_splits--;

		if (!req->active_splits) {
			blk_mq_end_request(req, virtblk_result(vbr));
		} else {
		}

		return BLK_STS_OK;
	}
#endif /* SPDM_ENABLED */

	spin_lock_irqsave(&vblk->vqs[qid].lock, flags);

	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM virt_blk: queueing for disk %s type: %X  num: %d is_scsi%d\n", vblk->disk->disk_name, vbr->out_hdr.type, num, blk_rq_is_scsi(req));

	if (blk_rq_is_scsi(req)) {
		err = virtblk_add_req_scsi(vblk->vqs[qid].vq, vbr, vbr->sg, num);
	}
	else {
		err = virtblk_add_req(vblk->vqs[qid].vq, vbr, vbr->sg, num);
	}
	if (err) {
		virtqueue_kick(vblk->vqs[qid].vq);
		blk_mq_stop_hw_queue(hctx);
		spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
		/* Out of mem doesn't actually happen, since we fall back
		 * to direct descriptors */
		if (err == -ENOMEM || err == -ENOSPC)
			return BLK_STS_DEV_RESOURCE;
		return BLK_STS_IOERR;
	}

	if (bd->last && virtqueue_kick_prepare(vblk->vqs[qid].vq))
		notify = true;
	spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);

	if (notify)
		virtqueue_notify(vblk->vqs[qid].vq);

	return BLK_STS_OK;
}

/* return id (s/n) string for *disk to *id_str
 */
static int virtblk_get_id(struct gendisk *disk, char *id_str)
{
	struct virtio_blk *vblk = disk->private_data;
	struct request_queue *q = vblk->disk->queue;
	struct request *req;
	int err;

	req = blk_get_request(q, REQ_OP_DRV_IN, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	err = blk_rq_map_kern(q, req, id_str, VIRTIO_BLK_ID_BYTES, GFP_KERNEL);
	if (err)
		goto out;

	blk_execute_rq(vblk->disk->queue, vblk->disk, req, false);
	err = blk_status_to_errno(virtblk_result(blk_mq_rq_to_pdu(req)));
out:
	blk_put_request(req);
	return err;
}


#if SPDM_ENABLED
// inspired by blk_end_sync_rq
static void my_blk_end_rq(struct request *rq, blk_status_t error)
{
	if (rq->end_io_data) kfree(rq->end_io_data);
	blk_put_request(rq);
}

static int virtblk_send_arbitrary_data(struct gendisk *disk, char *some_data, size_t size, sector_t pos, unsigned int op, struct request* main_req)
{
	struct virtio_blk *vblk = disk->private_data;
	struct request_queue *q = vblk->disk->queue;
	struct request *req;
	int err;

	req = blk_get_request(q, op | REQ_OP_WRITE, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (vblk->disk->queue->mq_ops && main_req) {
		char *new_buffer;
		new_buffer = kmalloc(size, GFP_KERNEL);
		if (!new_buffer) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(new_buffer, some_data, size);
		err = blk_rq_map_kern(q, req, new_buffer, size, GFP_KERNEL);
		if (err) {
			kfree(new_buffer);
			goto out;
		}

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// some flags to make sure no one will mess with the request
		req->rq_flags |= (RQF_SOFTBARRIER | RQF_STARTED);

		// re-encapsulated messages should be added to the queue, but not executed, to avoid recursion issues
		req->rq_disk = vblk->disk;
		req->end_io = my_blk_end_rq;
		req->end_io_data = new_buffer;
		// it is better to enqueue at head, otherwise stackoverflows were noticed
		blk_mq_sched_insert_request(req, true /*at_head*/, false, false);
		return BLK_STS_OK;
	} else {
		err = blk_rq_map_kern(q, req, some_data, size, GFP_KERNEL);
		if (err)
			goto out;

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// 'pure' SPDM messages can be executed righ away
		blk_execute_rq(vblk->disk->queue, vblk->disk, req, true);
	}

	err = blk_status_to_errno(virtblk_result(blk_mq_rq_to_pdu(req)));
out:
	blk_put_request(req);
	return err;
}

static int virtblk_get_arbitrary_data(struct gendisk *disk, char *buf, size_t *size, sector_t pos, unsigned int op, struct request* main_req)
{
	struct virtio_blk *vblk = disk->private_data;
	struct request_queue *q = vblk->disk->queue;
	struct request *req;
	size_t temp_size;
	int err;

	req = blk_get_request(q, op, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (vblk->disk->queue->mq_ops && main_req) {
		char *new_buffer;
		new_buffer = kmalloc(*size + 512, GFP_KERNEL);
		if (!new_buffer) {
			err = -ENOMEM;
			goto out;
		}
		err = blk_rq_map_kern(q, req, new_buffer, *size, GFP_KERNEL);
		if (err) {
			kfree(new_buffer);
			goto out;
		}

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// some flags to make sure no one will mess with the request
		req->rq_flags |= (RQF_SOFTBARRIER | RQF_STARTED);

		// re-encapsulated messages should be added to the queue, but not executed, to avoid recursion issues
		req->rq_disk = vblk->disk;
		req->end_io = my_blk_end_rq;
		req->end_io_data = new_buffer;

		blk_mq_sched_insert_request(req, true /*at_head*/, false /*true*/, false);
		return BLK_STS_OK;
	} else {
		err = blk_rq_map_kern(q, req, buf, *size, GFP_KERNEL);
		if (err)
			goto out;

		req->__sector = pos;
		req->spdm_original_req = main_req;
		// 'pure' SPDM messages can be executed righ away
		blk_execute_rq(vblk->disk->queue, vblk->disk, req, true);
	}

	if (!main_req) {
		temp_size = * ((u32*) (buf+1));
		if (temp_size  > *size) {
			err = -1;
			*size = 0;
			goto out;
		}
		*size = temp_size;
		BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM, changed size to %lu", *size);
		memmove (buf, buf + 5, *size); // magic number: assuming 1-byte message type and 4-byte message size
	}

#if BLK_SPDM_DEBUG
	{
	int i;
	printk (KERN_NOTICE "HPSPDM, virtblk_get_arbitrary_data got: ");
	for (i=0; i < ((*size < 64) ? *size : 64); i++) { printk (KERN_CONT " %02X", ((unsigned char*)buf)[i]); }
	printk (KERN_CONT "\n");
	}
#endif

	err = blk_status_to_errno(virtblk_result(blk_mq_rq_to_pdu(req)));
out:
	blk_put_request(req);
	return err;
}

static struct gendisk *global_spdm_disk = NULL;
// read_responder_public_certificate_chain
static uintn responder_public_certificate_chain_size = 519;
static uint8 responder_public_certificate_chain_data[] = { 0x07, 0x02, 0x00, 0x00, 0x5A, 0x64, 0xB3, 0x8B, 0x5D, 0x5F, 0x4D, 0xB3, 0x5F, 0xB2, 0xAA, 0x1D, 0x46, 0x9F, 0x6A, 0xDC, 0xCA, 0x7F, 0xAC, 0x85, 0xBE, 0xF0, 0x84, 0x10, 0x9C, 0xCD, 0x54, 0x09, 0xF0, 0xAB, 0x38, 0x3A, 0xAA, 0xF7, 0xA6, 0x2E, 0x3B, 0xD7, 0x81, 0x2C, 0xEA, 0x24, 0x7E, 0x14, 0xA9, 0x56, 0x9D, 0x28, 0x30, 0x82, 0x01, 0xCF, 0x30, 0x82, 0x01, 0x56, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x20, 0x3A, 0xC2, 0x59, 0xCC, 0xDA, 0xCB, 0xF6, 0x72, 0xF1, 0xC0, 0x1A, 0x62, 0x1A, 0x45, 0x82, 0x90, 0x24, 0xB8, 0xAF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x32, 0x30, 0x39, 0x30, 0x30, 0x35, 0x30, 0x35, 0x38, 0x5A, 0x17, 0x0D, 0x33, 0x31, 0x30, 0x32, 0x30, 0x37, 0x30, 0x30, 0x35, 0x30, 0x35, 0x38, 0x5A, 0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x43, 0x41, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x99, 0x8F, 0x81, 0x68, 0x9A, 0x83, 0x9B, 0x83, 0x39, 0xAD, 0x0E, 0x32, 0x8D, 0xB9, 0x42, 0x0D, 0xAE, 0xCC, 0x91, 0xA9, 0xBC, 0x4A, 0xE1, 0xBB, 0x79, 0x4C, 0x22, 0xFA, 0x3F, 0x0C, 0x9D, 0x93, 0x3C, 0x1A, 0x02, 0x5C, 0xC2, 0x73, 0x05, 0xEC, 0x43, 0x5D, 0x04, 0x02, 0xB1, 0x68, 0xB3, 0xF4, 0xD8, 0xDE, 0x0C, 0x8D, 0x53, 0xB7, 0x04, 0x8E, 0xA1, 0x43, 0x9A, 0xEB, 0x31, 0x0D, 0xAA, 0xCE, 0x89, 0x2D, 0xBA, 0x73, 0xDA, 0x4F, 0x1E, 0x39, 0x5D, 0x92, 0x11, 0x21, 0x38, 0xB4, 0x00, 0xD4, 0xF5, 0x55, 0x8C, 0xE8, 0x71, 0x30, 0x3D, 0x46, 0x83, 0xF4, 0xC4, 0x52, 0x50, 0xDA, 0x12, 0x5B, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xCF, 0x09, 0xD4, 0x7A, 0xEE, 0x08, 0x90, 0x62, 0xBF, 0xE6, 0x9C, 0xB4, 0xB9, 0xDF, 0xE1, 0x41, 0x33, 0x1C, 0x03, 0xA5, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xCF, 0x09, 0xD4, 0x7A, 0xEE, 0x08, 0x90, 0x62, 0xBF, 0xE6, 0x9C, 0xB4, 0xB9, 0xDF, 0xE1, 0x41, 0x33, 0x1C, 0x03, 0xA5, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x03, 0x67, 0x00, 0x30, 0x64, 0x02, 0x30, 0x5A, 0xB4, 0xF5, 0x95, 0x25, 0x82, 0xF6, 0x68, 0x3E, 0x49, 0xC7, 0xB4, 0xBB, 0x42, 0x81, 0x91, 0x7E, 0x38, 0xD0, 0x2D, 0xAC, 0x53, 0xAE, 0x8E, 0xB0, 0x51, 0x50, 0xAA, 0xF8, 0x7E, 0xFF, 0xC0, 0x30, 0xAB, 0xD5, 0x08, 0x5B, 0x06, 0xF7, 0xE1, 0xBF, 0x39, 0xD2, 0x3E, 0xAE, 0xBF, 0x8E, 0x48, 0x02, 0x30, 0x09, 0x75, 0xA8, 0xC0, 0x6F, 0x4F, 0x3C, 0xAD, 0x5D, 0x4E, 0x4F, 0xF8, 0x2C, 0x3B, 0x39, 0x46, 0xA0, 0xDF, 0x83, 0x8E, 0xB5, 0xD3, 0x61, 0x61, 0x59, 0xBC, 0x39, 0xD7, 0xAD, 0x68, 0x5E, 0x0D, 0x4F, 0x3F, 0xE2, 0xCA, 0xC1, 0x74, 0x8F, 0x47, 0x37, 0x11, 0xC8, 0x22, 0x59, 0x6F, 0x64, 0x52 };
static uintn responder_public_certificate_chain_hash_size = 48;
static uint8 responder_public_certificate_chain_hash[] = { 0x5A, 0x64, 0xB3, 0x8B, 0x5D, 0x5F, 0x4D, 0xB3, 0x5F, 0xB2, 0xAA, 0x1D, 0x46, 0x9F, 0x6A, 0xDC, 0xCA, 0x7F, 0xAC, 0x85, 0xBE, 0xF0, 0x84, 0x10, 0x9C, 0xCD, 0x54, 0x09, 0xF0, 0xAB, 0x38, 0x3A, 0xAA, 0xF7, 0xA6, 0x2E, 0x3B, 0xD7, 0x81, 0x2C, 0xEA, 0x24, 0x7E, 0x14, 0xA9, 0x56, 0x9D, 0x28 };
// read_requester_public_certificate_chain
static uintn requester_public_certificate_chain_size = 3684;
static uint8 requester_public_certificate_chain_data[] = { 0x64, 0x0E, 0x00, 0x00, 0xFA, 0x96, 0xED, 0xD0, 0x70, 0xD1, 0xD3, 0xC9, 0xC9, 0xC5, 0xF6, 0xD9, 0x49, 0x06, 0x8D, 0x2F, 0xC1, 0xB1, 0x99, 0xF8, 0xBE, 0xA6, 0x13, 0x36, 0x03, 0x04, 0x01, 0x54, 0x35, 0x3A, 0x79, 0xB5, 0x8F, 0xB0, 0x8E, 0x93, 0x8E, 0xCB, 0x1A, 0x1D, 0x8C, 0xEA, 0x42, 0x97, 0x0D, 0xC4, 0x3C, 0x35, 0x30, 0x82, 0x05, 0x19, 0x30, 0x82, 0x03, 0x01, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x13, 0x11, 0x90, 0x02, 0xDF, 0x80, 0xE6, 0x81, 0x20, 0x66, 0x79, 0x36, 0xF9, 0x60, 0x53, 0xAD, 0x34, 0xAC, 0x29, 0xBF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x1C, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x11, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x33, 0x36, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x31, 0x30, 0x30, 0x38, 0x30, 0x37, 0x34, 0x35, 0x33, 0x36, 0x5A, 0x30, 0x1C, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x11, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x41, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01, 0x00, 0xCC, 0x65, 0x13, 0xCE, 0x08, 0xF1, 0x49, 0x03, 0x3B, 0xDE, 0x7D, 0xDE, 0x46, 0xD3, 0x65, 0x08, 0x43, 0x2E, 0x48, 0x23, 0xE2, 0xD1, 0x01, 0x87, 0x92, 0x5D, 0xB5, 0xCF, 0xB2, 0x44, 0x5A, 0xAB, 0x69, 0xE3, 0x04, 0x59, 0x7F, 0xC2, 0xE2, 0xFC, 0xA6, 0xB9, 0xFF, 0x3F, 0xB5, 0xA0, 0x60, 0x8F, 0x5F, 0xB1, 0x3D, 0xCF, 0x98, 0x47, 0xE3, 0x7C, 0x38, 0xAB, 0x3B, 0x14, 0xD5, 0x2D, 0xD1, 0x30, 0x4A, 0x08, 0x7F, 0x67, 0x2E, 0x18, 0x5A, 0x8E, 0x4F, 0x60, 0xBA, 0x5D, 0x00, 0x8A, 0xAC, 0xDD, 0x28, 0xDE, 0xD7, 0xD9, 0xC7, 0x08, 0xED, 0x1F, 0xF9, 0x43, 0xF5, 0x6E, 0x5C, 0xD0, 0x97, 0x10, 0xC5, 0xDB, 0x33, 0x0A, 0x13, 0xB4, 0x7C, 0xD0, 0x2C, 0xF6, 0xA3, 0x83, 0xD5, 0xD2, 0x82, 0x45, 0x79, 0x6F, 0xB2, 0x1F, 0x49, 0x72, 0x56, 0x32, 0x2D, 0x30, 0x84, 0x44, 0xCC, 0x4A, 0xDE, 0xA9, 0xF8, 0xA5, 0x20, 0x59, 0xEC, 0x8E, 0x1D, 0x6E, 0xFD, 0x39, 0x71, 0xD1, 0x3D, 0xE5, 0x35, 0xD6, 0x06, 0xBC, 0x60, 0xE8, 0xCE, 0x03, 0xFC, 0x1F, 0xCF, 0x11, 0x73, 0xA6, 0xDC, 0xF8, 0xD1, 0x7D, 0x3F, 0xF4, 0x6C, 0xFD, 0x72, 0xF6, 0x64, 0x8A, 0x44, 0x88, 0xBE, 0xD6, 0x91, 0x2F, 0xFC, 0x4C, 0x18, 0xD4, 0x45, 0x2F, 0xB1, 0xF5, 0x9E, 0x6B, 0x60, 0xBD, 0xD3, 0xDC, 0xD1, 0x8F, 0x74, 0x98, 0x22, 0x33, 0x8C, 0xF5, 0x97, 0x7A, 0x48, 0x56, 0x17, 0x3C, 0x0B, 0xFA, 0x34, 0xFD, 0xE6, 0x1D, 0xB2, 0x20, 0x79, 0x88, 0x84, 0x43, 0xD0, 0xF1, 0x57, 0x69, 0xBB, 0x81, 0x9D, 0x4E, 0x3A, 0x09, 0x7A, 0x9B, 0xB2, 0xD3, 0x15, 0x03, 0xAC, 0x39, 0x76, 0x8D, 0x9C, 0xBE, 0x84, 0xF7, 0x4E, 0x29, 0xAB, 0x7E, 0x6A, 0x22, 0x15, 0xAB, 0x0F, 0xF8, 0x25, 0x7A, 0x77, 0x1D, 0x6C, 0x6E, 0x9E, 0xC4, 0xD2, 0x64, 0xEA, 0x71, 0x01, 0xFD, 0x20, 0x2D, 0x2F, 0x79, 0x54, 0x3E, 0xA9, 0x57, 0x48, 0xA5, 0x02, 0xA8, 0xFE, 0x19, 0x0D, 0x2B, 0x27, 0xE5, 0xED, 0x63, 0xE3, 0x0F, 0xD6, 0xB7, 0x93, 0x88, 0xD7, 0x08, 0xDF, 0x05, 0x9F, 0xC6, 0x0B, 0xBC, 0xC0, 0x3F, 0xB4, 0xD7, 0xDB, 0xE3, 0xFB, 0x0D, 0x71, 0x0D, 0x8C, 0x4A, 0xC5, 0x53, 0x84, 0x43, 0xAC, 0xD7, 0x34, 0xCB, 0xAC, 0xE0, 0xF2, 0xEF, 0x46, 0x84, 0xB1, 0xA1, 0x7B, 0xCA, 0x00, 0xED, 0xD1, 0x7D, 0x3D, 0xE1, 0x6C, 0xCC, 0x73, 0x78, 0x83, 0xCD, 0x07, 0xCD, 0x1F, 0x78, 0x3B, 0x8B, 0xDB, 0x76, 0x87, 0xC6, 0x8B, 0xF3, 0x37, 0x8B, 0xD9, 0xF6, 0x0C, 0xF5, 0x82, 0xB2, 0x55, 0x85, 0x0F, 0xC8, 0xDB, 0x5D, 0x6D, 0x1F, 0x19, 0xCA, 0x10, 0x78, 0x39, 0x76, 0xBD, 0x64, 0x3E, 0x42, 0x64, 0x24, 0xB7, 0x42, 0x63, 0x07, 0x35, 0xCB, 0xFD, 0x51, 0x56, 0x89, 0x38, 0x51, 0x51, 0x13, 0xEC, 0xE4, 0xF1, 0x5C, 0x6C, 0xC6, 0xC9, 0xD6, 0x0F, 0x97, 0xC5, 0xDA, 0x9D, 0x04, 0x24, 0xF0, 0x16, 0x37, 0x6F, 0xD3, 0xEF, 0x60, 0x2E, 0xAA, 0x92, 0x03, 0x41, 0x77, 0x12, 0x34, 0xCA, 0x0B, 0x18, 0x1F, 0xDB, 0xFD, 0x53, 0x48, 0x38, 0x7C, 0xA1, 0x79, 0x98, 0x46, 0x1C, 0xBA, 0x11, 0x61, 0x73, 0xF0, 0x5B, 0xB6, 0x7F, 0x7C, 0x8E, 0xE6, 0xF4, 0xFF, 0xA2, 0x78, 0xA6, 0x20, 0x51, 0x73, 0x47, 0x67, 0x4C, 0x5F, 0x04, 0x48, 0xA9, 0xB2, 0x7D, 0xD0, 0x3B, 0x50, 0xB2, 0xDD, 0xC9, 0x70, 0xFC, 0xF6, 0x64, 0x05, 0x1E, 0x5D, 0xED, 0x4A, 0xCB, 0x75, 0xF7, 0xBF, 0xF7, 0x3C, 0xAC, 0xBA, 0xDF, 0xCB, 0xEB, 0xB1, 0x23, 0x17, 0xA4, 0x41, 0x4E, 0x2A, 0xD3, 0x80, 0xD4, 0xAA, 0x3B, 0xD9, 0x9C, 0x0C, 0x0B, 0xA2, 0x8E, 0xE8, 0x56, 0x03, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x53, 0x40, 0xFE, 0xD2, 0x24, 0x96, 0x6A, 0x54, 0x04, 0x96, 0xA9, 0x57, 0x81, 0xA6, 0x49, 0x87, 0x43, 0xDA, 0x59, 0xA1, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x53, 0x40, 0xFE, 0xD2, 0x24, 0x96, 0x6A, 0x54, 0x04, 0x96, 0xA9, 0x57, 0x81, 0xA6, 0x49, 0x87, 0x43, 0xDA, 0x59, 0xA1, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x6F, 0x36, 0xE4, 0x58, 0xAA, 0xFF, 0xF1, 0xBF, 0x4C, 0x55, 0x84, 0x4B, 0x35, 0xBE, 0xFC, 0x60, 0xBF, 0xF5, 0xCC, 0xED, 0xA4, 0x64, 0x8E, 0x31, 0x68, 0x9A, 0x92, 0x03, 0x4F, 0x66, 0x4B, 0xCA, 0x4B, 0x2E, 0xFB, 0x19, 0x59, 0xE1, 0xBA, 0x12, 0xAB, 0x5C, 0xF0, 0xF2, 0xF1, 0x3B, 0x44, 0xA8, 0x66, 0xAE, 0xC3, 0x7A, 0x80, 0xA1, 0xE4, 0x31, 0xA9, 0x25, 0x87, 0x31, 0x8A, 0xEB, 0xB9, 0x72, 0x77, 0x37, 0x68, 0xF3, 0x6A, 0xF1, 0xD7, 0x5B, 0x2E, 0x71, 0x3C, 0xF0, 0x72, 0xE9, 0xDF, 0xB6, 0x12, 0xA9, 0xF2, 0x0B, 0xB4, 0xB0, 0x26, 0x04, 0x0C, 0x5D, 0x64, 0xE4, 0xB3, 0x96, 0x3D, 0xDE, 0x2E, 0x98, 0x12, 0x2E, 0x14, 0x06, 0x57, 0x12, 0x17, 0x38, 0x4F, 0x09, 0x29, 0x01, 0x56, 0xAD, 0x0B, 0xFC, 0x48, 0x18, 0x30, 0xEF, 0x70, 0x1D, 0x31, 0xDE, 0x85, 0xCA, 0xA0, 0x81, 0x43, 0x18, 0x17, 0x83, 0xEA, 0xC6, 0x2C, 0xC1, 0xFF, 0xBC, 0x8F, 0x2D, 0xE5, 0x27, 0xAC, 0xFB, 0xB5, 0x12, 0xE7, 0xBD, 0xFD, 0x5C, 0x3F, 0x8E, 0x9C, 0xED, 0xC5, 0xCD, 0x97, 0x43, 0xC9, 0x16, 0x7D, 0x3D, 0xEB, 0xD0, 0x8D, 0x08, 0xD8, 0x6A, 0x79, 0x1A, 0xCA, 0x52, 0x2B, 0xED, 0xB6, 0x5A, 0x73, 0x03, 0xFF, 0x3B, 0x26, 0x12, 0x0B, 0xF7, 0xB9, 0x72, 0x62, 0xEE, 0x4C, 0x7D, 0x2E, 0x29, 0x40, 0x52, 0xD0, 0xE5, 0x47, 0xD3, 0x33, 0x25, 0x8C, 0x32, 0xE2, 0x67, 0x85, 0xEB, 0x54, 0x43, 0xE7, 0x40, 0x2C, 0x67, 0x08, 0x4F, 0x2D, 0x14, 0xB6, 0x6C, 0x11, 0xA1, 0x6F, 0xED, 0x62, 0x67, 0x65, 0x8E, 0x43, 0xE7, 0x11, 0xA5, 0x1D, 0xAF, 0xA7, 0x16, 0xE7, 0xE7, 0xD6, 0xCB, 0xAE, 0xEA, 0x26, 0x7D, 0xA6, 0x34, 0xD7, 0x4B, 0x2A, 0x79, 0x48, 0x6C, 0xAC, 0x31, 0x3F, 0x65, 0xB6, 0x42, 0xEC, 0x65, 0xEA, 0xD6, 0x3C, 0x76, 0x61, 0xE1, 0x28, 0x26, 0x53, 0x0A, 0x0B, 0xED, 0xC9, 0xFC, 0x17, 0x20, 0xA6, 0x15, 0x93, 0xDC, 0xD3, 0x41, 0xE0, 0x0B, 0x9A, 0x3C, 0xB9, 0x51, 0x70, 0xB4, 0xD2, 0xBB, 0x61, 0xE9, 0xFD, 0x16, 0x00, 0xB4, 0xFA, 0x95, 0xB0, 0x5E, 0x4D, 0x9D, 0xC4, 0xF7, 0xDA, 0xD5, 0x70, 0x4B, 0x53, 0xAD, 0x27, 0xD7, 0x42, 0x36, 0xD3, 0xE5, 0xDB, 0xD8, 0xF3, 0x25, 0x6C, 0x31, 0x1B, 0x09, 0x2D, 0x07, 0x90, 0xB8, 0x10, 0x40, 0x30, 0x5C, 0x0D, 0xA4, 0xFF, 0xB2, 0x51, 0x86, 0xF1, 0x62, 0xEF, 0xEE, 0xE5, 0xE9, 0xF2, 0x72, 0x3D, 0x4C, 0x1A, 0xC6, 0x14, 0xBE, 0x29, 0x32, 0xB9, 0x54, 0x6D, 0xFC, 0x07, 0x22, 0x60, 0x83, 0x43, 0x88, 0xE4, 0xB3, 0x34, 0x24, 0x53, 0x8D, 0x59, 0xA6, 0x31, 0x14, 0xE3, 0x47, 0x57, 0x3E, 0xBE, 0x5A, 0xA0, 0x6B, 0x82, 0xBD, 0x3A, 0xF7, 0x08, 0x1D, 0x15, 0x45, 0xAE, 0x5B, 0xAF, 0x80, 0x0C, 0x93, 0x45, 0x80, 0xE1, 0xE9, 0xCA, 0xFD, 0xA0, 0xDF, 0x40, 0x69, 0xFC, 0xD9, 0x31, 0xFC, 0xED, 0xC2, 0x5F, 0xD2, 0x8D, 0x50, 0xF6, 0x2B, 0xCB, 0xB7, 0x4F, 0x83, 0xBA, 0xF0, 0x1F, 0x48, 0xEF, 0xF8, 0x0A, 0xDE, 0x0A, 0x80, 0x44, 0x34, 0x19, 0x00, 0xD2, 0xBB, 0xE3, 0xEB, 0x7D, 0xEF, 0x80, 0x44, 0xE2, 0x15, 0x77, 0x43, 0xAF, 0x9A, 0x7D, 0x13, 0x82, 0x06, 0x64, 0x9F, 0xCD, 0xB3, 0x61, 0xD0, 0xAF, 0x50, 0x3F, 0xAC, 0xB6, 0xE0, 0x62, 0x4D, 0xA7, 0x4B, 0xDA, 0x74, 0x6D, 0x2D, 0xB1, 0x32, 0x10, 0x07, 0x7B, 0xB9, 0x05, 0x1C, 0x76, 0x9B, 0x87, 0x9B, 0xC2, 0x25, 0x8E, 0x2F, 0x73, 0xB1, 0xF9, 0xA9, 0x32, 0xEB, 0xDC, 0x7D, 0xD6, 0xA7, 0x42, 0xA7, 0x8D, 0x0D, 0x98, 0xE0, 0x85, 0x66, 0xA2, 0xA0, 0x28, 0x09, 0x94, 0x72, 0x30, 0x82, 0x04, 0xA0, 0x30, 0x82, 0x02, 0x88, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x1C, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x11, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x30, 0x31, 0x30, 0x30, 0x38, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x30, 0x2B, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 0x01, 0x8A, 0x02, 0x82, 0x01, 0x81, 0x00, 0xCA, 0x16, 0xFF, 0x65, 0xEC, 0xCC, 0x91, 0xAB, 0xEB, 0x90, 0xC0, 0xCC, 0xC8, 0xC4, 0x7F, 0x96, 0x0E, 0x73, 0x7D, 0x55, 0x19, 0x6A, 0x72, 0x98, 0x8D, 0x0F, 0xEB, 0xB0, 0x3F, 0xAC, 0x30, 0xC4, 0x4A, 0x91, 0xFB, 0x4A, 0x8A, 0x35, 0x4B, 0x28, 0x92, 0xCB, 0x4F, 0x47, 0x18, 0x33, 0xAD, 0x14, 0x05, 0xC6, 0x86, 0x89, 0x1A, 0x06, 0x79, 0xB2, 0x77, 0xC7, 0x81, 0x3B, 0x09, 0xC3, 0x06, 0x88, 0xD9, 0xD7, 0xCC, 0xB4, 0xBD, 0x27, 0x66, 0x53, 0x6C, 0xDF, 0xE5, 0xD7, 0xAC, 0x68, 0xEC, 0x3A, 0x47, 0x2B, 0xFB, 0x32, 0x25, 0x38, 0xBD, 0xF7, 0xDF, 0xA1, 0x28, 0xCD, 0xCC, 0x04, 0xEB, 0xC2, 0xC7, 0x24, 0x9D, 0xE9, 0x86, 0x38, 0x8C, 0xC5, 0x0F, 0x26, 0xE5, 0x85, 0x4D, 0x3A, 0xBC, 0xFC, 0xE0, 0xCF, 0x5D, 0xF5, 0xDE, 0x09, 0x23, 0x99, 0xCA, 0x09, 0x8A, 0x72, 0xD9, 0x63, 0xAA, 0x75, 0xC2, 0x56, 0x53, 0x10, 0x84, 0x43, 0xBE, 0x0E, 0xC9, 0x29, 0xFD, 0x38, 0x71, 0x5D, 0x77, 0x04, 0x2E, 0x7D, 0x43, 0x5C, 0x29, 0xF7, 0xD2, 0xBE, 0x5B, 0xF2, 0xA1, 0x2A, 0x19, 0x51, 0x4D, 0x8F, 0xAE, 0x97, 0xD2, 0x17, 0x84, 0xF4, 0x64, 0x31, 0x61, 0xD7, 0x4B, 0x27, 0xA6, 0xEE, 0x93, 0xC4, 0xBC, 0x2E, 0x03, 0x68, 0xBC, 0xC8, 0x9F, 0xE3, 0x01, 0x77, 0xE5, 0xF9, 0x52, 0xB8, 0x1E, 0xBF, 0xAA, 0xD3, 0x79, 0x91, 0x13, 0x14, 0xDB, 0x23, 0x9C, 0x95, 0x47, 0x1C, 0x77, 0x84, 0x78, 0x9C, 0x63, 0xAB, 0xFD, 0x08, 0x87, 0x7A, 0x06, 0x2B, 0x06, 0xB9, 0xB5, 0xB9, 0x11, 0x42, 0x14, 0xD6, 0xBD, 0x37, 0xAF, 0x90, 0x69, 0x6F, 0x40, 0xAB, 0x45, 0xF4, 0xDD, 0x38, 0xC8, 0x2F, 0x9F, 0xE0, 0x8E, 0x5E, 0x4C, 0x49, 0x33, 0x65, 0x02, 0x34, 0x82, 0x71, 0xDC, 0xD3, 0x51, 0x07, 0x0B, 0x28, 0x39, 0x39, 0xA8, 0xAE, 0x48, 0xF2, 0x96, 0x98, 0x92, 0xB7, 0x7B, 0x79, 0x6C, 0x27, 0x4A, 0xC2, 0x68, 0xA6, 0xB5, 0x66, 0xEC, 0xEA, 0x10, 0xE9, 0xB1, 0x9A, 0xA7, 0x1C, 0xC2, 0x18, 0x24, 0xE6, 0x65, 0x9A, 0x86, 0xDD, 0x26, 0x8D, 0x0E, 0x71, 0x12, 0x24, 0x8D, 0xD7, 0x17, 0x47, 0x44, 0xF5, 0x6E, 0x0E, 0xDB, 0xBD, 0x63, 0x83, 0xA9, 0x02, 0xCD, 0xC2, 0xF6, 0x6A, 0x63, 0xD2, 0x0B, 0x74, 0x2C, 0xB8, 0x31, 0xCB, 0xD8, 0x87, 0xE6, 0x76, 0x9A, 0x60, 0x06, 0xD7, 0xB9, 0xDA, 0x26, 0x2B, 0xDF, 0x78, 0x24, 0x3B, 0x5E, 0x16, 0xE6, 0xED, 0xF7, 0x82, 0xDD, 0xB3, 0x79, 0x7F, 0xB9, 0x65, 0x03, 0xF8, 0xC9, 0x9A, 0x03, 0x0A, 0x09, 0xEB, 0x3A, 0x50, 0x62, 0x90, 0x0F, 0xE8, 0xCB, 0x31, 0x59, 0x12, 0x7D, 0x88, 0x48, 0xF4, 0x29, 0x43, 0xA3, 0x16, 0xCD, 0x5A, 0x3D, 0x91, 0x11, 0xAB, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x5E, 0x30, 0x5C, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x01, 0xFE, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x0B, 0xE2, 0x1D, 0xD7, 0xFC, 0x10, 0x86, 0xAB, 0xB6, 0xD3, 0x0E, 0xEF, 0xF7, 0xE0, 0xC4, 0x95, 0x26, 0x38, 0xC6, 0xDE, 0x30, 0x20, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x92, 0x91, 0xE1, 0x08, 0x0C, 0xFF, 0x71, 0xBD, 0x6E, 0xA3, 0xBC, 0xEA, 0x12, 0xD3, 0x0E, 0xF2, 0x05, 0xEB, 0xFA, 0x19, 0x16, 0xC9, 0x08, 0x6A, 0x2D, 0x94, 0x05, 0x2E, 0x56, 0x56, 0xE3, 0xC4, 0x27, 0xC8, 0xAB, 0x9D, 0x83, 0xD2, 0x1B, 0x85, 0x33, 0x0A, 0x02, 0x2B, 0xBF, 0x05, 0x7E, 0xE7, 0xFA, 0x53, 0xD0, 0x32, 0x4D, 0x22, 0xAE, 0x74, 0x64, 0xF4, 0x0D, 0x70, 0xA5, 0x3C, 0xD5, 0xE8, 0xEE, 0x52, 0x72, 0xB7, 0x06, 0xA5, 0x0E, 0x67, 0x1E, 0x22, 0xE0, 0xA2, 0x45, 0x73, 0x7A, 0xC0, 0xF5, 0x38, 0x1C, 0xC0, 0xBB, 0xF7, 0x44, 0x20, 0x8D, 0xE1, 0x45, 0x85, 0x02, 0x2E, 0xA8, 0x85, 0x13, 0x5C, 0x73, 0xAC, 0x45, 0x72, 0x74, 0xB8, 0xA5, 0x0E, 0x7B, 0xD3, 0x8E, 0x91, 0x76, 0x69, 0x69, 0x89, 0xF4, 0xDF, 0x24, 0xB8, 0x11, 0x64, 0x19, 0x26, 0xE6, 0x84, 0x95, 0x8A, 0xE1, 0x39, 0x1D, 0xA4, 0x2A, 0x1C, 0x0B, 0x93, 0x94, 0x52, 0xDB, 0xA7, 0xDA, 0xAB, 0x84, 0x52, 0x8D, 0x53, 0x8B, 0x80, 0x0B, 0x26, 0xA5, 0x88, 0x9D, 0x94, 0xA0, 0x2A, 0x2D, 0x7B, 0xB0, 0x05, 0x80, 0x96, 0x69, 0x25, 0xCE, 0x6B, 0xF6, 0x94, 0xF6, 0xDD, 0xFE, 0xC9, 0xAF, 0x0B, 0x7C, 0xF1, 0xF1, 0x9B, 0x3A, 0xD0, 0x48, 0x16, 0x59, 0x7D, 0xC0, 0x1A, 0xCB, 0xC8, 0xF0, 0xB6, 0x17, 0x5D, 0x10, 0x07, 0x16, 0x3E, 0x4D, 0x36, 0x4E, 0x2A, 0x92, 0xE6, 0x00, 0xFE, 0x9A, 0xBB, 0x6D, 0x7B, 0xCE, 0x7F, 0x64, 0x61, 0x0C, 0x89, 0x1D, 0xA4, 0x24, 0xCC, 0x8A, 0xBE, 0xF6, 0xB4, 0x28, 0xEE, 0x8C, 0x1F, 0xF2, 0x7D, 0xA1, 0x71, 0x3C, 0xD8, 0xA3, 0x98, 0xBA, 0x4F, 0x34, 0x06, 0x22, 0x95, 0xE0, 0xE3, 0x51, 0xDE, 0xFF, 0xA6, 0x0F, 0x33, 0xCA, 0xB4, 0x39, 0x99, 0xA3, 0x99, 0x8B, 0xA8, 0xF5, 0x81, 0xA8, 0x2C, 0xEF, 0x26, 0xE9, 0xE2, 0x4B, 0x9A, 0xD9, 0x89, 0xC4, 0xBF, 0x8D, 0xD1, 0x10, 0x72, 0x40, 0x26, 0xB4, 0x46, 0x49, 0x10, 0xFF, 0x00, 0x56, 0xA1, 0x0A, 0xCC, 0xD1, 0x18, 0xE6, 0xC8, 0x89, 0x34, 0x0B, 0x9E, 0x25, 0x06, 0x2A, 0x35, 0x56, 0x7D, 0x14, 0xB4, 0xF4, 0x8B, 0x66, 0x92, 0xC6, 0xCA, 0xE9, 0xB6, 0x17, 0x17, 0xCD, 0x4C, 0x23, 0x7C, 0x04, 0xBD, 0x1B, 0xF3, 0x4F, 0x7B, 0xC3, 0xCA, 0xB6, 0x9A, 0x60, 0xF7, 0xED, 0xD1, 0xD7, 0x74, 0x02, 0xE8, 0x9D, 0xD1, 0x29, 0x99, 0x61, 0x88, 0x67, 0xCC, 0xCD, 0x53, 0xD0, 0xDB, 0x6D, 0x4D, 0x3F, 0xC4, 0x26, 0xB8, 0x7A, 0x68, 0xAB, 0x0D, 0xCC, 0x71, 0x55, 0x18, 0x5F, 0x26, 0xC7, 0x6A, 0x0A, 0x5B, 0xDE, 0x6F, 0x13, 0x83, 0x27, 0x47, 0xFC, 0xE2, 0x2E, 0xC9, 0x64, 0x8D, 0x42, 0xD0, 0xC1, 0xB2, 0xFF, 0xC5, 0x46, 0xC0, 0xF0, 0x09, 0x62, 0x74, 0xAD, 0x56, 0x49, 0xD2, 0xF7, 0x1E, 0xC8, 0x52, 0x5B, 0x56, 0x72, 0xCE, 0x16, 0x98, 0xEE, 0xDB, 0x5E, 0xD4, 0x08, 0xEA, 0x10, 0x11, 0x7B, 0x2B, 0xC8, 0x84, 0xFE, 0xC1, 0xB2, 0x60, 0xFA, 0x6A, 0x7F, 0xFA, 0x8A, 0x59, 0xE0, 0x02, 0x5E, 0xB7, 0x23, 0xF5, 0x99, 0x99, 0xAE, 0x96, 0x7D, 0x98, 0x0A, 0x6A, 0x46, 0x0C, 0x54, 0x79, 0xD5, 0x5D, 0x14, 0x25, 0xC1, 0xD0, 0x13, 0xD3, 0x09, 0xA1, 0xDB, 0x40, 0xC0, 0x77, 0x81, 0x7C, 0x4C, 0x48, 0x66, 0x5D, 0x60, 0x1A, 0x02, 0x4E, 0x03, 0xA1, 0x7D, 0xE3, 0x31, 0xEA, 0xCC, 0xD2, 0x3D, 0xC9, 0x27, 0xE6, 0x5C, 0x63, 0xB2, 0x75, 0xD2, 0x8D, 0x57, 0xE2, 0x7F, 0x57, 0xEF, 0xF0, 0x56, 0x30, 0x5E, 0x86, 0x70, 0x0C, 0x94, 0xCB, 0x33, 0x0D, 0x06, 0xB3, 0xDB, 0x69, 0x12, 0x5F, 0x89, 0xB8, 0xD9, 0xBB, 0x0A, 0xBB, 0x30, 0x82, 0x04, 0x6B, 0x30, 0x82, 0x02, 0xD3, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x2B, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x31, 0x31, 0x30, 0x31, 0x30, 0x30, 0x37, 0x34, 0x35, 0x34, 0x30, 0x5A, 0x30, 0x28, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1D, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x72, 0x65, 0x71, 0x75, 0x73, 0x65, 0x74, 0x65, 0x72, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 0x01, 0x8A, 0x02, 0x82, 0x01, 0x81, 0x00, 0xC8, 0xC2, 0x62, 0x41, 0x2C, 0x2E, 0x53, 0x1E, 0x1C, 0x1F, 0x67, 0xBE, 0x50, 0xA8, 0x0E, 0x48, 0x67, 0x9B, 0x48, 0x29, 0xF9, 0xE3, 0x5E, 0x28, 0x54, 0x5E, 0xD1, 0x92, 0x90, 0x6A, 0xD4, 0xF2, 0xE6, 0xE4, 0xE5, 0x5F, 0x34, 0xD4, 0x14, 0xB9, 0x36, 0xC9, 0x36, 0xC3, 0x58, 0x5C, 0xAF, 0x1A, 0x83, 0x26, 0x93, 0xC3, 0x5D, 0x6F, 0xE4, 0xA0, 0xE1, 0xE4, 0xFF, 0xB5, 0x23, 0x39, 0xE6, 0xE8, 0x63, 0xB5, 0x95, 0x3C, 0xB2, 0xF2, 0x05, 0x60, 0x56, 0xA3, 0x2A, 0x0F, 0x37, 0x32, 0xD1, 0x77, 0xD6, 0x8D, 0x7F, 0x4D, 0x22, 0xA1, 0xE5, 0xFC, 0x4E, 0xF6, 0xBF, 0xE0, 0x90, 0x55, 0x06, 0x42, 0xBA, 0xB0, 0x6E, 0x23, 0xBE, 0x85, 0x74, 0xAB, 0xDF, 0xA6, 0x43, 0x5E, 0x3C, 0x32, 0x6D, 0x31, 0xD5, 0xE9, 0xE2, 0x9C, 0x80, 0xE9, 0xA7, 0x37, 0xCF, 0x0D, 0xD0, 0x73, 0x1B, 0xF4, 0x66, 0xA6, 0x72, 0x54, 0x44, 0xA7, 0x22, 0xAB, 0x9E, 0x3E, 0xB8, 0xB9, 0x46, 0x38, 0xB8, 0x83, 0x4A, 0x48, 0x23, 0x7C, 0x60, 0x20, 0x91, 0x7E, 0x1D, 0x36, 0x9E, 0x46, 0x71, 0xFE, 0xFC, 0x51, 0xBA, 0x7F, 0x58, 0xEB, 0xCB, 0xC0, 0x52, 0xF8, 0x0F, 0xD8, 0x97, 0x54, 0x38, 0xDB, 0x5C, 0x93, 0x4F, 0xF8, 0x22, 0xCB, 0x2D, 0x11, 0x2B, 0xE8, 0x54, 0x1A, 0x88, 0xD2, 0x9E, 0xEC, 0x71, 0x2A, 0x3D, 0x9A, 0x14, 0x39, 0x7D, 0x3C, 0x2B, 0x4F, 0x49, 0x4E, 0xDC, 0x41, 0xA5, 0xDB, 0x01, 0x0C, 0x1F, 0x70, 0xA0, 0xAE, 0x8B, 0x5A, 0x11, 0x9A, 0xE4, 0xE4, 0xD9, 0x9D, 0x86, 0x28, 0x05, 0x43, 0x23, 0xA4, 0xD6, 0x3A, 0xA4, 0xE7, 0x78, 0x2C, 0x9F, 0x80, 0x8A, 0xF7, 0xC4, 0x34, 0xD5, 0x57, 0xEE, 0x6A, 0xFA, 0x2D, 0x40, 0xCE, 0xEC, 0xA9, 0xFF, 0x58, 0xCD, 0x01, 0xE2, 0x04, 0x50, 0x1D, 0xE6, 0xB6, 0x3F, 0x9E, 0x34, 0xD2, 0x66, 0x57, 0xBB, 0x8A, 0x55, 0x86, 0x29, 0x47, 0x44, 0x3F, 0x21, 0xC3, 0x04, 0x28, 0xBF, 0x9C, 0x62, 0x7A, 0xF0, 0x6C, 0x90, 0x8C, 0xF9, 0x97, 0x70, 0x41, 0x6C, 0xB1, 0xDE, 0x5E, 0x04, 0xED, 0xD6, 0x3B, 0x06, 0xC3, 0x0F, 0x41, 0xD9, 0x79, 0xDE, 0x11, 0xFB, 0x25, 0xFA, 0xDE, 0xCA, 0x64, 0xC8, 0x4D, 0xB9, 0xB0, 0xAD, 0x38, 0x97, 0x0A, 0x64, 0xC9, 0xF5, 0x74, 0xF2, 0xD1, 0xBE, 0xCC, 0x5C, 0x0B, 0x6F, 0xA8, 0x9D, 0x44, 0x30, 0x67, 0x84, 0x23, 0x79, 0xB5, 0xC1, 0xCD, 0x56, 0xB9, 0x54, 0x57, 0x0E, 0x84, 0xC2, 0x11, 0xFA, 0x13, 0x79, 0x2C, 0x3A, 0x2F, 0xAD, 0xDA, 0x86, 0xAA, 0x82, 0xD0, 0x99, 0x00, 0xFF, 0x07, 0x11, 0x20, 0x86, 0x16, 0x2D, 0x58, 0xA2, 0xDB, 0x86, 0xCF, 0xDB, 0x50, 0x18, 0x62, 0x82, 0x72, 0xA2, 0xF1, 0xD3, 0x46, 0x3A, 0x3B, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x81, 0x9C, 0x30, 0x81, 0x99, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05, 0xE0, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x86, 0x5A, 0xD2, 0xBB, 0x45, 0xF7, 0x2A, 0x0F, 0xD6, 0x20, 0x29, 0x89, 0x7E, 0x82, 0xAF, 0x29, 0x6B, 0xF6, 0x42, 0xCB, 0x30, 0x31, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x2A, 0x30, 0x28, 0xA0, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x30, 0x2A, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x20, 0x30, 0x1E, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x81, 0x00, 0x35, 0x6B, 0x78, 0xE5, 0xE2, 0xC8, 0xAC, 0x49, 0x71, 0x24, 0xCB, 0x43, 0x5A, 0x47, 0x40, 0x01, 0xEC, 0x69, 0xEE, 0xBA, 0xBB, 0x58, 0x17, 0x95, 0x3A, 0x38, 0x61, 0x01, 0xB2, 0xB3, 0x83, 0xE5, 0xBD, 0xE5, 0xED, 0xA0, 0xD0, 0xAF, 0x62, 0x6A, 0x3C, 0xE4, 0x6E, 0xF1, 0x3A, 0x7E, 0xCD, 0x94, 0x32, 0x39, 0xBC, 0x51, 0x23, 0xE1, 0x3B, 0xC2, 0xA8, 0xA6, 0x08, 0xA8, 0xD0, 0xD5, 0x58, 0xFC, 0x4C, 0x0A, 0xE7, 0xAE, 0x5C, 0x98, 0x45, 0xC7, 0xDB, 0x11, 0x4E, 0x59, 0x5A, 0xBF, 0x13, 0x2A, 0xF9, 0x57, 0x91, 0xE6, 0x9A, 0xBD, 0x82, 0x48, 0x95, 0x1A, 0xE3, 0x87, 0x1E, 0x66, 0x55, 0xC9, 0x0F, 0x41, 0x07, 0x82, 0xB5, 0xF8, 0xBB, 0xBD, 0xEA, 0x38, 0x9B, 0x42, 0x34, 0x5E, 0xBC, 0x72, 0x91, 0x61, 0x76, 0x7B, 0x1A, 0xB2, 0xCB, 0x04, 0x70, 0x0D, 0x35, 0xC2, 0xAC, 0xE9, 0xE8, 0x65, 0x3D, 0x61, 0x9D, 0x43, 0x4A, 0x5E, 0xA6, 0x41, 0xCC, 0x67, 0x45, 0xB9, 0x2B, 0x35, 0x90, 0x21, 0x1C, 0x14, 0xA0, 0x55, 0x08, 0x11, 0x8C, 0x74, 0x3C, 0xCD, 0x7F, 0xB3, 0x20, 0x7F, 0x5C, 0x8F, 0x40, 0x5C, 0x57, 0xA7, 0xCC, 0xC5, 0x50, 0x0E, 0x8C, 0xE4, 0x39, 0xBF, 0x4F, 0xD8, 0x59, 0x8E, 0x16, 0x20, 0x2B, 0x2B, 0x3B, 0x32, 0xF0, 0x05, 0xB7, 0x1D, 0x31, 0x4A, 0xFD, 0x32, 0x31, 0x1F, 0x1F, 0x06, 0xF8, 0x91, 0x7D, 0x1F, 0x43, 0xA0, 0x74, 0x7D, 0xEC, 0x19, 0x19, 0x4A, 0x8C, 0xAA, 0x01, 0x02, 0x93, 0x7F, 0x88, 0xA1, 0x10, 0x29, 0x38, 0x66, 0x90, 0x3E, 0xD5, 0x3B, 0x69, 0x5A, 0x36, 0x98, 0x5F, 0x81, 0xC3, 0x0F, 0xB3, 0xC5, 0x25, 0xBA, 0xC4, 0x11, 0x84, 0xEE, 0xC7, 0x28, 0xD0, 0xB7, 0x74, 0x6D, 0xB7, 0x58, 0xBB, 0x87, 0x90, 0xDB, 0x6E, 0x2D, 0xFC, 0xEC, 0x23, 0xDA, 0x71, 0xA1, 0x27, 0xC0, 0xE8, 0xB0, 0x75, 0x4F, 0x5C, 0x22, 0x20, 0x3D, 0xB7, 0x3B, 0x18, 0xD7, 0x03, 0xE0, 0x12, 0xA1, 0x8E, 0x9D, 0x26, 0x91, 0x38, 0x1A, 0x1A, 0xFF, 0x52, 0xB1, 0x63, 0xD7, 0x2F, 0xFF, 0x3B, 0x96, 0x65, 0xB1, 0x05, 0xB6, 0x70, 0x5D, 0x8D, 0xFC, 0xDC, 0x19, 0x0A, 0x50, 0xCB, 0x1B, 0xA7, 0xE0, 0xF3, 0xA2, 0xEA, 0xFB, 0x28, 0x7B, 0x26, 0x66, 0x0C, 0xEC, 0x13, 0xD1, 0x54, 0x94, 0x6C, 0xD9, 0xE3, 0xCF, 0xDC, 0xCE, 0x32, 0x73, 0xD3, 0x09, 0x55, 0x61, 0x5A, 0xFA, 0x84, 0x0F, 0x55, 0x7B, 0x93, 0xB6, 0x60, 0x19, 0x0D, 0x37, 0x89, 0xC1, 0x14, 0x02, 0x81, 0xDF, 0x52, 0x42, 0xBD, 0x6D, 0xD8, 0x45, 0xAF, 0x5B, 0x38, 0xA5, 0x00, 0x5A, 0x84, 0x0C, 0xFC, 0x60, 0xF3, 0x70, 0xA6, 0x7A, 0x54, 0x44, 0xC2, 0x34, 0xAA, 0xC6, 0x76, 0x51, 0x1E, 0xD3, 0x9D, 0x83 };
#define TEST_PSK_DATA_STRING "TestPskData"
#define TEST_PSK_HINT_STRING "TestPskHint"

return_status do_authentication_via_spdm(void* spdm_context);

return_status spdm_blk_send_message(IN void *spdm_context,
				       IN uintn request_size, IN void *request,
				       IN uint64 timeout)
{
	virtblk_send_arbitrary_data(global_spdm_disk, request, request_size, 0, REQ_OP_SPDM, NULL);
	return RETURN_SUCCESS;
}

return_status spdm_blk_receive_message(IN void *spdm_context,
					  IN OUT uintn *response_size,
					  IN OUT void *response,
					  IN uint64 timeout)
{
	size_t size = *response_size;
	virtblk_get_arbitrary_data(global_spdm_disk, response, &size, 0, REQ_OP_SPDM, NULL);
	*response_size = size;
	return RETURN_SUCCESS;
}

void* virtblk_init_spdm(void) {
	void *spdm_context;
	spdm_data_parameter_t parameter;
	uint8 data8;
	uint16 data16;
	uint32 data32;
	spdm_version_number_t spdm_version;

	spdm_context = (void *)kmalloc(spdm_get_context_size(), GFP_KERNEL);
	if (spdm_context == NULL) {
		return NULL;
	}

	spdm_init_context(spdm_context);
	spdm_register_device_io_func(spdm_context, spdm_blk_send_message,
				     spdm_blk_receive_message);
	if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_MCTP) {
		spdm_register_transport_layer_func(
			spdm_context, spdm_transport_mctp_encode_message,
			spdm_transport_mctp_decode_message);
	} else if (m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
		// not supported
		return NULL;
	} else {
		return NULL;
	}

	if (m_use_version != SPDM_MESSAGE_VERSION_11) {
		zero_mem(&parameter, sizeof(parameter));
		parameter.location = SPDM_DATA_LOCATION_LOCAL;
		spdm_version.major_version = (m_use_version >> 4) & 0xF;
		spdm_version.minor_version = m_use_version & 0xF;
		spdm_version.alpha = 0;
		spdm_version.update_version_number = 0;
		spdm_set_data(spdm_context, SPDM_DATA_SPDM_VERSION, &parameter,
			      &spdm_version, sizeof(spdm_version));
	}

	if (m_use_secured_message_version != SPDM_MESSAGE_VERSION_11) {
		zero_mem(&parameter, sizeof(parameter));
		if (m_use_secured_message_version != 0) {
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			spdm_version.major_version =
				(m_use_secured_message_version >> 4) & 0xF;
			spdm_version.minor_version =
				m_use_secured_message_version & 0xF;
			spdm_version.alpha = 0;
			spdm_version.update_version_number = 0;
			spdm_set_data(spdm_context,
				      SPDM_DATA_SECURED_MESSAGE_VERSION,
				      &parameter, &spdm_version,
				      sizeof(spdm_version));
		} else {
			spdm_set_data(spdm_context,
				      SPDM_DATA_SECURED_MESSAGE_VERSION,
				      &parameter, NULL, 0);
		}
	}

	zero_mem(&parameter, sizeof(parameter));
	parameter.location = SPDM_DATA_LOCATION_LOCAL;

	data8 = 0;
	spdm_set_data(spdm_context, SPDM_DATA_CAPABILITY_CT_EXPONENT,
		      &parameter, &data8, sizeof(data8));
	data32 = m_use_requester_capability_flags;
	if (m_use_capability_flags != 0) {
		data32 = m_use_capability_flags;
	}
	spdm_set_data(spdm_context, SPDM_DATA_CAPABILITY_FLAGS, &parameter,
		      &data32, sizeof(data32));

	data8 = m_support_measurement_spec;
	spdm_set_data(spdm_context, SPDM_DATA_MEASUREMENT_SPEC, &parameter,
		      &data8, sizeof(data8));
	data32 = m_support_asym_algo;
	spdm_set_data(spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter,
		      &data32, sizeof(data32));
	data32 = m_support_hash_algo;
	spdm_set_data(spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter,
		      &data32, sizeof(data32));
	data16 = m_support_dhe_algo;
	spdm_set_data(spdm_context, SPDM_DATA_DHE_NAME_GROUP, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_aead_algo;
	spdm_set_data(spdm_context, SPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_req_asym_algo;
	spdm_set_data(spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		      &data16, sizeof(data16));
	data16 = m_support_key_schedule_algo;
	spdm_set_data(spdm_context, SPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
		      sizeof(data16));

	return spdm_context;
}


void virtblk_init_spdm_certificates(void* spdm_context) {
	uint8 index;
	return_status status;
	uintn data_size;
	spdm_data_parameter_t parameter;
	uint8 data8;
	uint16 data16;
	uint32 data32;

	zero_mem(&parameter, sizeof(parameter));
	parameter.location = SPDM_DATA_LOCATION_CONNECTION;

	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_CONNECTION_STATE, &parameter,
		      &data32, &data_size);
	ASSERT(data32 == SPDM_CONNECTION_STATE_NEGOTIATED);

	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
		      &data32, &data_size);
	m_use_measurement_hash_algo = data32;
	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_BASE_ASYM_ALGO, &parameter,
		      &data32, &data_size);
	m_use_asym_algo = data32;
	data_size = sizeof(data32);
	spdm_get_data(spdm_context, SPDM_DATA_BASE_HASH_ALGO, &parameter,
		      &data32, &data_size);
	m_use_hash_algo = data32;
	data_size = sizeof(data16);
	spdm_get_data(spdm_context, SPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
		      &data16, &data_size);
	m_use_req_asym_algo = data16;

	if ((m_use_slot_id == 0xFF) ||
	    ((m_use_requester_capability_flags &
	      SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP) != 0)) {
			zero_mem(&parameter, sizeof(parameter));
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			spdm_set_data(spdm_context,
				      SPDM_DATA_PEER_PUBLIC_CERT_CHAIN,
				      &parameter, responder_public_certificate_chain_data, responder_public_certificate_chain_size);
			// Do not free it.
	} else {
			zero_mem(&parameter, sizeof(parameter));
			parameter.location = SPDM_DATA_LOCATION_LOCAL;
			spdm_set_data(spdm_context,
				      SPDM_DATA_PEER_PUBLIC_ROOT_CERT_HASH,
				      &parameter, responder_public_certificate_chain_hash, responder_public_certificate_chain_hash_size);
			// Do not free it.
	}

		zero_mem(&parameter, sizeof(parameter));
		parameter.location = SPDM_DATA_LOCATION_LOCAL;
		data8 = m_use_slot_count;
		spdm_set_data(spdm_context, SPDM_DATA_LOCAL_SLOT_COUNT,
			      &parameter, &data8, sizeof(data8));

		for (index = 0; index < m_use_slot_count; index++) {
			parameter.additional_data[0] = index;
			spdm_set_data(spdm_context,
				      SPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
				      &parameter, requester_public_certificate_chain_data, requester_public_certificate_chain_size);
		}
		// printf("read_requester_public_certificate_chain\n");

	status = spdm_set_data(spdm_context, SPDM_DATA_PSK_HINT, NULL,
			       TEST_PSK_HINT_STRING,
			       sizeof(TEST_PSK_HINT_STRING));
	if (RETURN_ERROR(status)) {
		printk("spdm_set_data - %x\n", (uint32)status);
	}

}
#endif /* SPDM_ENABLED */

/* We provide getgeo only to please some old bootloader/partitioning tools */
static int virtblk_getgeo(struct block_device *bd, struct hd_geometry *geo)
{
	struct virtio_blk *vblk = bd->bd_disk->private_data;

	/* see if the host passed in geometry config */
	if (virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_GEOMETRY)) {
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.cylinders, &geo->cylinders);
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.heads, &geo->heads);
		virtio_cread(vblk->vdev, struct virtio_blk_config,
			     geometry.sectors, &geo->sectors);
	} else {
		/* some standard values, similar to sd */
		geo->heads = 1 << 6;
		geo->sectors = 1 << 5;
		geo->cylinders = get_capacity(bd->bd_disk) >> 11;
	}
	return 0;
}

static const struct block_device_operations virtblk_fops = {
	.ioctl  = virtblk_ioctl,
	.owner  = THIS_MODULE,
	.getgeo = virtblk_getgeo,
};

static int index_to_minor(int index)
{
	return index << PART_BITS;
}

static int minor_to_index(int minor)
{
	return minor >> PART_BITS;
}

static ssize_t virtblk_serial_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	int err;

	/* sysfs gives us a PAGE_SIZE buffer */
	BUILD_BUG_ON(PAGE_SIZE < VIRTIO_BLK_ID_BYTES);

	buf[VIRTIO_BLK_ID_BYTES] = '\0';
	err = virtblk_get_id(disk, buf);
	if (!err)
		return strlen(buf);

	if (err == -EIO) /* Unsupported? Make it empty. */
		return 0;

	return err;
}

static DEVICE_ATTR(serial, 0444, virtblk_serial_show, NULL);

/* The queue's logical block size must be set before calling this */
static void virtblk_update_capacity(struct virtio_blk *vblk, bool resize)
{
	struct virtio_device *vdev = vblk->vdev;
	struct request_queue *q = vblk->disk->queue;
	char cap_str_2[10], cap_str_10[10];
	unsigned long long nblocks;
	u64 capacity;

	/* Host must always specify the capacity. */
	virtio_cread(vdev, struct virtio_blk_config, capacity, &capacity);

	/* If capacity is too big, truncate with warning. */
	if ((sector_t)capacity != capacity) {
		dev_warn(&vdev->dev, "Capacity %llu too large: truncating\n",
			 (unsigned long long)capacity);
		capacity = (sector_t)-1;
	}

	nblocks = DIV_ROUND_UP_ULL(capacity, queue_logical_block_size(q) >> 9);

	string_get_size(nblocks, queue_logical_block_size(q),
			STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
	string_get_size(nblocks, queue_logical_block_size(q),
			STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));

	dev_notice(&vdev->dev,
		   "[%s] %s%llu %d-byte logical blocks (%s/%s)\n",
		   vblk->disk->disk_name,
		   resize ? "new size: " : "",
		   nblocks,
		   queue_logical_block_size(q),
		   cap_str_10,
		   cap_str_2);

	set_capacity(vblk->disk, capacity);
}

static void virtblk_config_changed_work(struct work_struct *work)
{
	struct virtio_blk *vblk =
		container_of(work, struct virtio_blk, config_work);
	char *envp[] = { "RESIZE=1", NULL };

	virtblk_update_capacity(vblk, true);
	revalidate_disk(vblk->disk);
	kobject_uevent_env(&disk_to_dev(vblk->disk)->kobj, KOBJ_CHANGE, envp);
}

static void virtblk_config_changed(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	queue_work(virtblk_wq, &vblk->config_work);
}

static int init_vq(struct virtio_blk *vblk)
{
	int err;
	int i;
	vq_callback_t **callbacks;
	const char **names;
	struct virtqueue **vqs;
	unsigned short num_vqs;
	struct virtio_device *vdev = vblk->vdev;
	struct irq_affinity desc = { 0, };

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_MQ,
				   struct virtio_blk_config, num_queues,
				   &num_vqs);
	if (err)
		num_vqs = 1;

	num_vqs = min_t(unsigned int, nr_cpu_ids, num_vqs);

	vblk->vqs = kmalloc_array(num_vqs, sizeof(*vblk->vqs), GFP_KERNEL);
	if (!vblk->vqs)
		return -ENOMEM;

	names = kmalloc_array(num_vqs, sizeof(*names), GFP_KERNEL);
	callbacks = kmalloc_array(num_vqs, sizeof(*callbacks), GFP_KERNEL);
	vqs = kmalloc_array(num_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!names || !callbacks || !vqs) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < num_vqs; i++) {
		callbacks[i] = virtblk_done;
		snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "req.%d", i);
		names[i] = vblk->vqs[i].name;
	}

	/* Discover virtqueues and write information to configuration.  */
	err = virtio_find_vqs(vdev, num_vqs, vqs, callbacks, names, &desc);
	if (err)
		goto out;

	for (i = 0; i < num_vqs; i++) {
		spin_lock_init(&vblk->vqs[i].lock);
		vblk->vqs[i].vq = vqs[i];
	}
	vblk->num_vqs = num_vqs;

out:
	kfree(vqs);
	kfree(callbacks);
	kfree(names);
	if (err)
		kfree(vblk->vqs);
	return err;
}

/*
 * Legacy naming scheme used for virtio devices.  We are stuck with it for
 * virtio blk but don't ever use it for any new driver.
 */
static int virtblk_name_format(char *prefix, int index, char *buf, int buflen)
{
	const int base = 'z' - 'a' + 1;
	char *begin = buf + strlen(prefix);
	char *end = buf + buflen;
	char *p;
	int unit;

	p = end - 1;
	*p = '\0';
	unit = base;
	do {
		if (p == begin)
			return -EINVAL;
		*--p = 'a' + (index % unit);
		index = (index / unit) - 1;
	} while (index >= 0);

	memmove(begin, p, end - p);
	memcpy(buf, prefix, strlen(prefix));

	return 0;
}

static int virtblk_get_cache_mode(struct virtio_device *vdev)
{
	u8 writeback;
	int err;

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE,
				   struct virtio_blk_config, wce,
				   &writeback);

	/*
	 * If WCE is not configurable and flush is not available,
	 * assume no writeback cache is in use.
	 */
	if (err)
		writeback = virtio_has_feature(vdev, VIRTIO_BLK_F_FLUSH);

	return writeback;
}

static void virtblk_update_cache_mode(struct virtio_device *vdev)
{
	u8 writeback = virtblk_get_cache_mode(vdev);
	struct virtio_blk *vblk = vdev->priv;

	blk_queue_write_cache(vblk->disk->queue, writeback, false);
	revalidate_disk(vblk->disk);
}

static const char *const virtblk_cache_types[] = {
	"write through", "write back"
};

static ssize_t
virtblk_cache_type_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	struct virtio_device *vdev = vblk->vdev;
	int i;

	BUG_ON(!virtio_has_feature(vblk->vdev, VIRTIO_BLK_F_CONFIG_WCE));
	i = sysfs_match_string(virtblk_cache_types, buf);
	if (i < 0)
		return i;

	virtio_cwrite8(vdev, offsetof(struct virtio_blk_config, wce), i);
	virtblk_update_cache_mode(vdev);
	return count;
}

static ssize_t
virtblk_cache_type_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	u8 writeback = virtblk_get_cache_mode(vblk->vdev);

	BUG_ON(writeback >= ARRAY_SIZE(virtblk_cache_types));
	return snprintf(buf, 40, "%s\n", virtblk_cache_types[writeback]);
}

static const struct device_attribute dev_attr_cache_type_ro =
	__ATTR(cache_type, 0444,
	       virtblk_cache_type_show, NULL);
static const struct device_attribute dev_attr_cache_type_rw =
	__ATTR(cache_type, 0644,
	       virtblk_cache_type_show, virtblk_cache_type_store);

#if SPDM_ENABLED

size_t print_measurement(char *buf, spdm_measurement_block_dmtf_t *measurement_block_dmtf) {
	unsigned int i;
	size_t total_size = 0;
	total_size += sprintf(buf + total_size, "measurement %u:\n", measurement_block_dmtf->Measurement_block_common_header.index);
	total_size += sprintf(buf + total_size, "0x%X 0x%X %u\n", measurement_block_dmtf->Measurement_block_common_header.measurement_specification,
												measurement_block_dmtf->Measurement_block_dmtf_header.dmtf_spec_measurement_value_type,
												measurement_block_dmtf->Measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
	for (i = 0; i < measurement_block_dmtf->Measurement_block_dmtf_header.dmtf_spec_measurement_value_size; i++) {
		total_size += sprintf(buf + total_size, "%02X ", ((uint8*)(measurement_block_dmtf+1))[i]);
		if ( (i+1) % 16 == 0 )
			total_size += sprintf(buf + total_size, "\n");
	}
	return total_size;
}

static ssize_t
virtblk_spdm_measurement_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	return_status status;
	uint8 request_attribute;
	uint8 number_of_block;
	uint32 measurement_record_length;
	uint8 *measurement_record;
	spdm_measurement_block_dmtf_t *measurement_block_dmtf;
	size_t total_size = 0;
	unsigned int i;

	measurement_record = kmalloc(MAX_SPDM_MEASUREMENT_RECORD_SIZE, GFP_KERNEL);
	if (measurement_record == NULL) {
		return sprintf(buf, "Could not allocate memory");
	}

	request_attribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
	measurement_record_length = MAX_SPDM_MEASUREMENT_RECORD_SIZE;

	status = spdm_get_measurement (
	     vblk->spdm_context,
	     NULL,
	     request_attribute,
	     SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
	     m_use_slot_id & 0xF,
	     &number_of_block,
	     &measurement_record_length,
	     measurement_record
	     );

	if (RETURN_ERROR(status)) {
		return sprintf(buf, "Could not obtain measurements Error %llu", status);
	}

	measurement_block_dmtf = (spdm_measurement_block_dmtf_t *) measurement_record;
	for (i = 0; i < number_of_block; i++) {
		total_size += print_measurement(buf + total_size, measurement_block_dmtf);

		measurement_block_dmtf = (spdm_measurement_block_dmtf_t *) (((uint8*)measurement_block_dmtf) +
									measurement_block_dmtf->Measurement_block_common_header.measurement_size +
									sizeof(spdm_measurement_block_common_header_t));
	}

	kfree(measurement_block_dmtf);
	return total_size;
}
static const struct device_attribute dev_attr_spdm_measurement =
	__ATTR(spdm_all_measurements, 0444,
	       virtblk_spdm_measurement_show, NULL);


static ssize_t
virtblk_spdm_tamper_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;

	int err;
	u8 measurement_index;
	return_status status;

	uint8 spdm_tamper_msg[10] = {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA, SPDM_BLK_APP_TAMPER };
	uint8 spdm_tamper_rsp[10];
	uintn spdm_tamper_rsp_size = sizeof(spdm_tamper_rsp);

	err = kstrtou8(buf, 10, &measurement_index);
	if (err || measurement_index > 9)
		return -EINVAL;

	spdm_tamper_msg[2] = measurement_index;

	status = spdm_send_receive_data(vblk->spdm_context, &vblk->session_id, TRUE,
						spdm_tamper_msg,
						sizeof(spdm_tamper_msg),
						spdm_tamper_rsp,
						&spdm_tamper_rsp_size);
	if (RETURN_ERROR(status)) {
		printk("%s error - %x\n", __func__, (uint32)status);
		return -EINVAL;
	}

	vblk->ts[measurement_index] = true;

	return count;
}
static ssize_t
virtblk_spdm_tamper_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct virtio_blk *vblk = disk->private_data;
	unsigned int i;
	ssize_t print_size = 0;

	struct attribute **spdm_attrs = vblk->spdm_sysfs->ktype->default_attrs;
	i = 0;
	while (spdm_attrs[i] != NULL) {
		print_size += sprintf(buf + print_size, "Measurement %u:%s tampered\n", i, (vblk->ts[i]) ? "" : " not" );
		i++;
	}

	return print_size;
}
static const struct device_attribute dev_attr_spdm_tamper =
	__ATTR(spdm_tamper_measurement, 0644,
	       virtblk_spdm_tamper_show, virtblk_spdm_tamper_store);
#endif /* SPDM_ENABLED */

static int virtblk_init_request(struct blk_mq_tag_set *set, struct request *rq,
		unsigned int hctx_idx, unsigned int numa_node)
{
	struct virtio_blk *vblk = set->driver_data;
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(rq);

#ifdef CONFIG_VIRTIO_BLK_SCSI
	vbr->sreq.sense = vbr->sense;
#endif
	sg_init_table(vbr->sg, vblk->sg_elems);
	return 0;
}

static int virtblk_map_queues(struct blk_mq_tag_set *set)
{
	struct virtio_blk *vblk = set->driver_data;

	return blk_mq_virtio_map_queues(set, vblk->vdev, 0);
}

#ifdef CONFIG_VIRTIO_BLK_SCSI
static void virtblk_initialize_rq(struct request *req)
{
	struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);

	scsi_req_init(&vbr->sreq);
}
#endif

static const struct blk_mq_ops virtio_mq_ops = {
	.queue_rq	= virtio_queue_rq,
	.complete	= virtblk_request_done,
	.init_request	= virtblk_init_request,
#ifdef CONFIG_VIRTIO_BLK_SCSI
	.initialize_rq_fn = virtblk_initialize_rq,
#endif
	.map_queues	= virtblk_map_queues,
};

static unsigned int virtblk_queue_depth;
module_param_named(queue_depth, virtblk_queue_depth, uint, 0444);

#if SPDM_ENABLED

struct spdm_sysfs_entry {
		struct attribute attr;
		ssize_t (*show)(int, char *);
		ssize_t (*store)(int, const char *, size_t);
};

static ssize_t dummy_show(int index, char *buf)
{
		return 0;
}

static struct spdm_sysfs_entry meas0_attribute = __ATTR(meas0, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas1_attribute = __ATTR(meas1, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas2_attribute = __ATTR(meas2, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas3_attribute = __ATTR(meas3, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas4_attribute = __ATTR(meas4, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas5_attribute = __ATTR(meas5, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas6_attribute = __ATTR(meas6, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas7_attribute = __ATTR(meas7, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas8_attribute = __ATTR(meas8, S_IRUGO, dummy_show, NULL);
static struct spdm_sysfs_entry meas9_attribute = __ATTR(meas9, S_IRUGO, dummy_show, NULL);

static struct attribute *spdm_attrs[] = {
		&meas0_attribute.attr,
		&meas1_attribute.attr,
		&meas2_attribute.attr,
		&meas3_attribute.attr,
		&meas4_attribute.attr,
		&meas5_attribute.attr,
		&meas6_attribute.attr,
		&meas7_attribute.attr,
		&meas8_attribute.attr,
		&meas9_attribute.attr,
		NULL,   /* need to NULL terminate the list of attributes */
};

static void spdm_release(struct kobject *kobj)
{

}

static ssize_t spdm_type_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
		struct kobject *parent = kobj->parent;
		struct device *disk_dev = container_of(parent, struct device, kobj);
		struct gendisk *disk = dev_to_disk(disk_dev);
		struct virtio_blk *vblk = disk->private_data;

		struct spdm_sysfs_entry *entry;
		ssize_t return_size;

		unsigned int i;

		return_status status;
		uint8 number_of_block;
		uint32 measurement_record_length;
		uint8 *measurement_record;

		entry = container_of(attr, struct spdm_sysfs_entry, attr);

		if (!entry->show)
			return -EIO;

		i = 0;
		while (spdm_attrs[i] != NULL) {
			if(spdm_attrs[i] == attr) break;
			i++;
		}
		if (spdm_attrs[i] == NULL) {
			return sprintf(buf, "Measurement index not available\n");
		}

		i++; //measurements are counted starting from 1

		measurement_record = kmalloc(MAX_SPDM_MEASUREMENT_RECORD_SIZE, GFP_KERNEL);
		if (measurement_record == NULL) {
			return sprintf(buf, "Could not allocate memory\n");
		}

		status = spdm_get_measurement (
		     vblk->spdm_context,
		     NULL,
		     SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
		     i,
		     m_use_slot_id & 0xF,
		     &number_of_block,
		     &measurement_record_length,
		     measurement_record
		     );

		if (RETURN_ERROR(status)) {
			kfree(measurement_record);
			return sprintf(buf, "Could not obtain measurements Error %llu\n", status);
		}

		return_size = print_measurement(buf, (spdm_measurement_block_dmtf_t *)measurement_record);
		kfree(measurement_record);

		return return_size;
}

static const struct sysfs_ops spdm_sysfs_ops = {
		.show = spdm_type_show,
};

static int virtblk_setup_spdm_sysfs(struct virtio_blk *vblk, uint8 measurement_count) {
	struct kobj_type *spdm_type;
	struct attribute **spdm_attrs_local;
	int err;
	unsigned int i;

	for (i = 0; i < 10; i++) {
		vblk->ts[i] = false;
	}

	// create sysfs entry for measurement
	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_spdm_measurement);
	if (err)
		return -ENOMEM;
	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_spdm_tamper);
	if (err)
		return -ENOMEM;

	vblk->spdm_sysfs = kmalloc(sizeof(struct kobject), GFP_KERNEL);
	if (vblk->spdm_sysfs == NULL)
		return -ENOMEM;
	memset(vblk->spdm_sysfs, 0, sizeof(struct kobject));

	// assuming each HD could have different number of measurements,
	//  so we allocate and fill kobj type and attributes dynamically
	spdm_type = kmalloc(sizeof(struct kobj_type), GFP_KERNEL);
	if (vblk->spdm_sysfs == NULL) {
		kfree(vblk->spdm_sysfs);
		return -ENOMEM;
	}
	spdm_attrs_local = kmalloc(sizeof(struct attribute*) * measurement_count, GFP_KERNEL);
	if (vblk->spdm_sysfs == NULL) {
		kfree(vblk->spdm_sysfs);
		kfree(spdm_type);
		return -ENOMEM;
	}
	memcpy(spdm_attrs_local, spdm_attrs, measurement_count * (sizeof(struct attribute*)));
	spdm_attrs_local[measurement_count] = NULL;

	spdm_type->release        = spdm_release;
	spdm_type->sysfs_ops      = &spdm_sysfs_ops;
	spdm_type->default_attrs  = spdm_attrs_local;

	kobject_init(vblk->spdm_sysfs, spdm_type);
	err = kobject_add(vblk->spdm_sysfs, &disk_to_dev(vblk->disk)->kobj, "spdm");
	if (err) {
		kobject_put(vblk->spdm_sysfs);
		kfree(vblk->spdm_sysfs);
		kfree(spdm_type);
		kfree(spdm_attrs_local);
		return err;
	}
	return 0;
}
#endif /* SPDM_ENABLED */

static int virtblk_probe(struct virtio_device *vdev)
{
	struct virtio_blk *vblk;
	struct request_queue *q;
	int err, index;

#if SPDM_ENABLED
	return_status status;
	boolean use_psk;
	uint8 heartbeat_period;
	uint8 measurement_hash[MAX_HASH_SIZE];
	uint8 number_of_blocks;
	uint8 spdm_test_msg[] = {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA, SPDM_BLK_APP_MSG, 'h', 'e', 'l', 'l', 'o'};
	uint8 spdm_test_rsp[50];
	uintn spdm_test_rsp_size = sizeof(spdm_test_rsp);
#endif /* SPDM_ENABLED */

	u32 v, blk_size, sg_elems, opt_io_size;
	u16 min_io_size;
	u8 physical_block_exp, alignment_offset;

	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	err = ida_simple_get(&vd_index_ida, 0, minor_to_index(1 << MINORBITS),
			     GFP_KERNEL);
	if (err < 0)
		goto out;
	index = err;

	/* We need to know how many segments before we allocate. */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SEG_MAX,
				   struct virtio_blk_config, seg_max,
				   &sg_elems);

	/* We need at least one SG element, whatever they say. */
	if (err || !sg_elems)
		sg_elems = 1;

	/* We need an extra sg elements at head and tail. */
	sg_elems += 2;
	vdev->priv = vblk = kmalloc(sizeof(*vblk), GFP_KERNEL);
	if (!vblk) {
		err = -ENOMEM;
		goto out_free_index;
	}

	vblk->vdev = vdev;
	vblk->sg_elems = sg_elems;

#if SPDM_ENABLED
	vblk->spdm_context = NULL;
	vblk->session_id = 0;
#endif /* SPDM_ENABLED */

	INIT_WORK(&vblk->config_work, virtblk_config_changed_work);

	err = init_vq(vblk);
	if (err)
		goto out_free_vblk;

	spin_lock_init(&spdm_spinlock);

	/* FIXME: How many partitions?  How long is a piece of string? */
	vblk->disk = alloc_disk(1 << PART_BITS);
	if (!vblk->disk) {
		err = -ENOMEM;
		goto out_free_vq;
	}

	/* Default queue sizing is to fill the ring. */
	if (!virtblk_queue_depth) {
		virtblk_queue_depth = vblk->vqs[0].vq->num_free;
		/* ... but without indirect descs, we use 2 descs per req */
		if (!virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC))
			virtblk_queue_depth /= 2;
	}

	memset(&vblk->tag_set, 0, sizeof(vblk->tag_set));
	vblk->tag_set.ops = &virtio_mq_ops;
	vblk->tag_set.queue_depth = BLK_MQ_MAX_DEPTH; //virtblk_queue_depth;
	vblk->tag_set.numa_node = NUMA_NO_NODE;
	vblk->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	vblk->tag_set.cmd_size =
		sizeof(struct virtblk_req) +
		sizeof(struct scatterlist) * sg_elems;
	vblk->tag_set.driver_data = vblk;
	vblk->tag_set.nr_hw_queues = vblk->num_vqs;

	err = blk_mq_alloc_tag_set(&vblk->tag_set);
	if (err)
		goto out_put_disk;

	q = blk_mq_init_queue(&vblk->tag_set);
	if (IS_ERR(q)) {
		err = -ENOMEM;
		goto out_free_tags;
	}
	vblk->disk->queue = q;

	q->queuedata = vblk;

	virtblk_name_format("vd", index, vblk->disk->disk_name, DISK_NAME_LEN);
	BLK_SPDM_PRINT (KERN_NOTICE "HPSPDM virt_blk: creating disk %s\n", vblk->disk->disk_name);

	vblk->disk->major = major;
	vblk->disk->first_minor = index_to_minor(index);
	vblk->disk->private_data = vblk;
	vblk->disk->fops = &virtblk_fops;
	vblk->disk->flags |= GENHD_FL_EXT_DEVT;
	vblk->index = index;

	/* configure queue flush support */
	virtblk_update_cache_mode(vdev);

	/* If disk is read-only in the host, the guest should obey */
	if (virtio_has_feature(vdev, VIRTIO_BLK_F_RO))
		set_disk_ro(vblk->disk, 1);

	/* We can handle whatever the host told us to handle. */
	blk_queue_max_segments(q, vblk->sg_elems-2);

	/* No real sector limit. */
	blk_queue_max_hw_sectors(q, -1U);

	/* Host can optionally specify maximum segment size and number of
	 * segments. */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SIZE_MAX,
				   struct virtio_blk_config, size_max, &v);
	if (!err)
		blk_queue_max_segment_size(q, v);
	else
		blk_queue_max_segment_size(q, -1U);

	/* Host can optionally specify the block size of the device */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_BLK_SIZE,
				   struct virtio_blk_config, blk_size,
				   &blk_size);
	if (!err)
		blk_queue_logical_block_size(q, blk_size);
	else
		blk_size = queue_logical_block_size(q);

	/* Use topology information if available */
	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, physical_block_exp,
				   &physical_block_exp);
	if (!err && physical_block_exp)
		blk_queue_physical_block_size(q,
				blk_size * (1 << physical_block_exp));

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, alignment_offset,
				   &alignment_offset);
	if (!err && alignment_offset)
		blk_queue_alignment_offset(q, blk_size * alignment_offset);

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, min_io_size,
				   &min_io_size);
	if (!err && min_io_size)
		blk_queue_io_min(q, blk_size * min_io_size);

	err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
				   struct virtio_blk_config, opt_io_size,
				   &opt_io_size);
	if (!err && opt_io_size)
		blk_queue_io_opt(q, blk_size * opt_io_size);

	virtblk_update_capacity(vblk, false);
	virtio_device_ready(vdev);

	device_add_disk(&vdev->dev, vblk->disk);
	err = device_create_file(disk_to_dev(vblk->disk), &dev_attr_serial);
	if (err)
		goto out_del_disk;

	if (virtio_has_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE))
		err = device_create_file(disk_to_dev(vblk->disk),
					 &dev_attr_cache_type_rw);
	else
		err = device_create_file(disk_to_dev(vblk->disk),
					 &dev_attr_cache_type_ro);
	if (err)
		goto out_del_disk;

#if SPDM_ENABLED

	global_spdm_disk = vblk->disk;

	vblk->spdm_context = virtblk_init_spdm();

	if (vblk->spdm_context == NULL)
		goto out_del_disk;

	// get_version, get_capabilities, and negotiate_algorithms
	status = spdm_init_connection(
			vblk->spdm_context,
			(m_exe_connection & EXE_CONNECTION_VERSION_ONLY) != 0);
	if (RETURN_ERROR(status)) {
		printk(KERN_ALERT "Error on spdm_init_connection.");
		goto out_free_spdm;
	} else {
		printk(KERN_ALERT "SpdmContext initialized.");
	}

	virtblk_init_spdm_certificates(vblk->spdm_context);

	// other messages
	status = do_authentication_via_spdm(vblk->spdm_context);
	if (RETURN_ERROR(status)) {
		printk("do_authentication_via_spdm - %x\n", (uint32)status);
		goto out_free_spdm;
	} else {
		printk("do_authentication_via_spdm - done");
	}

	use_psk = FALSE;
	heartbeat_period = 0;
	status = spdm_start_session(vblk->spdm_context, use_psk,
				    m_use_measurement_summary_hash_type,
				    m_use_slot_id, &vblk->session_id,
				    &heartbeat_period, measurement_hash);
	if (RETURN_ERROR(status)) {
		printk("spdm_start_session - %x\n", (uint32)status);
		goto out_free_spdm;
	}

	// query the total number of measurements available
	status = spdm_get_measurement (
	    vblk->spdm_context,
	    NULL,
	    0,
	    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
	    m_use_slot_id & 0xF,
	    &number_of_blocks,
	    NULL,
	    NULL);

	if (RETURN_ERROR(status)) {
		goto out_free_spdm;
	}

	// send an arbitraty message, so last_spdm_request_session_id is set at the responder
	status = spdm_send_receive_data(vblk->spdm_context, &vblk->session_id, TRUE,
						spdm_test_msg,
						sizeof(spdm_test_msg),
						spdm_test_rsp,
						&spdm_test_rsp_size);
	if (RETURN_ERROR(status)) {
		printk("spdm_send_receive_data error - %x\n", (uint32)status);
		goto out_free_spdm;
	}

	err = virtblk_setup_spdm_sysfs(vblk, number_of_blocks);
	if (err)
		goto out_free_spdm;

#endif /* SPDM_ENABLED */
	return 0;

#if SPDM_ENABLED
out_free_spdm:
	kfree(vblk->spdm_context);
#endif /* SPDM_ENABLED */
out_del_disk:
	del_gendisk(vblk->disk);
	blk_cleanup_queue(vblk->disk->queue);
out_free_tags:
	blk_mq_free_tag_set(&vblk->tag_set);
out_put_disk:
	put_disk(vblk->disk);
out_free_vq:
	vdev->config->del_vqs(vdev);
out_free_vblk:
	kfree(vblk);
out_free_index:
	ida_simple_remove(&vd_index_ida, index);
out:
	return err;
}

static void virtblk_remove(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int index = vblk->index;
	int refc;

	/* Make sure no work handler is accessing the device. */
	flush_work(&vblk->config_work);

#if SPDM_ENABLED
	kfree(vblk->spdm_sysfs->ktype->default_attrs);
	kfree(vblk->spdm_sysfs->ktype);
	kobject_put(vblk->spdm_sysfs);
	kfree(vblk->spdm_sysfs);
	kfree(vblk->spdm_context);
#endif /* SPDM_ENABLED */

	del_gendisk(vblk->disk);
	blk_cleanup_queue(vblk->disk->queue);

	blk_mq_free_tag_set(&vblk->tag_set);

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

	refc = kref_read(&disk_to_dev(vblk->disk)->kobj.kref);
	put_disk(vblk->disk);
	vdev->config->del_vqs(vdev);
	kfree(vblk->vqs);
	kfree(vblk);

	/* Only free device id if we don't have any users */
	if (refc == 1)
		ida_simple_remove(&vd_index_ida, index);
}

#ifdef CONFIG_PM_SLEEP
static int virtblk_freeze(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	/* Ensure we don't receive any more interrupts */
	vdev->config->reset(vdev);

	/* Make sure no work handler is accessing the device. */
	flush_work(&vblk->config_work);

	blk_mq_quiesce_queue(vblk->disk->queue);

	vdev->config->del_vqs(vdev);
	return 0;
}

static int virtblk_restore(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int ret;

	ret = init_vq(vdev->priv);
	if (ret)
		return ret;

	virtio_device_ready(vdev);

	blk_mq_unquiesce_queue(vblk->disk->queue);
	return 0;
}
#endif

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_BLOCK, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features_legacy[] = {
	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
#ifdef CONFIG_VIRTIO_BLK_SCSI
	VIRTIO_BLK_F_SCSI,
#endif
	VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
	VIRTIO_BLK_F_MQ,
}
;
static unsigned int features[] = {
	VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
	VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
	VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
	VIRTIO_BLK_F_MQ,
};

static struct virtio_driver virtio_blk = {
	.feature_table			= features,
	.feature_table_size		= ARRAY_SIZE(features),
	.feature_table_legacy		= features_legacy,
	.feature_table_size_legacy	= ARRAY_SIZE(features_legacy),
	.driver.name			= KBUILD_MODNAME,
	.driver.owner			= THIS_MODULE,
	.id_table			= id_table,
	.probe				= virtblk_probe,
	.remove				= virtblk_remove,
	.config_changed			= virtblk_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze				= virtblk_freeze,
	.restore			= virtblk_restore,
#endif
};

static int __init init(void)
{
	int error;

	printk(KERN_INFO "%s: SPDM_ENABLED: %u", __FILE__, SPDM_ENABLED);

	virtblk_wq = alloc_workqueue("virtio-blk", 0, 0);
	if (!virtblk_wq)
		return -ENOMEM;

	major = register_blkdev(0, "virtblk");
	if (major < 0) {
		error = major;
		goto out_destroy_workqueue;
	}

	error = register_virtio_driver(&virtio_blk);
	if (error)
		goto out_unregister_blkdev;
	return 0;

out_unregister_blkdev:
	unregister_blkdev(major, "virtblk");
out_destroy_workqueue:
	destroy_workqueue(virtblk_wq);
	return error;
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_blk);
	unregister_blkdev(major, "virtblk");
	destroy_workqueue(virtblk_wq);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio block driver");
MODULE_LICENSE("GPL");
