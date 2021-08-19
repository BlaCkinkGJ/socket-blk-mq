#include "blkdev.h"
#include "ksocket.h"
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/hdreg.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/uaccess.h>

#define BLKDEV_DEBUG	0

/* op(1B), offset(8B), size(8B) */
#define METASZ		17
#define DATAOFFSET	1
#define DATASIZE	9
#define READ		0
#define WRITE		1

static ksocket_t sockfd_clis[32];
static struct sockaddr_in addr_srv;
static int addr_len;

static int blkdev_major = 0;
static block_dev_t *blkdev_dev = NULL;

static int send_metadata(ksocket_t sockfd_cli, struct request *rq,
		loff_t pos, unsigned long b_len)
{
	char metadata[METASZ];
	int ret;

	metadata[0] = rq_data_dir(rq);
	memcpy(metadata+DATAOFFSET, &pos, 8);
	memcpy(metadata+DATASIZE, &b_len, 8);

	ret = ksend(sockfd_cli, metadata, METASZ,
			rq_data_dir(rq) == WRITE ? MSG_MORE : 0);

#if BLKDEV_DEBUG
	printk("metadata: pos: %llu, b_len: %lu, ret: %d/%d",
			pos, b_len, ret, METASZ);
#endif

	return ret;
}

static int read_data(ksocket_t sockfd_cli, u64 size, void *buf, struct request *rq) {
	struct bio_vec bvec;
	struct req_iterator iter;
	int len;
	loff_t pos = 0;

	len = krecv(sockfd_cli, buf, size, MSG_WAITALL);

	rq_for_each_segment(bvec, rq, iter) {
		unsigned long b_len = bvec.bv_len;
		void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;

		memcpy(b_buf, buf+pos, b_len);

		pos += b_len;
	}

#if BLKDEV_DEBUG
	printk("read: %s", (char *)buf);
#endif

	return len;
}

static int write_data(ksocket_t sockfd_cli, u64 size, void *buf, struct request *rq) {
	struct bio_vec bvec;
	struct req_iterator iter;
	int len;
	loff_t pos = 0;

	rq_for_each_segment(bvec, rq, iter) {
		unsigned long b_len = bvec.bv_len;
		void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;

		memcpy(buf+pos, b_buf, b_len);

		pos += b_len;
	}

	len = ksend(sockfd_cli, buf, size, MSG_WAITALL);

#if BLKDEV_DEBUG
	printk("write: %s", (char *)buf);
#endif
	len = krecv(sockfd_cli, buf, 1, MSG_WAITALL);
	if (((char *)buf)[0] == '1')
		len = 0;

	return len;
}

static int do_request(struct request *rq, unsigned int *nr_bytes) {
	int ret = SUCCESS;
	loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
	char *buf = NULL;
	u64 size = blk_rq_bytes(rq);
	int cpu = smp_processor_id();

	buf = kmalloc(size, GFP_KERNEL);
	if (buf == NULL) {
		printk("buf alloc error\n");
		return -ENOMEM;
	}

	if (send_metadata(sockfd_clis[cpu], rq, pos, size) != METASZ) {
		printk("send metadata error");
		kfree(buf);
		return -1;
	}

	switch (rq_data_dir(rq)) {
		case READ:
			read_data(sockfd_clis[cpu], size, buf, rq);
			break;
		case WRITE:
			write_data(sockfd_clis[cpu], size, buf, rq);
		default:
			break;
	}

	*nr_bytes += size;

	kfree(buf);

#if BLKDEV_DEBUG
	printk("results: nr_bytes(%u)", *nr_bytes);
#endif

	return ret;
}

static blk_status_t queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd) {
	unsigned int nr_bytes = 0;
	blk_status_t status = BLK_STS_OK;
	struct request *rq = bd->rq;

	blk_mq_start_request(rq);

	if (do_request(rq, &nr_bytes) != 0)
		status = BLK_STS_IOERR;

	blk_mq_end_request(rq, status);

	return BLK_STS_OK;
}

static int dev_open(struct block_device *bd, fmode_t mode) {
	block_dev_t *dev = bd->bd_disk->private_data;
	if (dev == NULL) {
		printk(KERN_ERR "dev open error");
		return -ENXIO;
	}
#if BLKDEV_DEBUG
	printk("dev open");
#endif
	atomic_inc(&dev->open_counter);
	return 0;
}

static void dev_release(struct gendisk *gd, fmode_t mode) {
	block_dev_t *dev = gd->private_data;
	if (dev == NULL)
		return;
#if BLKDEV_DEBUG
	printk("dev release");
#endif
	atomic_dec(&dev->open_counter);
}

static int dev_ioctl(struct block_device *bd, fmode_t mode, unsigned int cmd,
		unsigned long arg) {
	return -ENOTTY;
}

#ifdef CONFIG_COMPAT
static int dev_compat_ioctl(struct block_device *bd, fmode_t mode,
		unsigned int cmd, unsigned long arg) {
	return -ENOTTY;
}
#endif

static struct blk_mq_ops mq_ops = {
	.queue_rq = queue_rq
};

static const struct block_device_operations blk_fops = {
	.owner = THIS_MODULE,
	.open = dev_open,
	.release = dev_release,
	.ioctl = dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =
		dev_compat_ioctl
#endif
};

static int blkdev_alloc_buffer(block_dev_t *dev) {
	dev->capacity = BLKDEV_BUFSIZ >> SECTOR_SHIFT;
	return SUCCESS;
}

static void blkdev_free_buffer(block_dev_t *dev) {
	dev->capacity = 0;
}

static int blkdev_add_device(void) {
	int ret = SUCCESS;
	struct gendisk *disk;
	struct request_queue *q;
	block_dev_t *dev = kzalloc(sizeof(block_dev_t), GFP_KERNEL);
	if (dev == NULL) {
		printk(KERN_ERR "kzalloc error");
		return -ENOMEM;
	}
	blkdev_dev = dev;

	do {
		if ((ret = blkdev_alloc_buffer(dev)) != SUCCESS)
			break;

		dev->tag_set.cmd_size = sizeof(block_cmd_t);
		dev->tag_set.driver_data = dev;

		/* queue depth is 128 */
		q = blk_mq_init_sq_queue(&dev->tag_set, &mq_ops, 128,
				BLK_MQ_F_SHOULD_MERGE);
		if (IS_ERR(q)) {
			ret = PTR_ERR(q);
			printk(KERN_ERR "blk_mq_init_sq_queue error");
			break;
		}
		dev->queue = q;
		dev->queue->queuedata = dev;

		/* minor is 1 */
		if ((disk = alloc_disk(1)) == NULL) {
			printk(KERN_ERR "alloc_disk error");
			ret = -ENOMEM;
			break;
		}

		/* only one partition */
		disk->flags |= GENHD_FL_NO_PART_SCAN;
		disk->flags |= GENHD_FL_REMOVABLE;
		disk->major = blkdev_major;
		disk->first_minor = 0;
		disk->fops = &blk_fops;
		disk->private_data = dev;
		disk->queue = dev->queue;
		sprintf(disk->disk_name, "%s%d", BLKDEV_NAME, 0);
		set_capacity(disk, dev->capacity);
		dev->gdisk = disk;

		add_disk(disk);
	} while (false);

	if (ret) {
		blkdev_remove_device();
		printk(KERN_ERR "Failed to add block device\n");
	}
	return ret;
}

static void blkdev_remove_device(void) {
	block_dev_t *dev = blkdev_dev;

	if (!dev)
		return;

	if (dev->gdisk)
		del_gendisk(dev->gdisk);

	if (dev->queue) {
		blk_cleanup_queue(dev->queue);
		dev->queue = NULL;
	}

	if (dev->tag_set.tags)
		blk_mq_free_tag_set(&dev->tag_set);

	if (dev->gdisk) {
		put_disk(dev->gdisk);
		dev->gdisk = NULL;
	}

	blkdev_free_buffer(dev);
	kfree(dev);
	blkdev_dev = NULL;
}

static int __init blkdev_init(void) {
	int ret = SUCCESS;
	int i;

	memset(&addr_srv, 0, sizeof(addr_srv));
	addr_srv.sin_family = AF_INET;
	addr_srv.sin_port = htons(SERV_PORT);
	addr_srv.sin_addr.s_addr = inet_addr(SERV_ADDR);
	addr_len = sizeof(struct sockaddr_in);

	for (i=0; i<32; i++) {
		sockfd_clis[i] = ksocket(AF_INET, SOCK_STREAM, 0);
		if (sockfd_clis[i] == NULL) {
			printk("socket create error");
			return -ENOMEM;
		}

		if (kconnect(sockfd_clis[i], (struct sockaddr*)&addr_srv, addr_len) < 0) {
			printk("socket connect error");
			return -ENOMEM;
		}
	}

	blkdev_major = register_blkdev(blkdev_major, BLKDEV_NAME);
	if (blkdev_major <= 0) {
		printk(KERN_ERR "register_blkdev error");
		for (i=0; i<32; i++)
			kclose(sockfd_clis[i]);

		return -EBUSY;
	}

	if ((ret = blkdev_add_device()) != SUCCESS) {
		unregister_blkdev(blkdev_major, BLKDEV_NAME);
		for (i=0; i<32; i++)
			kclose(sockfd_clis[i]);
	}

	printk("%s init", BLKDEV_NAME);

	return ret;
}

static void __exit blkdev_exit(void) {
	int i;

	blkdev_remove_device();

	if (blkdev_major > 0)
		unregister_blkdev(blkdev_major, BLKDEV_NAME);

	for (i=0; i<32; i++)
		kclose(sockfd_clis[i]);

	printk("%s exit", BLKDEV_NAME);
}

module_init(blkdev_init);
module_exit(blkdev_exit);
MODULE_LICENSE("GPL");
