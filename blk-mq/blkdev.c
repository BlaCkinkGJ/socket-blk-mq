// [[ reference ]]
// - name: [Linux Kernel 5] Block Device Driver Example
// - author: pr0gr4m
// - link:
// https://pr0gr4m.tistory.com/entry/Linux-Kernel-5-Block-Device-Driver-Example
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

#define BUF_LEN 1024

static int blkdev_major = 0;
static block_dev_t *blkdev_dev = NULL;

static ksocket_t sockfd_cli;
static struct sockaddr_in addr_srv;
static int addr_len;
static char *buf;

static int do_request(struct request *rq, unsigned int *nr_bytes) {
  int ret = SUCCESS;
  struct bio_vec bvec;
  struct req_iterator iter;
  block_dev_t *dev = rq->q->queuedata;
  loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
  loff_t dev_size = (loff_t)(dev->capacity << SECTOR_SHIFT);

  printk("[pr0gr4m-blkdev] request start from sector %lld\n", blk_rq_pos(rq));

  rq_for_each_segment(bvec, rq, iter) {
    unsigned long b_len = bvec.bv_len;
    void *b_buf = page_address(bvec.bv_page) + bvec.bv_offset;

    if ((pos + b_len) > dev_size)
      b_len = (unsigned long)(dev_size - pos);
    if (b_len < 0)
      b_len = 0;

    if (rq_data_dir(rq) == WRITE) {
      unsigned long size = b_len;
      if (size >= BUF_LEN) {
        size = BUF_LEN - 1;
      }
      memcpy(buf, b_buf, size);
      buf[size] = '\0';
      printk("send: %s %ld", (const char *)b_buf, b_len);
      ksendto(sockfd_cli, buf, b_len + 1, 0, (struct sockaddr *)&addr_srv,
              sizeof(addr_srv));
      memcpy(dev->data + pos, b_buf, b_len);
    } else
      memcpy(b_buf, dev->data + pos, b_len);

    pos += b_len;
    *nr_bytes += b_len;
  }

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
  printk("[pr0gr4m-blkdev] request process %d bytes\n", nr_bytes);

#if 1
  blk_mq_end_request(rq, status);
#else
  if (blk_update_request(rq, status, nr_bytes))
    BUG();
  __blk_mq_end_request(rq, status);
#endif
  return BLK_STS_OK;
}

static int dev_open(struct block_device *bd, fmode_t mode) {
  block_dev_t *dev = bd->bd_disk->private_data;
  if (dev == NULL) {
    printk(KERN_ERR "[pr0gr4m-blkdev] open error");
    return -ENXIO;
  }

  atomic_inc(&dev->open_counter);
  printk("[pr0gr4m-blkdev] device was opened\n");
  return 0;
}

static void dev_release(struct gendisk *gd, fmode_t mode) {
  block_dev_t *dev = gd->private_data;
  if (dev == NULL) {
    printk(KERN_ERR "[pr0gr4m-blkdev] Invalid to release disk");
  } else {
    atomic_dec(&dev->open_counter);
    printk("[pr0gr4m-blkdev] device was closed\n");
  }
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

static struct blk_mq_ops mq_ops = {.queue_rq = queue_rq};

static const struct block_device_operations blk_fops = {.owner = THIS_MODULE,
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
  dev->data = kmalloc(dev->capacity << SECTOR_SHIFT, GFP_KERNEL);
  buf = kmalloc(BUF_LEN, GFP_KERNEL);
  if (dev->data == NULL) {
    printk(KERN_ERR "[pr0gr4m-blkdev] kmalloc error");
    return -ENOMEM;
  }
  return SUCCESS;
}

static void blkdev_free_buffer(block_dev_t *dev) {
  if (dev->data) {
    kfree(dev->data);
    kfree(buf);
    dev->data = NULL;
    dev->capacity = 0;
  }
}

static int blkdev_add_device(void) {
  int ret = SUCCESS;
  struct gendisk *disk;
  struct request_queue *queue;
  block_dev_t *dev = kzalloc(sizeof(block_dev_t), GFP_KERNEL);
  if (dev == NULL) {
    printk(KERN_ERR "[pr0gr4m-blkdev] kzalloc error");
    return -ENOMEM;
  }
  blkdev_dev = dev;

  do {
    if ((ret = blkdev_alloc_buffer(dev)) != SUCCESS)
      break;

#if 1
    dev->tag_set.cmd_size = sizeof(block_cmd_t);
    dev->tag_set.driver_data = dev;

    queue = blk_mq_init_sq_queue(&dev->tag_set, &mq_ops, 128,
                                 BLK_MQ_F_SHOULD_MERGE);
    if (IS_ERR(queue)) {
      ret = PTR_ERR(queue);
      printk(KERN_ERR "[pr0gr4m-blkdev] blk_mq_init_sq_queue error");
      break;
    }
    dev->queue = queue;
#else
    dev->tag_set.ops = &mq_ops;
    dev->tag_set.nr_hw_queues = 1;
    dev->tag_set.queue_depth = 128;
    dev->tag_set.numa_node = NUMA_NO_NODE;
    dev->tag_set.cmd_size = sizeof(block_cmd_t);
    dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
    dev->tag_set.driver_data = dev;

    ret = blk_mq_alloc_tag_set(&dev->tag_set);
    if (ret) {
      printk(KERN_ERR "[pr0gr4m-blkdev] blk_mq_alloc_tag_set error");
      break;
    }

    queue = blk_mq_init_queue(&dev->tag_set);
    if (IS_ERR(queue)) {
      ret = PTR_ERR(queue);
      printk(KERN_ERR "[pr0gr4m-blkdev] blk_mq_init_queue error");
      break;
    }
    dev->queue = queue;
#endif

    dev->queue->queuedata = dev;
    if ((disk = alloc_disk(1)) == NULL) {
      printk(KERN_ERR "[pr0gr4m-blkdev] alloc_disk error");
      ret = -ENOMEM;
      break;
    }

    disk->flags |= GENHD_FL_NO_PART_SCAN; // only one partition
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
    printk("[pr0gr4m-blkdev] block device was createdc\n");
  } while (false);

  if (ret) {
    blkdev_remove_device();
    printk(KERN_ERR "[pr0gr4m-blkdev] Failed to add block device\n");
  }
  return ret;
}

static void blkdev_remove_device(void) {
  block_dev_t *dev = blkdev_dev;
  if (dev) {
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

    printk("[pr0gr4m-blkdev] block device was removed\n");
  }
}

static int __init blkdev_init(void) {
  int ret = SUCCESS;

  //// start of udp initialize ////
  memset(&addr_srv, 0, sizeof(addr_srv));
  addr_srv.sin_family = AF_INET;
  addr_srv.sin_port = htons(4444);
  addr_srv.sin_addr.s_addr = inet_addr("192.168.1.8");
  ;
  addr_len = sizeof(struct sockaddr_in);

  sockfd_cli = ksocket(AF_INET, SOCK_DGRAM, 0);
  printk("sockfd_cli = 0x%p\n", sockfd_cli);
  if (sockfd_cli == NULL) {
    printk("socket failed\n");
    return -1;
  }
  //// end of udp initialize ////

  blkdev_major = register_blkdev(blkdev_major, BLKDEV_NAME);
  if (blkdev_major <= 0) {
    printk(KERN_ERR "[pr0gr4m-blkdev] register_blkdev error");
    return -EBUSY;
  }

  if ((ret = blkdev_add_device()) != SUCCESS)
    unregister_blkdev(blkdev_major, BLKDEV_NAME);
  return ret;
}

static void __exit blkdev_exit(void) {
  blkdev_remove_device();
  if (blkdev_major > 0)
    unregister_blkdev(blkdev_major, BLKDEV_NAME);
  kclose(sockfd_cli);
}

module_init(blkdev_init);
module_exit(blkdev_exit);
MODULE_LICENSE("GPL");
