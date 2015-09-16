#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

#define MODULE_NAME	"kiomem"

#define LOG(lvl, fmt, ...) \
	printk(lvl MODULE_NAME ":%s:%i:%s(): " fmt ".\n", \
	       __FILE__, __LINE__, \
	       __func__, ## __VA_ARGS__)
#define LOGw(fmt, ...)	LOG(KERN_WARNING, fmt, ## __VA_ARGS__)
#define LOGi(fmt, ...)	LOG(KERN_INFO, fmt, ## __VA_ARGS__)
#define LOGd(fmt, ...)	LOG(KERN_DEBUG, fmt, ## __VA_ARGS__)

struct kiomem_vma {
	size_t size;
	void *vaddr;
	dma_addr_t bus;
	int refcount;
};

static ssize_t kiomem_read(struct file *filp, char __user *buf,
			   size_t count, loff_t *ppos)
{
	struct vm_area_struct *vma;
	struct kiomem_vma *kv;
	uint64_t bus;
	unsigned long remaining;

	if (!filp->private_data
	    || sizeof(bus) != count
	    || 0 != *ppos)
		return -EFAULT;

	vma = find_vma(current->mm, (unsigned long)filp->private_data);
	if (!vma || !vma->vm_private_data)
		return -EFAULT;

	kv = vma->vm_private_data;
	bus = kv->bus;
	remaining = copy_to_user(buf, &bus, sizeof(bus));
	if (remaining)
		return -EFAULT;

	return sizeof(bus);
}

static ssize_t kiomem_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	unsigned long addr;
	unsigned long remaining;

	if (sizeof(addr) != count
	    || 0 != *ppos)
		return -EFAULT;

	remaining = copy_from_user(&addr, buf, sizeof(addr));
	if (remaining)
		return -EFAULT;

	filp->private_data = (void *)addr;
	return sizeof(addr);
}

static int kiomem_vma_access(struct vm_area_struct *vma, unsigned long addr,
			     void *buf, int len, int write)
{
	unsigned long offset = addr - vma->vm_start;
	struct kiomem_vma *kv = vma->vm_private_data;
	void *vaddr = (char *)kv->vaddr + offset;

	if (write)
		memcpy(vaddr, buf, len);
	else
		memcpy(buf, vaddr, len);

	return len;
}

static void kiomem_vma_open(struct vm_area_struct *vma)
{
	struct kiomem_vma *kv = vma->vm_private_data;
	kv->refcount++;
}

static void kiomem_vma_close(struct vm_area_struct *vma)
{
	struct kiomem_vma *kv = vma->vm_private_data;
	kv->refcount--;
	if (0 == kv->refcount) {
		LOGd("freeing (%p, %i, %p)", kv->vaddr, (int)kv->size,
		     (void *)kv->bus);
		dma_free_coherent(NULL, kv->size, kv->vaddr, kv->bus);
		kfree(kv);
		vma->vm_private_data = NULL;
	}
}

static const struct vm_operations_struct kiomem_vma_ops = {
	.open = kiomem_vma_open,
	.close = kiomem_vma_close,
	.access = kiomem_vma_access,
};

static int kiomem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	dma_addr_t bus;
	struct kiomem_vma *kv;
	int err;

	void *vaddr = dma_zalloc_coherent(NULL, size, &bus, GFP_KERNEL);
	if (!vaddr) {
		LOGd("dma_zalloc_coherent() failed");
		err = -ENOMEM;
		goto err0;
	}

	kv = kmalloc(sizeof(*kv), GFP_KERNEL);
	if (!kv) {
		LOGd("kmalloc() failed");
		err = -ENOMEM;
		goto err1;
	}

	kv->size	= size;
	kv->vaddr	= vaddr;
	kv->bus		= bus;
	kv->refcount	= 1;

	vma->vm_ops = &kiomem_vma_ops;
	vma->vm_private_data = kv;

	err = dma_common_mmap(NULL, vma, vaddr, bus, size);
	if (err) {
		LOGd("dma_common_mmap() failed");
		goto err2;
	}

	return 0;

err2:
	kfree(kv);
err1:
	dma_free_coherent(NULL, size, vaddr, bus);
err0:
	return err;
}


static struct kiomem_dev {
	dev_t dev;
	struct cdev cdev;
} kiomem_dev;

static const struct file_operations kiomem_fops = {
	.owner	= THIS_MODULE,
	.read	= kiomem_read,
	.write	= kiomem_write,
	.mmap	= kiomem_mmap,
};

static int kiomem_init(void)
{
	int err = alloc_chrdev_region(&kiomem_dev.dev, 0, 1, MODULE_NAME);
	if (err) {
		LOGw("alloc_chrdev_region() failed");
		return err;
	}
	cdev_init(&kiomem_dev.cdev, &kiomem_fops);
	kiomem_dev.cdev.owner = THIS_MODULE;
	err = cdev_add(&kiomem_dev.cdev, kiomem_dev.dev, 1);
	if (err) {
		LOGw("cdev_add() failed");
		return err;
	}
	LOGi("starting");
	return 0;
}

static void kiomem_exit(void)
{
	cdev_del(&kiomem_dev.cdev);
	unregister_chrdev_region(kiomem_dev.dev, 1);
	LOGi("exiting");
}

module_init(kiomem_init);
module_exit(kiomem_exit);
