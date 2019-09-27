// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/memblock.h>
#include <linux/miscdevice.h>
#include <linux/msm_ion.h>
#include <linux/uaccess.h>
#include "compat_ion.h"
#include "ion_priv.h"

struct ion_device {
	struct miscdevice dev;
	struct plist_head heaps;
	struct rw_semaphore heap_rwsem;
	struct idr buffers;
	spinlock_t buffer_lock;
	long (*custom_ioctl)(void *client, unsigned int cmd, unsigned long arg);
};

static void ion_buffer_free_work(struct work_struct *work)
{
	struct ion_buffer *buffer = container_of(work, typeof(*buffer), free);
	struct ion_heap *heap = buffer->heap;

	heap->ops->unmap_dma(heap, buffer);
	heap->ops->free(buffer);
	kfree(buffer);
}

static struct ion_buffer *ion_buffer_create(struct ion_device *idev,
					    struct ion_heap *heap, size_t len,
					    size_t align, unsigned int flags)
{
	struct ion_buffer *buffer;
	struct scatterlist *sg;
	unsigned int i, nents;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.idev = idev,
		.flags = flags,
		.heap = heap,
		.size = len,
		.free = __WORK_INITIALIZER(buffer->free, ion_buffer_free_work),
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.refcount = ATOMIC_INIT(1),
		.iommu_data = {
			.map_list = LIST_HEAD_INIT(buffer->iommu_data.map_list),
			.lock = __MUTEX_INITIALIZER(buffer->iommu_data.lock)
		}
	};

	if (heap->ops->allocate(heap, buffer, len, align, flags)) {
		if (!(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

		ion_heap_freelist_drain(heap, 0);
		if (heap->ops->allocate(heap, buffer, len, align, flags))
			goto free_buffer;
	}

	buffer->sg_table = heap->ops->map_dma(heap, buffer);
	if (IS_ERR_OR_NULL(buffer->sg_table))
		goto free_heap;

	idr_preload(GFP_KERNEL);
	spin_lock(&idev->buffer_lock);
	buffer->id = idr_alloc(&idev->buffers, buffer, 1, 0, GFP_NOWAIT);
	spin_unlock(&idev->buffer_lock);
	idr_preload_end();

	if (buffer->id < 0)
		goto free_dma;

	for (sg = buffer->sg_table->sgl, nents = buffer->sg_table->nents;
	     nents > SG_MAX_SINGLE_ALLOC; nents -= SG_MAX_SINGLE_ALLOC - 1,
	     sg = sg_chain_ptr(sg - 1)) {
		for (i = 0; i < SG_MAX_SINGLE_ALLOC; sg++, i++) {
			sg_dma_address(sg) = sg_phys(sg);
			sg_dma_len(sg) = sg->length;
		}
	}

	for (; nents; sg++, nents--) {
		sg_dma_address(sg) = sg_phys(sg);
		sg_dma_len(sg) = sg->length;
	}

	return buffer;

free_dma:
	heap->ops->unmap_dma(heap, buffer);
free_heap:
	heap->ops->free(buffer);
free_buffer:
	kfree(buffer);
	return ERR_PTR(-EINVAL);
}

static void ion_buffer_free_rcu(struct rcu_head *head)
{
	struct ion_buffer *buffer = container_of(head, typeof(*buffer), rcu);

	queue_work(system_power_efficient_wq, &buffer->free);
}

void ion_buffer_destroy(struct ion_buffer *buffer)
{
	struct ion_device *idev = buffer->idev;

	spin_lock(&idev->buffer_lock);
	idr_remove(&idev->buffers, buffer->id);
	spin_unlock(&idev->buffer_lock);

	call_rcu(&buffer->rcu, ion_buffer_free_rcu);
}

void ion_buffer_put(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;

	if (atomic_dec_return(&buffer->refcount))
		return;

	msm_dma_buf_freed(&buffer->iommu_data);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_freelist_add(heap, buffer);
	else
		ion_buffer_destroy(buffer);
}

void *__ion_map_kernel(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	void *vaddr;

	if (!heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_cnt) {
		vaddr = buffer->vaddr;
		buffer->kmap_cnt++;
	} else {
		vaddr = heap->ops->map_kernel(heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_cnt++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);

	return vaddr;
}

void __ion_unmap_kernel(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;

	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_cnt)
		heap->ops->unmap_kernel(heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
}

struct ion_buffer *ion_buffer_find_by_id(struct ion_device *idev, int id)
{
	struct ion_buffer *buffer;

	rcu_read_lock();
	buffer = idr_find(&idev->buffers, id);
	rcu_read_unlock();

	return buffer ? buffer : ERR_PTR(-EINVAL);
}

struct ion_buffer *__ion_alloc(struct ion_device *idev, size_t len, size_t align,
			       unsigned int heap_id_mask, unsigned int flags)
{
	struct ion_buffer *buffer;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	down_read(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (!(BIT(heap->id) & heap_id_mask))
			continue;

		buffer = ion_buffer_create(idev, heap, len, align, flags);
		if (!IS_ERR(buffer)) {
			up_read(&idev->heap_rwsem);
			return buffer;
		}
	}
	up_read(&idev->heap_rwsem);

	return ERR_PTR(-EINVAL);
}

int __ion_phys(struct ion_buffer *buffer, ion_phys_addr_t *addr, size_t *len)
{
	struct ion_heap *heap = buffer->heap;

	if (!heap->ops->phys)
		return -ENODEV;

	return heap->ops->phys(heap, buffer, addr, len);
}

void ion_pages_sync_for_device(struct device *dev, struct page *page,
			       size_t size, enum dma_data_direction dir)
{
	dma_sync_single_for_device(dev, page_to_phys(page), size, dir);
}

static struct sg_table *ion_dup_sg_table(struct sg_table *orig_table)
{
	unsigned int nents = orig_table->nents;
	struct scatterlist *sg_d, *sg_s;
	struct sg_table *table;

	table = kmalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;

	if (sg_alloc_table(table, nents, GFP_KERNEL)) {
		sg_free_table(table);
		kfree(table);
		return NULL;
	}

	for (sg_d = table->sgl, sg_s = orig_table->sgl;
	     nents > SG_MAX_SINGLE_ALLOC; nents -= SG_MAX_SINGLE_ALLOC - 1,
	     sg_d = sg_chain_ptr(sg_d + SG_MAX_SINGLE_ALLOC - 1),
	     sg_s = sg_chain_ptr(sg_s + SG_MAX_SINGLE_ALLOC - 1))
		memcpy(sg_d, sg_s, (SG_MAX_SINGLE_ALLOC - 1) * sizeof(*sg_d));

	if (nents)
		memcpy(sg_d, sg_s, nents * sizeof(*sg_d));

	return table;
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction direction)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return ion_dup_sg_table(buffer->sg_table);
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction direction)
{
	sg_free_table(table);
	kfree(table);
}

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	if (!heap->ops->map_user)
		return -EINVAL;

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return heap->ops->map_user(heap, buffer, vma);
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	ion_buffer_put(buffer);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return buffer->vaddr + offset * PAGE_SIZE;
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf, size_t start,
					size_t len,
					enum dma_data_direction direction)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	return PTR_RET(__ion_map_kernel(buffer));
}

static void ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf, size_t start,
				       size_t len,
				       enum dma_data_direction direction)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	__ion_unmap_kernel(buffer);
}

static const struct dma_buf_ops ion_dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.kmap_atomic = ion_dma_buf_kmap,
	.kmap = ion_dma_buf_kmap
};

struct dma_buf *__ion_share_dma_buf(struct ion_buffer *buffer)
{
	struct dma_buf_export_info exp_info = {
		.ops = &ion_dma_buf_ops,
		.size = buffer->size,
		.flags = O_RDWR,
		.priv = &buffer->iommu_data
	};
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_export(&exp_info);
	if (!IS_ERR(dmabuf))
		atomic_inc(&buffer->refcount);

	return dmabuf;
}

int __ion_share_dma_buf_fd(struct ion_buffer *buffer)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = __ion_share_dma_buf(buffer);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

struct ion_buffer *__ion_import_dma_buf(int fd)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	buffer = container_of(dmabuf->priv, typeof(*buffer), iommu_data);
	atomic_inc(&buffer->refcount);
	dma_buf_put(dmabuf);
	return buffer;
}

static int ion_sync_for_device(int fd)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	buffer = container_of(dmabuf->priv, typeof(*buffer), iommu_data);
	dma_sync_sg_for_device(NULL, buffer->sg_table->sgl,
			       buffer->sg_table->nents, DMA_BIDIRECTIONAL);
	dma_buf_put(dmabuf);
	return 0;
}

static long ion_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	union {
		struct ion_fd_data fd;
		struct ion_allocation_data allocation;
		struct ion_handle_data handle;
		struct ion_custom_data custom;
	} data;
	struct ion_device *idev = file->private_data;
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	switch (cmd) {
	case ION_IOC_ALLOC:
	case ION_IOC_FREE:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
	case ION_IOC_SYNC:
	case ION_IOC_CUSTOM:
		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
		buffer = __ion_alloc(idev, data.allocation.len,
				     data.allocation.align,
				     data.allocation.heap_id_mask,
				     data.allocation.flags);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

		data.allocation.handle = buffer->id;
		break;
	case ION_IOC_FREE:
		buffer = ion_buffer_find_by_id(idev, data.handle.handle);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

		ion_buffer_put(buffer);
		return 0;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		buffer = ion_buffer_find_by_id(idev, data.handle.handle);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

		data.fd.fd = __ion_share_dma_buf_fd(buffer);
		if (data.fd.fd < 0)
			return data.fd.fd;
		break;
	case ION_IOC_IMPORT:
		buffer = __ion_import_dma_buf(data.fd.fd);
		if (IS_ERR(buffer))
			return PTR_ERR(buffer);

		data.handle.handle = buffer->id;
		break;
	case ION_IOC_SYNC:
		return ion_sync_for_device(data.fd.fd);
	case ION_IOC_CUSTOM:
		if (idev->custom_ioctl)
			return idev->custom_ioctl(idev, data.custom.cmd,
						  data.custom.arg);
		return -ENOTTY;
	case ION_IOC_CLEAN_CACHES:
	case ION_IOC_INV_CACHES:
	case ION_IOC_CLEAN_INV_CACHES:
		return idev->custom_ioctl(idev, cmd, arg);
	default:
		return -ENOTTY;
	}

	if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd))) {
		switch (cmd) {
		case ION_IOC_ALLOC:
		case ION_IOC_IMPORT:
			ion_buffer_put(buffer);
			break;
		case ION_IOC_SHARE:
		case ION_IOC_MAP:
			dmabuf = dma_buf_get(data.fd.fd);
			dma_buf_put(dmabuf);
			dma_buf_put(dmabuf);
			break;
		}

		return -EFAULT;
	}

	return 0;
}

static int ion_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct ion_device *idev = container_of(miscdev, typeof(*idev), dev);

	file->private_data = idev;
	return 0;
}

static const struct file_operations ion_fops = {
	.owner = THIS_MODULE,
	.open = ion_open,
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = compat_ion_ioctl
};

void ion_device_add_heap(struct ion_device *idev, struct ion_heap *heap)
{
	spin_lock_init(&heap->free_lock);
	heap->free_list_size = 0;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_init_deferred_free(heap);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE || heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	plist_node_init(&heap->node, -heap->id);

	down_write(&idev->heap_rwsem);
	plist_add(&heap->node, &idev->heaps);
	up_write(&idev->heap_rwsem);
}

int __ion_walk_heaps(struct ion_device *idev, int heap_id,
		     enum ion_heap_type type, void *data,
		     int (*f)(struct ion_heap *heap, void *data))
{
	struct ion_heap *heap;
	int ret = 0;

	down_write(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}
	up_write(&idev->heap_rwsem);

	return ret;
}

struct ion_device *ion_device_create(long (*custom_ioctl)
				     (void *client, unsigned int cmd,
				      unsigned long arg))
{
	struct ion_device *idev;
	int ret;

	idev = kmalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev)
		return ERR_PTR(-ENOMEM);

	*idev = (typeof(*idev)){
		.custom_ioctl = custom_ioctl,
		.heaps = PLIST_HEAD_INIT(idev->heaps),
		.heap_rwsem = __RWSEM_INITIALIZER(idev->heap_rwsem),
		.buffers = IDR_INIT(idev->buffers),
		.buffer_lock = __SPIN_LOCK_UNLOCKED(idev->buffer_lock),
		.dev = {
			.minor = MISC_DYNAMIC_MINOR,
			.name = "ion",
			.fops = &ion_fops
		},
	};

	ret = misc_register(&idev->dev);
	if (ret) {
		kfree(idev);
		return ERR_PTR(ret);
	}

	return idev;
}

void __init ion_reserve(struct ion_platform_data *data)
{
	phys_addr_t paddr;
	int i;

	for (i = 0; i < data->nr; i++) {
		if (!data->heaps[i].size)
			continue;

		if (data->heaps[i].base) {
			memblock_reserve(data->heaps[i].base,
					 data->heaps[i].size);
		} else {
			paddr = memblock_alloc_base(data->heaps[i].size,
						    data->heaps[i].align,
						    MEMBLOCK_ALLOC_ANYWHERE);
			if (paddr)
				data->heaps[i].base = paddr;
		}
	}
}
