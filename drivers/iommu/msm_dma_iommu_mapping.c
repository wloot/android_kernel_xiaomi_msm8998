// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/dma-buf.h>
#include <linux/msm_dma_iommu_mapping.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/barrier.h>

struct msm_iommu_meta {
	struct msm_iommu_data *data;
	struct list_head lnode;
	struct list_head map_list;
	atomic_t refcount;
	rwlock_t map_lock;
};

struct msm_iommu_map {
	struct device *dev;
	struct msm_iommu_meta *meta;
	struct list_head lnode;
	struct scatterlist sgl;
	enum dma_data_direction dir;
	unsigned int nents;
	atomic_t refcount;
};

static LIST_HEAD(meta_list);
static DEFINE_RWLOCK(meta_lock);

static struct msm_iommu_map *msm_iommu_map_lookup(struct msm_iommu_meta *meta,
						  struct device *dev)
{
	struct msm_iommu_map *map;

	list_for_each_entry(map, &meta->map_list, lnode) {
		if (map->dev == dev)
			return map;
	}

	return NULL;
}

static void msm_iommu_meta_put(struct msm_iommu_data *data)
{
	struct msm_iommu_meta *meta = data->meta;
	bool free_meta;

	write_lock(&meta_lock);
	free_meta = atomic_dec_and_test(&meta->refcount);
	if (free_meta)
		list_del(&meta->lnode);
	write_unlock(&meta_lock);

	if (free_meta) {
		kfree(meta);
		data->meta = NULL;
	}
}

int msm_dma_map_sg_attrs(struct device *dev, struct scatterlist *sg, int nents,
			 enum dma_data_direction dir, struct dma_buf *dma_buf,
			 struct dma_attrs *attrs)
{
	int not_lazy = dma_get_attr(DMA_ATTR_NO_DELAYED_UNMAP, attrs);
	struct msm_iommu_data *data = dma_buf->priv;
	struct msm_iommu_meta *meta;
	struct msm_iommu_map *map;

	/* The same buffer can be mapped concurrently, so lock onto it */
	mutex_lock(&data->lock);
	meta = data->meta;
	if (meta) {
		atomic_inc(&meta->refcount);
		read_lock(&meta->map_lock);
		map = msm_iommu_map_lookup(meta, dev);
		if (map)
			atomic_inc(&map->refcount);
		read_unlock(&meta->map_lock);
	} else {
		meta = kmalloc(sizeof(*meta), GFP_KERNEL | __GFP_NOFAIL);
		*meta = (typeof(*meta)){
			.data = data,
			.refcount = ATOMIC_INIT(2 - not_lazy),
			.map_lock = __RW_LOCK_UNLOCKED(&meta->map_lock),
			.map_list = LIST_HEAD_INIT(meta->map_list)
		};

		write_lock(&meta_lock);
		list_add(&meta->lnode, &meta_list);
		write_unlock(&meta_lock);

		data->meta = meta;
		map = NULL;
	}

	if (map) {
		sg->dma_address = map->sgl.dma_address;
		sg->dma_length = map->sgl.dma_length;
		if (is_device_dma_coherent(dev))
			dmb(ish);
	} else {
		while (!dma_map_sg_attrs(dev, sg, nents, dir, attrs));

		map = kmalloc(sizeof(*map), GFP_KERNEL | __GFP_NOFAIL);
		*map = (typeof(*map)){
			.dev = dev,
			.dir = dir,
			.meta = meta,
			.nents = nents,
			.lnode = LIST_HEAD_INIT(map->lnode),
			.refcount = ATOMIC_INIT(2 - not_lazy),
			.sgl = {
				.dma_address = sg->dma_address,
				.dma_length = sg->dma_length
			}
		};

		write_lock(&meta->map_lock);
		list_add(&map->lnode, &meta->map_list);
		write_unlock(&meta->map_lock);
	}
	mutex_unlock(&data->lock);

	return nents;
}

void msm_dma_unmap_sg(struct device *dev, struct scatterlist *sgl, int nents,
		      enum dma_data_direction dir, struct dma_buf *dma_buf)
{
	struct msm_iommu_data *data = dma_buf->priv;
	struct msm_iommu_meta *meta;
	struct msm_iommu_map *map;
	bool free_map;

	mutex_lock(&data->lock);
	meta = data->meta;
	if (!meta) {
		mutex_unlock(&data->lock);
		return;
	}

	write_lock(&meta->map_lock);
	map = msm_iommu_map_lookup(meta, dev);
	if (!map) {
		write_unlock(&meta->map_lock);
		mutex_unlock(&data->lock);
		return;
	}

	free_map = atomic_dec_and_test(&map->refcount);
	if (free_map)
		list_del(&map->lnode);
	write_unlock(&meta->map_lock);

	if (free_map) {
		dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
		kfree(map);
	}
	msm_iommu_meta_put(data);
	mutex_unlock(&data->lock);
}

int msm_dma_unmap_all_for_dev(struct device *dev)
{
	struct msm_iommu_map *map, *tmp_map;
	struct msm_iommu_meta *meta;
	LIST_HEAD(unmap_list);
	int ret = 0;

	read_lock(&meta_lock);
	list_for_each_entry(meta, &meta_list, lnode) {
		write_lock(&meta->map_lock);
		list_for_each_entry_safe(map, tmp_map, &meta->map_list, lnode) {
			if (map->dev != dev)
				continue;

			/* Do the actual unmapping outside of the locks */
			if (atomic_dec_and_test(&map->refcount))
				list_move_tail(&map->lnode, &unmap_list);
			else
				ret = -EINVAL;
		}
		write_unlock(&meta->map_lock);
	}
	read_unlock(&meta_lock);

	list_for_each_entry_safe(map, tmp_map, &unmap_list, lnode) {
		dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
		kfree(map);
	}

	return ret;
}

void msm_dma_buf_freed(struct msm_iommu_data *data)
{
	struct msm_iommu_map *map, *tmp_map;
	struct msm_iommu_meta *meta;
	LIST_HEAD(unmap_list);

	mutex_lock(&data->lock);
	meta = data->meta;
	if (!meta) {
		mutex_unlock(&data->lock);
		return;
	}

	write_lock(&meta->map_lock);
	list_for_each_entry_safe(map, tmp_map, &meta->map_list, lnode) {
		/* Do the actual unmapping outside of the lock */
		if (atomic_dec_and_test(&map->refcount))
			list_move_tail(&map->lnode, &unmap_list);
		else
			list_del_init(&map->lnode);
	}
	write_unlock(&meta->map_lock);

	list_for_each_entry_safe(map, tmp_map, &unmap_list, lnode) {
		dma_unmap_sg(map->dev, &map->sgl, map->nents, map->dir);
		kfree(map);
	}

	msm_iommu_meta_put(data);
	mutex_unlock(&data->lock);
}
