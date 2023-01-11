/*
 * Copyright (c) 2022 Martin Jäger <martin@libre.solar>
 * Copyright (c) 2022 tado GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "frag_flash.h"

#include <zephyr/kernel.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE
#include <zephyr/drivers/flash.h>
#include <zephyr/fs/nvs.h>
#endif

LOG_MODULE_REGISTER(lorawan_frag_flash, CONFIG_LORAWAN_SERVICES_LOG_LEVEL);

#define TARGET_IMAGE_AREA DT_FIXED_PARTITION_ID(DT_NODE_BY_FIXED_PARTITION_LABEL(image_1))

#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE

#define SCRATCH_PARTTITION_LABEL image_scratch
#define SCRATCH_PARTITION_NODE   DT_NODE_BY_FIXED_PARTITION_LABEL(SCRATCH_PARTTITION_LABEL)
#define SCRATCH_DEVICE_NODE      DT_MTD_FROM_FIXED_PARTITION(SCRATCH_PARTITION_NODE)

static struct nvs_fs scratch_fs = {
	.flash_device = DEVICE_DT_GET(SCRATCH_DEVICE_NODE),
};

#else

static uint8_t cache_frag_data[FRAG_TOLERANCE][FRAG_MAX_SIZE];

#endif /* CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE */

static uint16_t cache_frag_number[FRAG_TOLERANCE];
static uint32_t frag_size;
static int cached_frags;
static bool use_cache;

static const struct flash_area *fa;

/**
 * Frag counting starts from 0, so we can use 0 as error indicator
 *
 * @returns Fragment number or 0 in case of error
 */
static inline uint16_t frag_address_to_number(uint32_t address)
{
	if (frag_size == 0 || address % frag_size != 0) {
		return 0;
	}

	return address / frag_size + 1;
}

/**
 * @returns Flash address offset or 0 in case of error
 */
static inline uint32_t frag_number_to_address(uint16_t number)
{
	if (number < 1) {
		return 0;
	}

	return (number - 1) * frag_size;
}

int frag_flash_init(uint32_t fragment_size)
{
	int err;

	if (fragment_size > FRAG_MAX_SIZE) {
		return -ENOSPC;
	}

	frag_size = fragment_size;
	cached_frags = 0;
	use_cache = false;

#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE
	struct flash_pages_info page_info;

	scratch_fs.offset = DT_REG_ADDR(DT_NODE_BY_FIXED_PARTITION_LABEL(SCRATCH_PARTTITION_LABEL));
	err = flash_get_page_info_by_offs(scratch_fs.flash_device, scratch_fs.offset,
					  &page_info);
	if (err) {
		LOG_ERR("Unable to get flash page info");
		return err;
	}
	scratch_fs.sector_size = page_info.size;
	scratch_fs.sector_count = 
		DT_REG_SIZE(DT_NODE_BY_FIXED_PARTITION_LABEL(SCRATCH_PARTTITION_LABEL)) / page_info.size;

	err = nvs_mount(&scratch_fs);
	err |= nvs_clear(&scratch_fs);
	err |= nvs_mount(&scratch_fs);
	if (err) {
		LOG_ERR("Scratch partition NVS init failed");
		return err;
	}
#endif /* CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE */

	err = flash_area_open(TARGET_IMAGE_AREA, &fa);
	if (err) {
		return err;
	}

	LOG_DBG("Starting to erase flash area");

	err = flash_area_erase(fa, 0, fa->fa_size);

	LOG_DBG("Finished erasing flash area");

	return err;
}

int frag_flash_write(uint32_t addr, const uint8_t *data, uint32_t size)
{
	uint16_t frag_number;
	int ret = 0;

	frag_number = frag_address_to_number(addr);
	if (size != frag_size || frag_number == 0) {
		LOG_ERR("Invalid fragment addr %u or size %u", addr, size);
		return -EINVAL;
	}

	if (!use_cache) {
		LOG_DBG("Writing %u bytes to addr 0x%x", size, addr);

		ret = flash_area_write(fa, addr, data, size);

		if (ret) {
			LOG_ERR("Write to addr: 0x%x failed\r\n", addr);
		}
		
	} else {
		LOG_DBG("Caching %u bytes for addr 0x%x", size, addr);

		/* overwrite fragment in cache if existing */
		for (int i = 0; i < cached_frags; i++) {
			if (cache_frag_number[i] == frag_number) {
#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE
				ret = nvs_write(&scratch_fs, frag_number, data, size);
				return ret == size ? 0 : -ENOSPC;
#else
				memcpy(cache_frag_data[i], data, size);
				return 0;
#endif /* CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE */
			}
		}

		/* otherwise create new cache entry */
		if (cached_frags < ARRAY_SIZE(cache_frag_number)) {
			cache_frag_number[cached_frags] = frag_number;
#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE
			ret = nvs_write(&scratch_fs, frag_number, data, size);
			if (ret != size) {
				LOG_ERR("NVS too small");
				return -ENOSPC;
			}
#else
			memcpy(cache_frag_data[cached_frags], data, size);
#endif /* CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE */
			cached_frags++;
		} else {
			LOG_ERR("Fragment cache too small");
			ret = -ENOSPC;
		}
	}

	return ret;
}

int frag_flash_read(uint32_t addr, uint8_t *data, uint32_t size)
{
	uint16_t frag_number;

	frag_number = frag_address_to_number(addr);
	if (size != frag_size || frag_number == 0) {
		LOG_ERR("Invalid fragment addr %u or size %u", addr, size);
		return -EINVAL;
	}

#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE
	if (nvs_read(&scratch_fs, frag_number, data, size) == size) {
		return 0;
	}
#else
	for (int i = 0; i < cached_frags; i++) {
		if (cache_frag_number[i] == frag_number) {
			memcpy(data, cache_frag_data[i], size);
			return 0;
		}
	}
#endif /* CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE */

	return flash_area_read(fa, addr, data, size);
}

void frag_flash_use_cache(void)
{
	use_cache = true;
}

void frag_flash_finish(void)
{
	uint32_t frag_address;
	int err = 0;
#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE
	uint8_t buf[frag_size];
#endif

	for (int i = 0; i < cached_frags; i++) {
		frag_address = frag_number_to_address(cache_frag_number[i]);
		LOG_DBG("Writing %u bytes to addr 0x%x", frag_size, frag_address);
#ifdef CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE
		if (nvs_read(&scratch_fs, cache_frag_number[i], buf, frag_size) == frag_size) {
			err = flash_area_write(fa, frag_address, buf, frag_size);
		}
        else {
            LOG_ERR("Reading NVS frag number %d frag size %d failed\r\n",
				cache_frag_number[i], frag_size);
        }
#else
		err = flash_area_write(fa, frag_address, cache_frag_data[i], frag_size);
#endif /* CONFIG_LORAWAN_FRAG_TRANSPORT_SCRATCH_PARTITION_CACHE */
        if (err) {
			LOG_ERR("Write to addr: 0x%x failed\r\n", frag_address);
		}
	}

	flash_area_close(fa);

	LOG_DBG("All fragments written to flash");

	err = boot_request_upgrade(BOOT_UPGRADE_TEST);
	if (err) {
		LOG_ERR("Failed to request upgrade (err %d)", err);
	}
}
