/*
 * Copyright (C) 2009 Karel Zak <kzak@redhat.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <linux/blkzoned.h>

#include "superblocks.h"

struct btrfs_super_block {
	uint8_t csum[32];
	uint8_t fsid[16];
	uint64_t bytenr;
	uint64_t flags;
	uint8_t magic[8];
	uint64_t generation;
	uint64_t root;
	uint64_t chunk_root;
	uint64_t log_root;
	uint64_t log_root_transid;
	uint64_t total_bytes;
	uint64_t bytes_used;
	uint64_t root_dir_objectid;
	uint64_t num_devices;
	uint32_t sectorsize;
	uint32_t nodesize;
	uint32_t leafsize;
	uint32_t stripesize;
	uint32_t sys_chunk_array_size;
	uint64_t chunk_root_generation;
	uint64_t compat_flags;
	uint64_t compat_ro_flags;
	uint64_t incompat_flags;
	uint16_t csum_type;
	uint8_t root_level;
	uint8_t chunk_root_level;
	uint8_t log_root_level;
	struct btrfs_dev_item {
		uint64_t devid;
		uint64_t total_bytes;
		uint64_t bytes_used;
		uint32_t io_align;
		uint32_t io_width;
		uint32_t sector_size;
		uint64_t type;
		uint64_t generation;
		uint64_t start_offset;
		uint32_t dev_group;
		uint8_t seek_speed;
		uint8_t bandwidth;
		uint8_t uuid[16];
		uint8_t fsid[16];
	} __attribute__ ((__packed__)) dev_item;
	uint8_t label[256];
} __attribute__ ((__packed__));

#define BTRFS_SUPER_INFO_SIZE 4096
#define SECTOR_SHIFT 9

#define READ 0
#define WRITE 1

#define ASSERT(x) assert(x)

typedef uint64_t u64;
typedef uint64_t sector_t;
typedef uint8_t u8;

static int sb_write_pointer(int fd, struct blk_zone *zones, u64 *wp_ret)
{
	bool empty[2];
	bool full[2];
	sector_t sector;

	ASSERT(zones[0].type != BLK_ZONE_TYPE_CONVENTIONAL &&
	       zones[1].type != BLK_ZONE_TYPE_CONVENTIONAL);

	empty[0] = zones[0].cond == BLK_ZONE_COND_EMPTY;
	empty[1] = zones[1].cond == BLK_ZONE_COND_EMPTY;
	full[0] = zones[0].cond == BLK_ZONE_COND_FULL;
	full[1] = zones[1].cond == BLK_ZONE_COND_FULL;

	/*
	 * Possible state of log buffer zones
	 *
	 *   E I F
	 * E * x 0
	 * I 0 x 0
	 * F 1 1 C
	 *
	 * Row: zones[0]
	 * Col: zones[1]
	 * State:
	 *   E: Empty, I: In-Use, F: Full
	 * Log position:
	 *   *: Special case, no superblock is written
	 *   0: Use write pointer of zones[0]
	 *   1: Use write pointer of zones[1]
	 *   C: Compare SBs from zones[0] and zones[1], use the newer one
	 *   x: Invalid state
	 */

	if (empty[0] && empty[1]) {
		/* special case to distinguish no superblock to read */
		*wp_ret = zones[0].start << SECTOR_SHIFT;
		return -ENOENT;
	} else if (full[0] && full[1]) {
		/* Compare two super blocks */
		u8 super_block_data[2][BTRFS_SUPER_INFO_SIZE];
		struct btrfs_super_block *super[2];
		int i;
		int ret;

		for (i = 0; i < 2; i++) {
			u64 bytenr = ((zones[i].start + zones[i].len) << SECTOR_SHIFT) -
				BTRFS_SUPER_INFO_SIZE;

			ret = pread64(fd, super_block_data[i],
				      BTRFS_SUPER_INFO_SIZE, bytenr);
			if (ret != BTRFS_SUPER_INFO_SIZE)
				return -EIO;
			super[i] = (struct btrfs_super_block *)&super_block_data[i];
		}

		if (super[0]->generation > super[1]->generation)
			sector = zones[1].start;
		else
			sector = zones[0].start;
	} else if (!full[0] && (empty[1] || full[1])) {
		sector = zones[0].wp;
	} else if (full[0]) {
		sector = zones[1].wp;
	} else {
		return -EUCLEAN;
	}
	*wp_ret = sector << SECTOR_SHIFT;
	return 0;
}

static int sb_log_offset(uint32_t zone_size_sector, blkid_probe pr,
			 uint64_t *offset_ret)
{
	uint32_t zone_num = 0;
	struct blk_zone_report *rep;
	struct blk_zone *zones;
	size_t rep_size;
	int ret;
	uint64_t wp;

	rep_size = sizeof(struct blk_zone_report) + sizeof(struct blk_zone) * 2;
	rep = malloc(rep_size);
	if (!rep)
		return -errno;

	memset(rep, 0, rep_size);
	rep->sector = zone_num * zone_size_sector;
	rep->nr_zones = 2;

	ret = ioctl(pr->fd, BLKREPORTZONE, rep);
	if (ret) {
		ret = -errno;
		goto out;
	}
	if (rep->nr_zones != 2) {
		ret = 1;
		goto out;
	}

	zones = (struct blk_zone *)(rep + 1);

	if (zones[0].type == BLK_ZONE_TYPE_CONVENTIONAL) {
		*offset_ret = zones[0].start << SECTOR_SHIFT;
		ret = 0;
		goto out;
	}

	ret = sb_write_pointer(pr->fd, zones, &wp);
	if (ret != -ENOENT && ret) {
		ret = 1;
		goto out;
	}
	if (ret != -ENOENT) {
		if (wp == zones[0].start << SECTOR_SHIFT)
			wp = (zones[1].start + zones[1].len) << SECTOR_SHIFT;
		wp -= BTRFS_SUPER_INFO_SIZE;
	}
	*offset_ret = wp;

	ret = 0;
out:
	free(rep);

	return ret;
}

static int probe_btrfs(blkid_probe pr, const struct blkid_idmag *mag)
{
	struct btrfs_super_block *bfs;
	uint32_t zone_size_sector;
	int ret;

	if (pr->zone_size != 0) {
		uint64_t offset = 0;

		ret = sb_log_offset(zone_size_sector, pr, &offset);
		if (ret)
			return ret;
		bfs = (struct btrfs_super_block*)
			blkid_probe_get_buffer(pr, offset,
					       sizeof(struct btrfs_super_block));
	} else {
		bfs = blkid_probe_get_sb(pr, mag, struct btrfs_super_block);
	}
	if (!bfs)
		return errno ? -errno : 1;

	if (*bfs->label)
		blkid_probe_set_label(pr,
				(unsigned char *) bfs->label,
				sizeof(bfs->label));

	blkid_probe_set_uuid(pr, bfs->fsid);
	blkid_probe_set_uuid_as(pr, bfs->dev_item.uuid, "UUID_SUB");
	blkid_probe_set_block_size(pr, le32_to_cpu(bfs->sectorsize));

	return 0;
}

const struct blkid_idinfo btrfs_idinfo =
{
	.name		= "btrfs",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_btrfs,
	.minsz		= 1024 * 1024,
	.magics		=
	{
	  { .magic = "_BHRfS_M", .len = 8, .sboff = 0x40, .kboff = 64 },
	  /* for HMZONED btrfs */
	  { .magic = "!BHRfS_M", .len = 8, .sboff = 0x40,
	    .is_zone = 1, .zonenum = 0, .kboff_inzone = 0 },
	  { .magic = "_BHRfS_M", .len = 8, .sboff = 0x40,
	    .is_zone = 1, .zonenum = 0, .kboff_inzone = 0 },
	  { .magic = "_BHRfS_M", .len = 8, .sboff = 0x40,
	    .is_zone = 1, .zonenum = 1, .kboff_inzone = 0 },
	  { NULL }
	}
};

