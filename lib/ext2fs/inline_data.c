/*
 * inline_data.c --- data in inode
 *
 * Copyright (C) 2012 Zheng Liu <wenqing.lz@taobao.com>
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU library
 * General Public License, version 2.
 * %End-Header%
 */

#include "config.h"
#include <stdio.h>
#include <time.h>

#include "ext2_fs.h"
#include "ext2_ext_attr.h"

#include "ext2fs.h"
#include "ext2fsP.h"

static void *ext2fs_get_inline_xattr_pos(struct ext2_inode_large *inode,
					 struct inline_data *data);
static unsigned int ext2fs_get_max_inline_size(ext2_filsys fs,
					       struct ext2_inode_large *inode);
static void ext2fs_inline_data_finish_convert(ext2_filsys fs, ext2_ino_t ino,
					      char *target, char *buf,
					      int inline_size);
static void ext2fs_update_final_de(ext2_filsys fs, char *de_buf,
				   int old_size, int new_size);

errcode_t ext2fs_inline_data_find(ext2_filsys fs,
				  struct ext2_inode_large *inode,
				  struct inline_data *data)
{
	errcode_t retval;

	struct ext2_ext_attr_search s = {
		.not_found = ENODATA,
	};
	struct ext2_ext_attr_info i = {
		.name_index = EXT4_EXT_ATTR_INDEX_SYSTEM,
		.name = EXT4_EXT_ATTR_SYSTEM_DATA,
	};

	data->inline_off = 0;
	if (inode->i_extra_isize > (EXT2_INODE_SIZE(fs->super) -
				   EXT2_GOOD_OLD_INODE_SIZE))
		return EXT2_ET_BAD_EXTRA_SIZE;

	retval = ext2fs_ext_attr_ibody_find(fs, inode, &i, &s);
	if (retval)
		return retval;

	if (!s.not_found) {
		data->inline_off = (__u16)((char *)s.here - (char *)inode);
		data->inline_size = EXT4_MIN_INLINE_DATA_SIZE +
				    s.here->e_value_size;
		return 0;
	}

	return EXT2_ET_BAD_EXT_ATTR_MAGIC;
}

static void *ext2fs_get_inline_xattr_pos(struct ext2_inode_large *inode,
					 struct inline_data *data)
{
	struct ext2_ext_attr_entry *entry;
	struct ext2_ext_attr_ibody_header *header;

	header = IHDR(inode);
	entry = (struct ext2_ext_attr_entry *)
			((char *)inode + data->inline_off);

	return (void *) (IFIRST(header) + entry->e_value_offs);
}

errcode_t ext2fs_inline_data_destory_data(ext2_filsys fs, ext2_ino_t ino,
					  struct ext2_inode_large *inode,
					  struct inline_data *data)
{
	struct ext2_ext_attr_ibody_header *header;
	struct ext2_ext_attr_search s = {
		.not_found = ENODATA,
	};
	struct ext2_ext_attr_info i = {
		.name_index = EXT4_EXT_ATTR_INDEX_SYSTEM,
		.name = EXT4_EXT_ATTR_SYSTEM_DATA,
		.value = "",
		.value_len = 0,
	};
	errcode_t retval;

	if (!data->inline_off)
		return 0;

	if (inode->i_extra_isize > (EXT2_INODE_SIZE(fs->super) -
				    EXT2_GOOD_OLD_INODE_SIZE))
		return EXT2_ET_BAD_EXTRA_SIZE;

	header = IHDR(inode);
	if (header->h_magic != EXT2_EXT_ATTR_MAGIC)
		return EXT2_ET_BAD_EXT_ATTR_MAGIC;

	retval = ext2fs_ext_attr_ibody_find(fs, inode, &i, &s);
	if (retval)
		return retval;

	if (!s.not_found) {
		retval = ext2fs_ext_attr_set_entry(&i, &s);
		if (retval)
			return retval;
	}

	memset((void *)inode->i_block, 0, EXT4_MIN_INLINE_DATA_SIZE);

	return 0;
}

int ext2fs_inode_has_inline_data(ext2_filsys fs, ext2_ino_t ino)
{
	struct ext2_inode inode;
	errcode_t retval;

	retval = ext2fs_read_inode(fs, ino, &inode);
	if (retval)
		return 0;

	return (inode.i_flags & EXT4_INLINE_DATA_FL);
}

int ext2fs_inline_data_get_size(ext2_filsys fs, ext2_ino_t ino)
{
	struct ext2_inode_large *inode;
	struct inline_data data;
	errcode_t retval = 0;
	int size = 0;

	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return 0;
	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto out;

	if (inode->i_flags & EXT4_INLINE_DATA_FL) {
		retval = ext2fs_inline_data_find(fs, inode, &data);
		if (retval)
			goto out;
		size = data.inline_size;
	}

out:
	ext2fs_free_mem(&inode);
	return size;
}

static void ext2fs_update_final_de(ext2_filsys fs, char *de_buf,
				   int old_size, int new_size)
{
	struct ext2_dir_entry *de, *prev_de;
	char *limit;
	unsigned int de_len;

	de = (struct ext2_dir_entry *)de_buf;
	if (old_size) {
		limit = de_buf + old_size;
		do {
			prev_de = de;
			ext2fs_get_rec_len(fs, de, &de_len);
			de_buf += de_len;
			de = (struct ext2_dir_entry *)de_buf;
		} while (de_buf < limit);

		ext2fs_set_rec_len(fs, de_len + new_size - old_size,
				   prev_de);
	} else {
		de->inode = 0;
		ext2fs_set_rec_len(fs, new_size, de);
	}
}

static void ext2fs_inline_data_finish_convert(ext2_filsys fs, ext2_ino_t ino,
					      char *target, char *buf,
					      int inline_size)
{
	struct ext2_dir_entry *de;
	struct ext2_dir_entry_tail *t;
	int header_size = 0;
	int csum_size = 0;
	int filetype = 0;

	if (EXT2_HAS_RO_COMPAT_FEATURE(fs->super,
				       EXT4_FEATURE_RO_COMPAT_METADATA_CSUM))
		csum_size = sizeof(struct ext2_dir_entry_tail);

	/* First create '.' and '..' */
	if (fs->super->s_feature_incompat &
	    EXT2_FEATURE_INCOMPAT_FILETYPE)
		filetype = EXT2_FT_DIR << 8;

	de = (struct ext2_dir_entry *)target;
	de->inode = ino;
	de->name_len = 1 | filetype;
	de->name[0] = '.';
	de->name[1] = '\0';
	de->rec_len = EXT2_DIR_REC_LEN(1);

	de = (struct ext2_dir_entry *)(target + de->rec_len);
	de->rec_len = EXT2_DIR_REC_LEN(2);
	de->inode = ((struct ext2_dir_entry *)buf)->inode;
	de->name_len = 2 | filetype;
	de->name[0] = '.';
	de->name[1] = '.';
	de->name[2] = '\0';

	de = (struct ext2_dir_entry *)(target +
				       EXT2_DIR_REC_LEN(1) +
				       EXT2_DIR_REC_LEN(2));
	header_size = (char *)de - (char *)target;

	memcpy((void *)de, buf + EXT4_INLINE_DATA_DOTDOT_SIZE,
		inline_size - EXT4_INLINE_DATA_DOTDOT_SIZE);

	ext2fs_update_final_de(fs, target,
		inline_size - EXT4_INLINE_DATA_DOTDOT_SIZE + header_size,
		fs->blocksize - csum_size);

	if (csum_size) {
		t = EXT2_DIRENT_TAIL(target, fs->blocksize);
		ext2fs_initialize_dirent_tail(fs, t);
	}
}

errcode_t ext2fs_inline_data_iterate(ext2_filsys fs,
			       ext2_ino_t ino,
			       int flags,
			       char *block_buf,
			       int (*func)(ext2_filsys fs,
					   char *buf,
					   unsigned int buf_len,
					   e2_blkcnt_t blockcnt,
					   struct ext2_inode_large *inode,
					   void *priv_data),
			       void *priv_data)
{
	struct dir_context *ctx;
	struct ext2_inode_large *inode;
	struct ext2_dir_entry dirent;
	struct inline_data data;
	errcode_t retval = 0;
	e2_blkcnt_t blockcnt = 0;
	void *inline_start;
	int inline_size;

	ctx = (struct dir_context *)priv_data;

	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return retval;

	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto out;

	if (inode->i_size == 0)
		goto out;

	/* we first check '.' and '..' dir */
	dirent.inode = ino;
	dirent.name_len = 1;
	ext2fs_set_rec_len(fs, EXT2_DIR_REC_LEN(2), &dirent);
	dirent.name[0] = '.';
	dirent.name[1] = '\0';
	retval |= (*func)(fs, (void *)&dirent, dirent.rec_len, blockcnt++,
			 inode, priv_data);
	if (retval & BLOCK_ABORT)
		goto out;

	dirent.inode = (__u32)*inode->i_block;
	dirent.name_len = 2;
	ext2fs_set_rec_len(fs, EXT2_DIR_REC_LEN(3), &dirent);
	dirent.name[0] = '.';
	dirent.name[1] = '.';
	dirent.name[2] = '\0';
	retval |= (*func)(fs, (void *)&dirent, dirent.rec_len, blockcnt++,
			 inode, priv_data);
	if (retval & BLOCK_ABORT)
		goto out;

	inline_start = (char *)inode->i_block + EXT4_INLINE_DATA_DOTDOT_SIZE;
	inline_size = EXT4_MIN_INLINE_DATA_SIZE - EXT4_INLINE_DATA_DOTDOT_SIZE;
	retval |= (*func)(fs, inline_start, inline_size, blockcnt++,
			 inode, priv_data);
	if (retval & BLOCK_ABORT)
		goto out;

	retval = ext2fs_inline_data_find(fs, inode, &data);
	if (retval)
		goto out;
	if (data.inline_size > EXT4_MIN_INLINE_DATA_SIZE) {
		inline_start = ext2fs_get_inline_xattr_pos(inode, &data);
		inline_size = data.inline_size - EXT4_MIN_INLINE_DATA_SIZE;
		retval |= (*func)(fs, inline_start, inline_size, blockcnt++,
			 inode, priv_data);
		if (retval & BLOCK_ABORT)
			goto out;
	}

out:
	retval |= BLOCK_ERROR;
	ext2fs_free_mem(&inode);
	return retval & BLOCK_ERROR ? ctx->errcode : 0;
}

errcode_t ext2fs_read_inline_data(ext2_filsys fs, ext2_ino_t ino, char *buf)
{
	struct ext2_inode_large *inode;
	struct inline_data data;
	errcode_t retval = 0;
	unsigned int inline_size;

	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return retval;

	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto err;

	retval = ext2fs_inline_data_find(fs, inode, &data);
	if (retval)
		goto err;

	inline_size = data.inline_size;

	memcpy(buf, (void *)inode->i_block, EXT4_MIN_INLINE_DATA_SIZE);
	if (inline_size > EXT4_MIN_INLINE_DATA_SIZE)
		memcpy(buf + EXT4_MIN_INLINE_DATA_SIZE,
		       ext2fs_get_inline_xattr_pos(inode, &data),
		       inline_size - EXT4_MIN_INLINE_DATA_SIZE);

err:
	ext2fs_free_mem(&inode);
	return retval;
}

errcode_t ext2fs_write_inline_data(ext2_filsys fs, ext2_ino_t ino, char *buf)
{
	struct ext2_inode_large *inode;
	struct inline_data data;
	errcode_t retval = 0;
	unsigned int inline_size;

	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return retval;

	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto err;

	retval = ext2fs_inline_data_find(fs, inode, &data);
	if (retval)
		goto err;

	inline_size = data.inline_size;

	memcpy((void *)inode->i_block, buf, EXT4_MIN_INLINE_DATA_SIZE);
	if (inline_size > EXT4_MIN_INLINE_DATA_SIZE)
		memcpy(ext2fs_get_inline_xattr_pos(inode, &data),
		       buf + EXT4_MIN_INLINE_DATA_SIZE,
		       inline_size - EXT4_MIN_INLINE_DATA_SIZE);

	retval = ext2fs_write_inode_full(fs, ino, (void *)inode,
					 EXT2_INODE_SIZE(fs->super));
err:
	ext2fs_free_mem(&inode);
	return retval;
}

int ext2fs_inline_data_check(ext2_filsys fs, ext2_ino_t ino)
{
	struct ext2_inode_large *inode;
	struct inline_data data;
	errcode_t retval = 0;
	int pass = 0;

	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return pass;

	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto err;

	retval = ext2fs_inline_data_find(fs, inode, &data);
	if (retval)
		goto err;

	if (data.inline_off != 0)
		pass = 1;

err:
	ext2fs_free_mem(&inode);
	return pass;
}

errcode_t ext2fs_inline_data_convert(ext2_filsys fs,
				     ext2_ino_t  ino,
				     void *priv_data)
{
	struct expand_dir_struct *es;
	struct ext2_inode_large *inode;
	struct inline_data data;
	ext2_extent_handle_t handle;
	errcode_t retval;
	blk64_t blk;
	char *backup_buf;
	char *blk_buf;
	unsigned int inline_size;

	EXT2_CHECK_MAGIC(fs, EXT2_ET_MAGIC_EXT2FS_FILSYS);

	es = (struct expand_dir_struct *)priv_data;
	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return retval;

	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto out;

	retval = ext2fs_inline_data_find(fs, inode, &data);
	if (retval)
		goto out;

	inline_size = data.inline_size;
	retval = ext2fs_get_mem(inline_size, &backup_buf);
	if (retval)
		goto out;

	memcpy(backup_buf, (void *)inode->i_block, EXT4_MIN_INLINE_DATA_SIZE);
	if (inline_size > EXT4_MIN_INLINE_DATA_SIZE)
		memcpy(backup_buf + EXT4_MIN_INLINE_DATA_SIZE,
		       ext2fs_get_inline_xattr_pos(inode, &data),
		       inline_size - EXT4_MIN_INLINE_DATA_SIZE);

	/* clear the entry and the flag in dir now */
	retval = ext2fs_inline_data_destory_data(fs, ino, inode, &data);
	if (retval)
		goto out1;

	if (fs->super->s_feature_incompat & EXT3_FEATURE_INCOMPAT_EXTENTS) {
		if (LINUX_S_ISDIR(inode->i_mode) ||
		    LINUX_S_ISREG(inode->i_mode) ||
		    LINUX_S_ISLNK(inode->i_mode))
			inode->i_flags |= EXT4_EXTENTS_FL;
	}

	inode->i_flags &= ~EXT4_INLINE_DATA_FL;

	retval = ext2fs_new_block2(fs, 0, 0, &blk);
	if (retval)
		goto out1;

	ext2fs_iblk_set(fs, (void*)inode, 1);
	if (!(fs->super->s_feature_incompat & EXT3_FEATURE_INCOMPAT_EXTENTS))
		inode->i_block[0] = blk;
	inode->i_size = fs->blocksize;

	retval = ext2fs_get_mem(fs->blocksize, &blk_buf);
	if (retval)
		goto out1;

	memset(blk_buf, 0, sizeof(fs->blocksize));
	if (LINUX_S_ISDIR(inode->i_mode)) {
		/* set the final dir entry to cover the whole block */
		ext2fs_inline_data_finish_convert(fs, ino, blk_buf, backup_buf,
						  inline_size);
	} else {
		memcpy(blk_buf, backup_buf, inline_size);
	}

	retval = ext2fs_write_dir_block4(fs, blk, blk_buf, 0, ino);
	if (retval)
		goto out2;
	retval = ext2fs_write_inode_full(fs, ino, (void *)inode,
					 EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto out2;

	if (fs->super->s_feature_incompat & EXT3_FEATURE_INCOMPAT_EXTENTS) {
		retval = ext2fs_extent_open2(fs, ino, (void *)inode, &handle);
		if (retval)
			goto out2;
		retval = ext2fs_extent_set_bmap(handle, 0, blk, 0);
		ext2fs_extent_free(handle);
		if (retval)
			goto out2;
	}

	ext2fs_block_alloc_stats2(fs, blk, +1);

out2:
	ext2fs_free_mem(&blk_buf);
out1:
	ext2fs_free_mem(&backup_buf);
out:
	ext2fs_free_mem(&inode);

	if (retval) {
		es->err = retval;
	} else {
		es->done = 1;
		es->newblocks++;
		es->goal = blk;
	}
	return retval;
}

static unsigned int ext2fs_get_max_inline_size(ext2_filsys fs,
					       struct ext2_inode_large *inode)
{
	struct ext2_ext_attr_entry *entry;
	struct ext2_ext_attr_ibody_header *header;
	struct inline_data data;
	errcode_t retval = 0;
	size_t freesize, min_offs;

	min_offs = EXT2_INODE_SIZE(fs->super) -
		   EXT2_GOOD_OLD_INODE_SIZE -
		   inode->i_extra_isize -
		   sizeof(struct ext2_ext_attr_ibody_header);

	header = IHDR(inode);
	entry = IFIRST(header);

	for (; !EXT2_EXT_IS_LAST_ENTRY(entry);
	     entry = EXT2_EXT_ATTR_NEXT(entry)) {
		if (!entry->e_value_block && entry->e_value_size) {
			size_t offs = entry->e_value_offs;
			if (offs < min_offs)
				min_offs = offs;
		}
	}
	freesize = min_offs -
		((char *)entry - (char *)IFIRST(header)) - sizeof(__u32);

	/*
	 * We try to get inline data offset, but maybe it doesn't be
	 * created.  So we ignore this error.
	 */
	retval = ext2fs_inline_data_find(fs, inode, &data);
	if (retval && retval != EXT2_ET_BAD_EXT_ATTR_MAGIC)
		return 0;

	if (data.inline_off) {
		entry = (struct ext2_ext_attr_entry *)
			((char *)inode + data.inline_off);
		freesize += entry->e_value_size;
		goto out;
	}

	freesize -= EXT2_EXT_ATTR_LEN(strlen(EXT4_EXT_ATTR_SYSTEM_DATA));

	if (freesize > EXT2_EXT_ATTR_ROUND)
		freesize = EXT2_EXT_ATTR_SIZE(freesize - EXT2_EXT_ATTR_ROUND);
	else
		freesize = 0;

out:
	return freesize + EXT4_MIN_INLINE_DATA_SIZE;
}

errcode_t ext2fs_try_to_write_inline_data(ext2_filsys fs, ext2_ino_t ino,
					  const void *buf, unsigned int nbytes,
					  unsigned int *written)
{
	struct ext2_inode_large *inode;
	struct inline_data data;
	errcode_t retval = 0;
	unsigned int inline_size = 0;

	retval = ext2fs_get_mem(EXT2_INODE_SIZE(fs->super), &inode);
	if (retval)
		return retval;
	retval = ext2fs_read_inode_full(fs, ino, (void *)inode,
					EXT2_INODE_SIZE(fs->super));
	if (retval)
		goto out;

	if (nbytes > ext2fs_get_max_inline_size(fs, inode)) {
		retval = EXT2_ET_INLINE_DATA_NO_SPACE;
		goto out;
	}

	retval = ext2fs_inline_data_create(fs, inode, nbytes);
	if (retval)
		goto out;

	retval = ext2fs_inline_data_find(fs, inode, &data);
	if (retval)
		goto out;

	inline_size = data.inline_size;

	memcpy((void *)inode->i_block, buf, EXT4_MIN_INLINE_DATA_SIZE);
	if (inline_size > EXT4_MIN_INLINE_DATA_SIZE)
		memcpy(ext2fs_get_inline_xattr_pos(inode, &data),
		       (const char *) buf + EXT4_MIN_INLINE_DATA_SIZE,
		       inline_size - EXT4_MIN_INLINE_DATA_SIZE);

	inode->i_flags &= ~EXT4_EXTENTS_FL;
	inode->i_flags |= EXT4_INLINE_DATA_FL;

	retval = ext2fs_write_inode_full(fs, ino, (void *)inode,
					 EXT2_INODE_SIZE(fs->super));

	if (!retval)
		*written = nbytes;
	else
		*written = 0;

out:
	ext2fs_free_mem(&inode);
	return retval;
}

errcode_t ext2fs_inline_data_create(ext2_filsys fs,
				    struct ext2_inode_large *inode,
				    unsigned int len)
{
	struct ext2_ext_attr_ibody_header *header;
	struct ext2_ext_attr_search s = {
		.not_found = ENODATA,
	};
	struct ext2_ext_attr_info i = {
		.name_index = EXT4_EXT_ATTR_INDEX_SYSTEM,
		.name = EXT4_EXT_ATTR_SYSTEM_DATA,
	};
	errcode_t retval;

	if (len > EXT4_MIN_INLINE_DATA_SIZE) {
		i.value = EXT2_ZERO_EXT_ATTR_VALUE;
		i.value_len = len - EXT4_MIN_INLINE_DATA_SIZE;
	} else {
		i.value = "";
		i.value_len = 0;
	}

	retval = ext2fs_ext_attr_ibody_find(fs, inode, &i, &s);
	if (retval)
		return retval;
	retval = ext2fs_ext_attr_set_entry(&i, &s);
	if (retval)
		return retval;

	header = IHDR(inode);
	if (!EXT2_EXT_IS_LAST_ENTRY(s.first))
		header->h_magic = EXT2_EXT_ATTR_MAGIC;
	else
		header->h_magic = 0;

	return 0;
}

#ifdef DEBUG
#include "e2p/e2p.h"

/*
 * The length of buffer is set to 64 because in inode's i_block member it only
 * can save 60 bytes.  Thus this value can let the data being saved in extra
 * space.
 */
#define BUF_LEN (64)

/*
 * Test manipulation of regular file.
 *
 * In this test case, the following operations are tested:
 *  - regular file creation with inline_data flag
 *  - try to write data into inode while the size of data is fit for saving in
 *    inode
 *  - read data from inode
 *  - write data without changing the size of inline data
 *  - get the size of inline data
 *  - truncate
 *  - check header
 */
static errcode_t test_file(ext2_filsys fs)
{
	ext2_ino_t newfile;
	errcode_t retval;
	unsigned int written;
	struct ext2_inode_large inode;
	char *buf, *cmpbuf;
	int inline_size;

	retval = ext2fs_new_inode(fs, 2, 010755, 0, &newfile);
	if (retval) {
		com_err("test_file", retval,
			"While creating a new file");
		return 1;
	}

	retval = ext2fs_write_new_inode(fs, newfile, (void *)&inode);
	if (retval) {
		com_err("test_file", retval,
			"While writting a new inode");
		return 1;
	}

	retval = ext2fs_get_arrayzero(BUF_LEN, sizeof(char), &buf);
	if (retval) {
		com_err("test_file", retval, "While creating buffer");
		return 1;
	}
	memset(buf, 'a', BUF_LEN);
	retval = ext2fs_try_to_write_inline_data(fs, newfile, buf,
						 BUF_LEN, &written);
	if (retval) {
		com_err("test_file", retval,
			"While trying to write a regular file");
		return 1;
	}

	if (written != BUF_LEN) {
		printf("inline_data: write a regular file error, written %d "
		       "should be %d.\n", written, BUF_LEN);
		return 1;
	}

	inline_size = ext2fs_inline_data_get_size(fs, newfile);
	if (inline_size != BUF_LEN) {
		printf("inline_data: the size of inline data is incorrect\n");
		return 1;
	}

	retval = ext2fs_get_arrayzero(BUF_LEN, sizeof(char), &cmpbuf);
	if (retval) {
		com_err("test_file", retval, "While creating buffer");
		return 1;
	}
	retval = ext2fs_read_inline_data(fs, newfile, cmpbuf);
	if (retval) {
		com_err("test_file", retval, "While reading");
		return 1;
	}

	if (memcmp(buf, cmpbuf, BUF_LEN)) {
		printf("inline_data: read a regular file error\n");
		return 1;
	}

	retval = ext2fs_write_inline_data(fs, newfile, buf);
	if (retval) {
		printf("inline_data: write a regular file error\n");
		return 1;
	}

	retval = ext2fs_punch(fs, newfile, 0, 0, 0, ~0U);
	if (retval) {
		printf("inline_data: truncate failed\n");
		return 1;
	}

	retval = ext2fs_inline_data_check(fs, newfile);
	if (retval != 1) {
		printf("inline_data: header check failed\n");
		return 1;
	}

	ext2fs_free_mem(&buf);
	ext2fs_free_mem(&cmpbuf);

	printf("tst_inline_data(REG): OK\n");

	return 0;
}

static errcode_t test_create_parent_dir(ext2_filsys fs, ext2_ino_t *ino)
{
	const char *test_dir = "test";
	const char *dot = ".";
	errcode_t retval;
	ext2_ino_t dir, tmp;

	/* create a stub directory */
	retval = ext2fs_mkdir(fs, 11, 11, "stub");
	if (retval) {
		com_err("test_dir", retval, "while creating stub dir");
		return 1;
	}

	/* create a new empty directory with inline data */
	retval = ext2fs_mkdir(fs, 11, 0, test_dir);
	if (retval)
		return 1;

	/* lookup this new directory */
	retval = ext2fs_lookup(fs, 11, test_dir,
			       strlen(test_dir), 0, &dir);
	if (retval) {
		com_err("test_create_parent_dir", retval,
			"while looking up test dir");
		return 1;
	}

	/* lookup '.' in this new directory */
	retval = ext2fs_lookup(fs, dir, dot, strlen(dot), 0, &tmp);
	if (retval) {
		com_err("test_create_parent_dir", retval,
			"while looking up dot dir");
		return 1;
	}

	if (tmp != dir) {
		fprintf(stderr, "inline_data: looking up '.' error\n");
		return 1;
	}

	*ino = dir;
	return 0;
}

static errcode_t test_manipulate_dirs(ext2_filsys fs, ext2_ino_t parent)
{
	errcode_t retval;
	ext2_ino_t dir = 13, tmp;
	char name[PATH_MAX];
	int i;

	/*
	 * Here we only try to create 4 dirs:
	 *   4 bytes (parent inode) + 56 bytes
	 * In ext4 a dir at least need to take 12 bytes.  So it only can
	 * save 4 dirs in inode's i_block.
	 */
	for (i = 0; i < 4; i++) {
		tmp = 0;
		snprintf(name, PATH_MAX, "%d", i);
		retval = ext2fs_mkdir(fs, parent, 0, name);
		if (retval) {
			com_err("test_manipulate_dirs", retval,
				"while making dir %s", name);
			return 1;
		}

		retval = ext2fs_lookup(fs, parent, name,
				       strlen(name), 0, &tmp);
		if (retval) {
			com_err("test_manipulate_dirs", retval,
				"while looking up test dir");
			return 1;
		}

		if (tmp != dir) {
			printf("inline_data: create subdirs failed, "
			       "dir inode is %d, but now is %d\n", dir, tmp);
			return 1;
		}

		dir++;
	}

	/*
	 * XXX: In e2fsprogs the size of inline data doesn't expand from i_block
	 * space to extra space while making a new dir.  If extra space has been
	 * used while creating a new dir, extra space will be used.  So here
	 * ext2fs_mkdir() will return EXT2_ET_DIR_NO_SPACE.
	 */
	snprintf(name, PATH_MAX, "%d", i);
	retval = ext2fs_mkdir(fs, parent, 0, name);
	if (retval != EXT2_ET_DIR_NO_SPACE) {
		com_err("test_manipulate_dirs", retval,
			"while making dir %s", name);
		return 1;
	}

	retval = ext2fs_expand_dir(fs, parent);
	if (retval) {
		com_err("test_maniuplate_dirs", retval,
			"while expanding test dir");
		return 1;
	}

	retval = ext2fs_inline_data_check(fs, parent);
	if (retval != 1) {
		printf("inline_data: header check failed\n");
		return 1;
	}

	return 0;
}

/*
 * Test manipulation of directory.
 *
 * In this test case, we first try to create a test dir.  Then we will try to
 * create, lookup this dir and make sure all tests pass.
 */
static errcode_t test_dir(ext2_filsys fs)
{
	errcode_t retval;
	ext2_ino_t dir;

	retval = test_create_parent_dir(fs, &dir);
	if (retval)
		return 1;

	retval = test_manipulate_dirs(fs, dir);
	if (retval)
		return 1;

	printf("tst_inline_data(DIR): OK\n");
	return 0;
}

int main(int argc, char *argv[])
{
	struct ext2_super_block param;
	errcode_t		retval;
	ext2_filsys		fs;
	int			i;

	memset(&param, 0, sizeof(param));
	ext2fs_blocks_count_set(&param, 32768);

	retval = ext2fs_initialize("test fs", EXT2_FLAG_64BITS, &param,
				   test_io_manager, &fs);
	if (retval) {
		com_err("setup", retval,
			"While initializing filesystem");
		exit(1);
	}

	fs->super->s_feature_ro_compat |= EXT2_FEATURE_COMPAT_EXT_ATTR;
	fs->super->s_feature_incompat |= EXT4_FEATURE_INCOMPAT_INLINE_DATA;
	fs->super->s_rev_level = EXT2_DYNAMIC_REV;
	fs->super->s_inode_size = 256;

	retval = ext2fs_allocate_tables(fs);
	if (retval) {
		com_err("setup", retval,
			"while allocating tables for test filesysmte");
		exit(1);
	}

	retval = test_file(fs);
	if (retval)
		return retval;

	retval = test_dir(fs);
	if (retval)
		return retval;

	return 0;
}
#endif
