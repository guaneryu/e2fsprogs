/*
 * ext_attr.c --- extended attribute blocks
 *
 * Copyright (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
 *
 * Copyright (C) 2002 Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Library
 * General Public License, version 2.
 * %End-Header%
 */

#include "config.h"
#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <time.h>

#include "ext2_fs.h"
#include "ext2_ext_attr.h"

#include "ext2fs.h"

#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

/*
 * ext2_xattr_hash_entry()
 *
 * Compute the hash of an extended attribute.
 */
__u32 ext2fs_ext_attr_hash_entry(struct ext2_ext_attr_entry *entry, void *data)
{
	__u32 hash = 0;
	char *name = ((char *) entry) + sizeof(struct ext2_ext_attr_entry);
	int n;

	for (n = 0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - NAME_HASH_SHIFT)) ^
		       *name++;
	}

	/* The hash needs to be calculated on the data in little-endian. */
	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		__u32 *value = (__u32 *)data;
		for (n = (entry->e_value_size + EXT2_EXT_ATTR_ROUND) >>
			 EXT2_EXT_ATTR_PAD_BITS; n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8*sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       ext2fs_le32_to_cpu(*value++);
		}
	}

	return hash;
}

#undef NAME_HASH_SHIFT
#undef VALUE_HASH_SHIFT

errcode_t ext2fs_read_ext_attr3(ext2_filsys fs, blk64_t block, void *buf,
				ext2_ino_t inum)
{
	errcode_t	retval;

	retval = io_channel_read_blk64(fs->io, block, 1, buf);
	if (retval)
		return retval;

	if (!(fs->flags & EXT2_FLAG_IGNORE_CSUM_ERRORS) &&
	    !ext2fs_ext_attr_block_csum_verify(fs, inum, block, buf))
		retval = EXT2_ET_EXT_ATTR_CSUM_INVALID;

#ifdef WORDS_BIGENDIAN
	ext2fs_swap_ext_attr(buf, buf, fs->blocksize, 1);
#endif

	return retval;
}

errcode_t ext2fs_read_ext_attr2(ext2_filsys fs, blk64_t block, void *buf)
{
	return ext2fs_read_ext_attr3(fs, block, buf, 0);
}

errcode_t ext2fs_read_ext_attr(ext2_filsys fs, blk_t block, void *buf)
{
	return ext2fs_read_ext_attr2(fs, block, buf);
}

errcode_t ext2fs_write_ext_attr3(ext2_filsys fs, blk64_t block, void *inbuf,
				 ext2_ino_t inum)
{
	errcode_t	retval;
	char		*write_buf;

#ifdef WORDS_BIGENDIAN
	retval = ext2fs_get_mem(fs->blocksize, &write_buf);
	if (retval)
		return retval;
	ext2fs_swap_ext_attr(write_buf, inbuf, fs->blocksize, 1);
#else
	write_buf = (char *) inbuf;
#endif

	retval = ext2fs_ext_attr_block_csum_set(fs, inum, block,
			(struct ext2_ext_attr_header *)write_buf);
	if (retval)
		return retval;

	retval = io_channel_write_blk64(fs->io, block, 1, write_buf);
#ifdef WORDS_BIGENDIAN
	ext2fs_free_mem(&write_buf);
#endif
	if (!retval)
		ext2fs_mark_changed(fs);
	return retval;
}

errcode_t ext2fs_write_ext_attr2(ext2_filsys fs, blk64_t block, void *inbuf)
{
	return ext2fs_write_ext_attr3(fs, block, inbuf, 0);
}

errcode_t ext2fs_write_ext_attr(ext2_filsys fs, blk_t block, void *inbuf)
{
	return ext2fs_write_ext_attr2(fs, block, inbuf);
}

/*
 * This function adjusts the reference count of the EA block.
 */
errcode_t ext2fs_adjust_ea_refcount3(ext2_filsys fs, blk64_t blk,
				    char *block_buf, int adjust,
				    __u32 *newcount, ext2_ino_t inum)
{
	errcode_t	retval;
	struct ext2_ext_attr_header *header;
	char	*buf = 0;

	if ((blk >= ext2fs_blocks_count(fs->super)) ||
	    (blk < fs->super->s_first_data_block))
		return EXT2_ET_BAD_EA_BLOCK_NUM;

	if (!block_buf) {
		retval = ext2fs_get_mem(fs->blocksize, &buf);
		if (retval)
			return retval;
		block_buf = buf;
	}

	retval = ext2fs_read_ext_attr3(fs, blk, block_buf, inum);
	if (retval)
		goto errout;

	header = (struct ext2_ext_attr_header *) block_buf;
	header->h_refcount += adjust;
	if (newcount)
		*newcount = header->h_refcount;

	retval = ext2fs_write_ext_attr3(fs, blk, block_buf, inum);
	if (retval)
		goto errout;

errout:
	if (buf)
		ext2fs_free_mem(&buf);
	return retval;
}

errcode_t ext2fs_adjust_ea_refcount2(ext2_filsys fs, blk64_t blk,
				    char *block_buf, int adjust,
				    __u32 *newcount)
{
	return ext2fs_adjust_ea_refcount3(fs, blk, block_buf, adjust,
					  newcount, 0);
}

errcode_t ext2fs_adjust_ea_refcount(ext2_filsys fs, blk_t blk,
					char *block_buf, int adjust,
					__u32 *newcount)
{
	return ext2fs_adjust_ea_refcount2(fs, blk, block_buf, adjust,
					  newcount);
}

static errcode_t
ext2fs_ext_attr_check_names(struct ext2_ext_attr_entry *entry, void *end)
{
	while (!EXT2_EXT_IS_LAST_ENTRY(entry)) {
		struct ext2_ext_attr_entry *next = EXT2_EXT_ATTR_NEXT(entry);
		if ((void *)next >= end)
			return EXT2_ET_EXT_ATTR_CORRUPT;
		entry = next;
	}
	return 0;
}

static inline errcode_t
ext2fs_ext_attr_check_entry(struct ext2_ext_attr_entry *entry, size_t size)
{
	size_t value_size = entry->e_value_size;

	if (entry->e_value_block != 0 || value_size > size ||
	    entry->e_value_offs + value_size > size)
		return EXT2_ET_EXT_ATTR_CORRUPT;
	return 0;
}

errcode_t ext2fs_ext_attr_find_entry(struct ext2_ext_attr_entry **pentry,
				     int name_index, const char *name,
				     size_t size, int sorted)
{
	struct ext2_ext_attr_entry *entry;
	size_t name_len;
	int cmp = 1;

	if (name == NULL)
		return EXT2_ET_INVALID_ARGUMENT;
	name_len = strlen(name);
	for (entry = *pentry; !EXT2_EXT_IS_LAST_ENTRY(entry);
	     entry = EXT2_EXT_ATTR_NEXT(entry)) {
		cmp = name_index - entry->e_name_index;
		if (!cmp)
			cmp = name_len - entry->e_name_len;
		if (!cmp)
			cmp = memcmp(name, EXT2_EXT_ATTR_NAME(entry),
				     name_len);
		if (cmp <= 0 && (sorted || cmp == 0))
			break;
	}
	*pentry = entry;
	if (!cmp && ext2fs_ext_attr_check_entry(entry, size))
		return EXT2_ET_EXT_ATTR_CORRUPT;
	return cmp ? ENODATA : 0;
}

errcode_t ext2fs_ext_attr_ibody_find(ext2_filsys fs,
				     struct ext2_inode_large *inode,
				     struct ext2_ext_attr_info *i,
				     struct ext2_ext_attr_search *s)
{
	struct ext2_ext_attr_ibody_header *header;
	errcode_t error;

	if (inode->i_extra_isize == 0)
		return 0;
	header = IHDR(inode);
	s->base = s->first = IFIRST(header);
	s->here = s->first;
	s->end = (char *)inode + EXT2_INODE_SIZE(fs->super);

	error = ext2fs_ext_attr_check_names(IFIRST(header), s->end);
	if (error)
		return error;
	/* Find the named attribute. */
	error = ext2fs_ext_attr_find_entry(&s->here, i->name_index,
					   i->name, (char *)s->end -
					   (char *)s->base, 0);
	if (error && error != ENODATA)
		return error;
	s->not_found = error;
	return 0;
}

errcode_t ext2fs_ext_attr_set_entry(struct ext2_ext_attr_info *i,
				    struct ext2_ext_attr_search *s)
{
	struct ext2_ext_attr_entry *last;
	size_t freesize, min_offs = (char *)s->end - (char *)s->base;
	size_t name_len = strlen(i->name);

	/* Compute min_offs and last. */
	last = s->first;
	for (; !EXT2_EXT_IS_LAST_ENTRY(last); last = EXT2_EXT_ATTR_NEXT(last)) {
		if (!last->e_value_block && last->e_value_size) {
			size_t offs = last->e_value_offs;
			if (offs < min_offs)
				min_offs = offs;
		}
	}
	freesize = min_offs - ((char *)last - (char *)s->base) - sizeof(__u32);
	if (!s->not_found) {
		if (!s->here->e_value_block && s->here->e_value_size) {
			size_t size = s->here->e_value_size;
			freesize += EXT2_EXT_ATTR_SIZE(size);
		}
		freesize += EXT2_EXT_ATTR_LEN(name_len);
	}
	if (i->value) {
		if (freesize < EXT2_EXT_ATTR_SIZE(i->value_len) ||
		    freesize < EXT2_EXT_ATTR_LEN(name_len) +
			   EXT2_EXT_ATTR_SIZE(i->value_len))
			return ENOSPC;
	}

	if (i->value && s->not_found) {
		/* Insert the new name. */
		size_t size = EXT2_EXT_ATTR_LEN(name_len);
		size_t rest = (char *)last - (char *)s->here + sizeof(__u32);
		memmove((char *)s->here + size, s->here, rest);
		memset(s->here, 0, size);
		s->here->e_name_index = i->name_index;
		s->here->e_name_len = name_len;
		memcpy(EXT2_EXT_ATTR_NAME(s->here), i->name, name_len);
	} else {
		if (!s->here->e_value_block && s->here->e_value_size) {
			char *first_val = (char *) s->base + min_offs;
			size_t offs = s->here->e_value_offs;
			char *val = (char *)s->base + offs;
			size_t size = EXT2_EXT_ATTR_SIZE(s->here->e_value_size);

			if (i->value && size == EXT2_EXT_ATTR_SIZE(i->value_len)) {
				/* The old and the new value have the same
				 * size. Just replace. */
				s->here->e_value_size = i->value_len;
				if (i->value == EXT2_ZERO_EXT_ATTR_VALUE) {
					memset(val, 0, size);
				} else {
					memset(val + size - EXT2_EXT_ATTR_PAD, 0,
						EXT2_EXT_ATTR_PAD);
					memcpy(val, i->value, i->value_len);
				}
				return 0;
			}

			/* Remove the old value. */
			memmove(first_val + size, first_val, val - first_val);
			memset(first_val, 0, size);
			s->here->e_value_size = 0;
			s->here->e_value_offs = 0;
			min_offs += size;

			/* Adjust all value offsets. */
			last = s->first;
			while (!EXT2_EXT_IS_LAST_ENTRY(last)) {
				size_t o = last->e_value_offs;
				if (!last->e_value_block &&
				    last->e_value_size && o < offs)
					last->e_value_offs = o + size;
				last = EXT2_EXT_ATTR_NEXT(last);
			}
		}
		if (!i->value) {
			/* Remove the old name. */
			size_t size = EXT2_EXT_ATTR_LEN(name_len);
			last = (struct ext2_ext_attr_entry *)last - size;
			memmove(s->here, (char *)s->here + size,
				(char *)last - (char *)s->here + sizeof(__u32));
			memset(last, 0, size);
		}
	}

	if (i->value) {
		/* Insert the new value. */
		s->here->e_value_size = i->value_len;
		if (i->value_len) {
			size_t size = EXT2_EXT_ATTR_SIZE(i->value_len);
			char *val = (char *)s->base + min_offs - size;
			s->here->e_value_offs = min_offs - size;
			if (i->value == EXT2_ZERO_EXT_ATTR_VALUE) {
				memset(val, 0, size);
			} else {
				memset(val + size - EXT2_EXT_ATTR_PAD, 0,
					EXT2_EXT_ATTR_PAD);
				memcpy(val, i->value, i->value_len);
			}
		}
	}
	return 0;
}
