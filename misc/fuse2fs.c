/*
 * fuse2fs.c - FUSE server for e2fsprogs.
 *
 * Copyright (C) 2013 Oracle.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 29
#define _GNU_SOURCE
#include <pthread.h>
#ifdef __linux__
# include <linux/fs.h>
# include <linux/falloc.h>
# include <linux/xattr.h>
#endif
#include <sys/ioctl.h>
#include <unistd.h>
#include <fuse.h>
#include "ext2fs/ext2fs.h"
#include "ext2fs/ext2_fs.h"

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 8)
# ifdef _IOR
#  ifdef _IOW
#   define SUPPORT_I_FLAGS
#  endif
# endif
#endif

#ifdef FALLOC_FL_KEEP_SIZE
# define FL_KEEP_SIZE_FLAG FALLOC_FL_KEEP_SIZE
#else
# define FL_KEEP_SIZE_FLAG (0)
#endif

#ifdef FALLOC_FL_PUNCH_HOLE
# define FL_PUNCH_HOLE_FLAG FALLOC_FL_PUNCH_HOLE
#else
# define FL_PUNCH_HOLE_FLAG (0)
#endif

/*
 * ext2_file_t contains a struct inode, so we can't leave files open.
 * Use this as a proxy instead.
 */
struct fuse2fs_file_handle {
	ext2_ino_t ino;
	int open_flags;
};

/* Main program context */
struct fuse2fs {
	ext2_filsys fs;
	pthread_mutex_t bfl;
	int panic_on_error;
	FILE *err_fp;
	unsigned int next_generation;
};

static int __translate_error(ext2_filsys fs, errcode_t err, ext2_ino_t ino,
			     const char *file, int line);
#define translate_error(fs, ino, err) __translate_error((fs), (err), (ino), \
			__FILE__, __LINE__)

/* for macosx */
#ifndef W_OK
#  define W_OK 2
#endif

#ifndef R_OK
#  define R_OK 4
#endif

#define EXT4_EPOCH_BITS 2
#define EXT4_EPOCH_MASK ((1 << EXT4_EPOCH_BITS) - 1)
#define EXT4_NSEC_MASK  (~0UL << EXT4_EPOCH_BITS)

/*
 * Extended fields will fit into an inode if the filesystem was formatted
 * with large inodes (-I 256 or larger) and there are not currently any EAs
 * consuming all of the available space. For new inodes we always reserve
 * enough space for the kernel's known extended fields, but for inodes
 * created with an old kernel this might not have been the case. None of
 * the extended inode fields is critical for correct filesystem operation.
 * This macro checks if a certain field fits in the inode. Note that
 * inode-size = GOOD_OLD_INODE_SIZE + i_extra_isize
 */
#define EXT4_FITS_IN_INODE(ext4_inode, field)		\
	((offsetof(typeof(*ext4_inode), field) +	\
	  sizeof((ext4_inode)->field))			\
	<= (EXT2_GOOD_OLD_INODE_SIZE +			\
	    (ext4_inode)->i_extra_isize))		\

static inline __u32 ext4_encode_extra_time(const struct timespec *time)
{
	return (sizeof(time->tv_sec) > 4 ?
		(time->tv_sec >> 32) & EXT4_EPOCH_MASK : 0) |
	       ((time->tv_nsec << EXT4_EPOCH_BITS) & EXT4_NSEC_MASK);
}

static inline void ext4_decode_extra_time(struct timespec *time, __u32 extra)
{
	if (sizeof(time->tv_sec) > 4)
		time->tv_sec |= (__u64)((extra) & EXT4_EPOCH_MASK) << 32;
	time->tv_nsec = ((extra) & EXT4_NSEC_MASK) >> EXT4_EPOCH_BITS;
}

#define EXT4_INODE_SET_XTIME(xtime, timespec, raw_inode)		       \
do {									       \
	(raw_inode)->xtime = (timespec)->tv_sec;			       \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime ## _extra))		       \
		(raw_inode)->xtime ## _extra =				       \
				ext4_encode_extra_time(timespec);	       \
} while (0)

#define EXT4_EINODE_SET_XTIME(xtime, timespec, raw_inode)		       \
do {									       \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime))			       \
		(raw_inode)->xtime = (timespec)->tv_sec;		       \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime ## _extra))		       \
		(raw_inode)->xtime ## _extra =				       \
				ext4_encode_extra_time(timespec);	       \
} while (0)

#define EXT4_INODE_GET_XTIME(xtime, timespec, raw_inode)		       \
do {									       \
	(timespec)->tv_sec = (signed)((raw_inode)->xtime);		       \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime ## _extra))		       \
		ext4_decode_extra_time((timespec),			       \
				       raw_inode->xtime ## _extra);	       \
	else								       \
		(timespec)->tv_nsec = 0;				       \
} while (0)

#define EXT4_EINODE_GET_XTIME(xtime, timespec, raw_inode)		       \
do {									       \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime))			       \
		(timespec)->tv_sec =					       \
			(signed)((raw_inode)->xtime);			       \
	if (EXT4_FITS_IN_INODE(raw_inode, xtime ## _extra))		       \
		ext4_decode_extra_time((timespec),			       \
				       raw_inode->xtime ## _extra);	       \
	else								       \
		(timespec)->tv_nsec = 0;				       \
} while (0)

static void get_now(struct timespec *now)
{
#ifdef CLOCK_REALTIME
	if (!clock_gettime(CLOCK_REALTIME, now))
		return;
#endif

	now->tv_sec = time(NULL);
	now->tv_nsec = 0;
}

static void increment_version(struct ext2_inode_large *inode)
{
	__u64 ver;

	ver = inode->osd1.linux1.l_i_version;
	if (EXT4_FITS_IN_INODE(inode, i_version_hi))
		ver |= (__u64)inode->i_version_hi << 32;
	ver++;
	inode->osd1.linux1.l_i_version = ver;
	if (EXT4_FITS_IN_INODE(inode, i_version_hi))
		inode->i_version_hi = ver >> 32;
}

static void init_times(struct ext2_inode_large *inode)
{
	struct timespec now;

	get_now(&now);
	EXT4_INODE_SET_XTIME(i_atime, &now, inode);
	EXT4_INODE_SET_XTIME(i_ctime, &now, inode);
	EXT4_INODE_SET_XTIME(i_mtime, &now, inode);
	EXT4_EINODE_SET_XTIME(i_crtime, &now, inode);
	increment_version(inode);
}

static int update_ctime(ext2_filsys fs, ext2_ino_t ino,
			struct ext2_inode_large *pinode)
{
	errcode_t err;
	struct timespec now;
	struct ext2_inode_large inode;

	get_now(&now);

	/* If user already has a inode buffer, just update that */
	if (pinode) {
		increment_version(pinode);
		EXT4_INODE_SET_XTIME(i_ctime, &now, pinode);
		return 0;
	}

	/* Otherwise we have to read-modify-write the inode */
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	increment_version(&inode);
	EXT4_INODE_SET_XTIME(i_ctime, &now, &inode);

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	return 0;
}

static int update_atime(ext2_filsys fs, ext2_ino_t ino)
{
	errcode_t err;
	struct ext2_inode_large inode, *pinode;
	struct timespec atime, mtime, now;

	if (!(fs->flags & EXT2_FLAG_RW))
		return 0;
	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	pinode = &inode;
	EXT4_INODE_GET_XTIME(i_atime, &atime, pinode);
	EXT4_INODE_GET_XTIME(i_mtime, &mtime, pinode);
	get_now(&now);
	/*
	 * If atime is newer than mtime and atime hasn't been updated in more
	 * than a day, skip the atime update.  Same idea as Linux "relatime".
	 */
	if (atime.tv_sec >= mtime.tv_sec && atime.tv_sec >= now.tv_sec - 86400)
		return 0;
	EXT4_INODE_SET_XTIME(i_atime, &now, &inode);

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	return 0;
}

static int update_mtime(ext2_filsys fs, ext2_ino_t ino)
{
	errcode_t err;
	struct ext2_inode_large inode;
	struct timespec now;

	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	get_now(&now);
	EXT4_INODE_SET_XTIME(i_mtime, &now, &inode);
	EXT4_INODE_SET_XTIME(i_ctime, &now, &inode);
	increment_version(&inode);

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	return 0;
}

static int ext2_file_type(unsigned int mode)
{
	if (LINUX_S_ISREG(mode))
		return EXT2_FT_REG_FILE;

	if (LINUX_S_ISDIR(mode))
		return EXT2_FT_DIR;

	if (LINUX_S_ISCHR(mode))
		return EXT2_FT_CHRDEV;

	if (LINUX_S_ISBLK(mode))
		return EXT2_FT_BLKDEV;

	if (LINUX_S_ISLNK(mode))
		return EXT2_FT_SYMLINK;

	if (LINUX_S_ISFIFO(mode))
		return EXT2_FT_FIFO;

	if (LINUX_S_ISSOCK(mode))
		return EXT2_FT_SOCK;

	return 0;
}

static int fs_writeable(ext2_filsys fs)
{
	return (fs->flags & EXT2_FLAG_RW) && (fs->super->s_error_count == 0);
}

static int __check_access(struct fuse_context *ctxt, ext2_filsys fs,
			  ext2_ino_t ino, int mask, int ignore_flags)
{
	errcode_t err;
	struct ext2_inode inode;
	mode_t perms;

	/* no writing to read-only or broken fs */
	if ((mask & W_OK) && !fs_writeable(fs))
		return -EROFS;

	err = ext2fs_read_inode(fs, ino, &inode);
	if (err)
		return translate_error(fs, ino, err);

	/* existence check */
	if (mask == 0)
		return 0;

	/* is immutable? */
	if (!ignore_flags && (mask & W_OK) &&
	    (inode.i_flags & EXT2_IMMUTABLE_FL))
		return -EPERM;

	perms = inode.i_mode & 0777;

	/* always allow root */
	if (ctxt->uid == 0)
		return 0;

	/* allow owner, if perms match */
	if (inode.i_uid == ctxt->uid) {
		if ((mask << 6) & perms)
			return 0;
		return -EPERM;
	}

	/* allow group, if perms match */
	if (inode.i_gid == ctxt->gid) {
		if ((mask << 3) & perms)
			return 0;
		return -EPERM;
	}

	/* otherwise check other */
	if (mask & perms)
		return 0;
	return -EPERM;
}

static int check_inum_access(struct fuse_context *ctxt, ext2_filsys fs,
			     ext2_ino_t ino, int mask)
{
	return __check_access(ctxt, fs, ino, mask, 0);
}

static int check_flags_access(struct fuse_context *ctxt, ext2_filsys fs,
			      ext2_ino_t ino, int mask)
{
	return __check_access(ctxt, fs, ino, mask, 1);
}

static void op_destroy(void *p)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;

	if (fs->flags & EXT2_FLAG_RW) {
		fs->super->s_state |= EXT2_VALID_FS;
		if (fs->super->s_error_count)
			fs->super->s_state |= EXT2_ERROR_FS;
		ext2fs_mark_super_dirty(fs);
		err = ext2fs_set_gdt_csum(fs);
		if (err)
			translate_error(fs, 0, err);
	}
}

static void *op_init(struct fuse_conn_info *conn)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;

	if (fs->flags & EXT2_FLAG_RW) {
		fs->super->s_mnt_count++;
		fs->super->s_mtime = time(NULL);
		fs->super->s_state &= ~EXT2_VALID_FS;
		ext2fs_mark_super_dirty(fs);
		err = ext2fs_flush2(fs, 0);
		if (err)
			translate_error(fs, 0, err);
	}
	return ff;
}

static int stat_inode(ext2_filsys fs, ext2_ino_t ino, struct stat *statbuf)
{
	struct ext2_inode_large inode;
	dev_t fakedev = 0;
	errcode_t err;
	int ret = 0;

	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err)
		return translate_error(fs, ino, err);

	memcpy(&fakedev, fs->super->s_uuid, sizeof(fakedev));
	statbuf->st_dev = fakedev;
	statbuf->st_ino = ino;
	statbuf->st_mode = inode.i_mode;
	statbuf->st_nlink = inode.i_links_count;
	statbuf->st_uid = inode.i_uid;
	statbuf->st_gid = inode.i_gid;
	statbuf->st_size = inode.i_size;
	statbuf->st_blksize = fs->blocksize;
	statbuf->st_blocks = inode.i_blocks;
	statbuf->st_atime = inode.i_atime;
	statbuf->st_mtime = inode.i_mtime;
	statbuf->st_ctime = inode.i_ctime;
	if (LINUX_S_ISCHR(inode.i_mode) ||
	    LINUX_S_ISBLK(inode.i_mode)) {
		if (inode.i_block[0])
			statbuf->st_rdev = inode.i_block[0];
		else
			statbuf->st_rdev = inode.i_block[1];
	}

	return ret;
}

static int op_getattr(const char *path, struct stat *statbuf)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}
	ret = stat_inode(fs, ino, statbuf);
out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_readlink(const char *path, char *buf, size_t len)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t ino;
	struct ext2_inode inode;
	unsigned int got;
	ext2_file_t file;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	err = ext2fs_read_inode(fs, ino, &inode);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	if (!LINUX_S_ISLNK(inode.i_mode)) {
		ret = -EINVAL;
		goto out;
	}

	len--;
	if (inode.i_size < len)
		len = inode.i_size;
	if (ext2fs_inode_data_blocks2(fs, &inode)) {
		/* big symlink */

		err = ext2fs_file_open(fs, ino, 0, &file);
		if (err) {
			ret = translate_error(fs, ino, err);
			goto out;
		}

		err = ext2fs_file_read(file, buf, len, &got);
		if (err || got != len) {
			ext2fs_file_close(file);
			ret = translate_error(fs, ino, err);
			goto out;
		}

		err = ext2fs_file_close(file);
		if (err) {
			ret = translate_error(fs, ino, err);
			goto out;
		}
	} else
		/* inline symlink */
		memcpy(buf, (char *)inode.i_block, len);
	buf[len] = 0;

	if (fs_writeable(fs)) {
		ret = update_atime(fs, ino);
		if (ret)
			goto out;
	}

out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_mknod(const char *path, mode_t mode, dev_t dev)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	ext2_ino_t parent, child;
	char *temp_path = strdup(path);
	errcode_t err;
	char *node_name, a;
	int filetype;
	struct ext2_inode_large inode;
	int ret = 0;

	if (!temp_path) {
		ret = -ENOMEM;
		goto out;
	}
	node_name = strrchr(temp_path, '/');
	if (!node_name) {
		ret = -ENOMEM;
		goto out;
	}
	node_name++;
	a = *node_name;
	*node_name = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
			   &parent);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	ret = check_inum_access(ctxt, fs, parent, W_OK);
	if (ret)
		goto out2;

	*node_name = a;

	if (LINUX_S_ISCHR(mode))
		filetype = EXT2_FT_CHRDEV;
	else if (LINUX_S_ISBLK(mode))
		filetype = EXT2_FT_BLKDEV;
	else if (LINUX_S_ISFIFO(mode))
		filetype = EXT2_FT_FIFO;
	else {
		ret = -EINVAL;
		goto out2;
	}

	err = ext2fs_new_inode(fs, parent, mode, 0, &child);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	err = ext2fs_link(fs, parent, node_name, child, filetype);
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, parent);
		if (err) {
			ret = translate_error(fs, parent, err);
			goto out2;
		}

		err = ext2fs_link(fs, parent, node_name, child,
				     filetype);
	}
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out2;
	}

	ret = update_mtime(fs, parent);
	if (ret)
		goto out2;

	memset(&inode, 0, sizeof(inode));
	inode.i_mode = mode;

	if (dev & ~0xFFFF)
		inode.i_block[1] = dev;
	else
		inode.i_block[0] = dev;
	inode.i_links_count = 1;
	inode.i_extra_isize = sizeof(struct ext2_inode_large) -
		EXT2_GOOD_OLD_INODE_SIZE;

	err = ext2fs_write_new_inode(fs, child, (struct ext2_inode *)&inode);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	inode.i_generation = ff->next_generation++;
	init_times(&inode);
	err = ext2fs_write_inode_full(fs, child, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	ext2fs_inode_alloc_stats2(fs, child, 1, 0);

	err = ext2fs_flush2(fs, EXT2_FLAG_FLUSH_NO_SYNC);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

out2:
	pthread_mutex_unlock(&ff->bfl);
out:
	free(temp_path);
	return ret;
}

static int op_mkdir(const char *path, mode_t mode)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	ext2_ino_t parent, child;
	char *temp_path = strdup(path);
	errcode_t err;
	char *node_name, a;
	struct ext2_inode_large inode;
	char *block;
	blk64_t blk;
	int ret = 0;

	if (!temp_path) {
		ret = -ENOMEM;
		goto out;
	}
	node_name = strrchr(temp_path, '/');
	if (!node_name) {
		ret = -ENOMEM;
		goto out;
	}
	node_name++;
	a = *node_name;
	*node_name = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
			   &parent);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	ret = check_inum_access(ctxt, fs, parent, W_OK);
	if (ret)
		goto out2;

	*node_name = a;

	err = ext2fs_mkdir(fs, parent, 0, node_name);
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, parent);
		if (err) {
			ret = translate_error(fs, parent, err);
			goto out2;
		}

		err = ext2fs_mkdir(fs, parent, 0, node_name);
	}
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out2;
	}

	ret = update_mtime(fs, parent);
	if (ret)
		goto out2;

	/* Still have to update the uid/gid of the dir */
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
			   &child);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	err = ext2fs_read_inode_full(fs, child, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	inode.i_uid = ctxt->uid;
	inode.i_gid = ctxt->gid;
	inode.i_generation = ff->next_generation++;

	err = ext2fs_write_inode_full(fs, child, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	/* Rewrite the directory block checksum, having set i_generation */
	if (!EXT2_HAS_RO_COMPAT_FEATURE(fs->super,
					EXT4_FEATURE_RO_COMPAT_METADATA_CSUM))
		goto out2;
	err = ext2fs_new_dir_block(fs, child, parent, &block);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}
	err = ext2fs_bmap2(fs, child, (struct ext2_inode *)&inode, NULL, 0, 0,
			   NULL, &blk);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out3;
	}
	err = ext2fs_write_dir_block4(fs, blk, block, 0, child);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out3;
	}

out3:
	ext2fs_free_mem(&block);
out2:
	pthread_mutex_unlock(&ff->bfl);
out:
	free(temp_path);
	return ret;
}

static int unlink_file_by_name(struct fuse_context *ctxt, ext2_filsys fs,
			       const char *path)
{
	errcode_t err;
	ext2_ino_t dir;
	char *filename = strdup(path);
	char *base_name;
	int ret;

	base_name = strrchr(filename, '/');
	if (base_name) {
		*base_name++ = '\0';
		err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, filename,
				   &dir);
		if (err) {
			free(filename);
			return translate_error(fs, 0, err);
		}
	} else {
		dir = EXT2_ROOT_INO;
		base_name = filename;
	}

	ret = check_inum_access(ctxt, fs, dir, W_OK);
	if (ret) {
		free(filename);
		return ret;
	}

	err = ext2fs_unlink(fs, dir, base_name, 0, 0);
	free(filename);
	if (err)
		return translate_error(fs, dir, err);

	return update_mtime(fs, dir);
}

static int release_blocks_proc(ext2_filsys fs, blk64_t *blocknr,
			       e2_blkcnt_t blockcnt EXT2FS_ATTR((unused)),
			       blk64_t ref_block EXT2FS_ATTR((unused)),
			       int ref_offset EXT2FS_ATTR((unused)),
			       void *private EXT2FS_ATTR((unused)))
{
	blk64_t blk = *blocknr;

	if (blk % EXT2FS_CLUSTER_RATIO(fs) == 0)
		ext2fs_block_alloc_stats2(fs, *blocknr, -1);
	return 0;
}

static int remove_inode(struct fuse2fs *ff, ext2_ino_t ino)
{
	ext2_filsys fs = ff->fs;
	errcode_t err;
	struct ext2_inode_large inode;
	int ret = 0;

	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	switch (inode.i_links_count) {
	case 0:
		return 0; /* XXX: already done? */
	case 1:
		inode.i_links_count--;
		inode.i_dtime = fs->now ? fs->now : time(0);
		break;
	default:
		inode.i_links_count--;
	}

	ret = update_ctime(fs, ino, &inode);
	if (ret)
		goto out;

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	if (inode.i_links_count)
		goto out;

	if (ext2fs_inode_has_valid_blocks2(fs, (struct ext2_inode *)&inode))
		ext2fs_block_iterate3(fs, ino, BLOCK_FLAG_READ_ONLY, NULL,
				      release_blocks_proc, NULL);
	ext2fs_inode_alloc_stats2(fs, ino, -1,
				  LINUX_S_ISDIR(inode.i_mode));

	err = ext2fs_flush2(fs, EXT2_FLAG_FLUSH_NO_SYNC);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

out:
	return ret;
}

static int __op_unlink(const char *path)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, W_OK);
	if (ret)
		goto out;

	ret = unlink_file_by_name(ctxt, fs, path);
	if (ret)
		goto out;

	ret = remove_inode(ff, ino);
	if (ret)
		goto out;
out:
	return ret;
}

static int op_unlink(const char *path)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	int ret;

	pthread_mutex_lock(&ff->bfl);
	ret = __op_unlink(path);
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

struct rd_struct {
	ext2_ino_t	parent;
	int		empty;
};

static int rmdir_proc(ext2_ino_t dir EXT2FS_ATTR((unused)),
		      int	entry EXT2FS_ATTR((unused)),
		      struct ext2_dir_entry *dirent,
		      int	offset EXT2FS_ATTR((unused)),
		      int	blocksize EXT2FS_ATTR((unused)),
		      char	*buf EXT2FS_ATTR((unused)),
		      void	*private)
{
	struct rd_struct *rds = (struct rd_struct *) private;

	if (dirent->inode == 0)
		return 0;
	if (((dirent->name_len & 0xFF) == 1) && (dirent->name[0] == '.'))
		return 0;
	if (((dirent->name_len & 0xFF) == 2) && (dirent->name[0] == '.') &&
	    (dirent->name[1] == '.')) {
		rds->parent = dirent->inode;
		return 0;
	}
	rds->empty = 0;
	return 0;
}

static int op_rmdir(const char *path)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	ext2_ino_t child;
	errcode_t err;
	struct ext2_inode inode;
	struct rd_struct rds;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &child);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, child, W_OK);
	if (ret)
		goto out;

	rds.parent = 0;
	rds.empty = 1;

	err = ext2fs_dir_iterate2(fs, child, 0, 0, rmdir_proc, &rds);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out;
	}

	if (rds.empty == 0) {
		ret = -ENOTEMPTY;
		goto out;
	}

	ret = unlink_file_by_name(ctxt, fs, path);
	if (ret)
		goto out;
	/* Directories have to be "removed" twice. */
	ret = remove_inode(ff, child);
	if (ret)
		goto out;
	ret = remove_inode(ff, child);
	if (ret)
		goto out;

	if (rds.parent) {
		err = ext2fs_read_inode(fs, rds.parent, &inode);
		if (err) {
			ret = translate_error(fs, rds.parent, err);
			goto out;
		}
		if (inode.i_links_count > 1)
			inode.i_links_count--;
		ret = update_mtime(fs, rds.parent);
		if (ret)
			goto out;
		err = ext2fs_write_inode(fs, rds.parent, &inode);
		if (err) {
			ret = translate_error(fs, rds.parent, err);
			goto out;
		}
	}

out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_symlink(const char *src, const char *dest)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	ext2_ino_t parent, child;
	char *temp_path = strdup(dest);
	errcode_t err;
	char *node_name, a;
	struct ext2_inode_large inode;
	int len = strlen(src);
	int ret = 0;

	if (!temp_path) {
		ret = -ENOMEM;
		goto out;
	}
	node_name = strrchr(temp_path, '/');
	if (!node_name) {
		ret = -ENOMEM;
		goto out;
	}
	node_name++;
	a = *node_name;
	*node_name = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
			   &parent);
	*node_name = a;
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	ret = check_inum_access(ctxt, fs, parent, W_OK);
	if (ret)
		goto out2;


	/* Create symlink */
	err = ext2fs_symlink(fs, parent, 0, node_name, (char *)src);
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out2;
	}

	/* Update parent dir's mtime */
	ret = update_mtime(fs, parent);
	if (ret)
		goto out2;

	/* Still have to update the uid/gid of the symlink */
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
			   &child);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	err = ext2fs_read_inode_full(fs, child, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	inode.i_uid = ctxt->uid;
	inode.i_gid = ctxt->gid;
	inode.i_generation = ff->next_generation++;

	err = ext2fs_write_inode_full(fs, child, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}
out2:
	pthread_mutex_unlock(&ff->bfl);
out:
	free(temp_path);
	return ret;
}

static int op_rename(const char *from, const char *to)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t from_ino, to_ino, to_dir_ino, from_dir_ino;
	char *temp_to = NULL, *temp_from = NULL;
	char *cp, a;
	struct ext2_inode from_inode;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, from, &from_ino);
	if (err || from_ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, to, &to_ino);
	if (err && err != EXT2_ET_FILE_NOT_FOUND) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	if (err == EXT2_ET_FILE_NOT_FOUND)
		to_ino = 0;

	/* Already the same file? */
	if (to_ino != 0 && to_ino == from_ino) {
		ret = 0;
		goto out;
	}

	temp_to = strdup(to);
	if (!temp_to) {
		ret = -ENOMEM;
		goto out;
	}

	temp_from = strdup(from);
	if (!temp_from) {
		ret = -ENOMEM;
		goto out2;
	}

	/* Find parent dir of the source and check write access */
	cp = strrchr(temp_from, '/');
	if (!cp) {
		ret = -EINVAL;
		goto out2;
	}

	a = *(cp + 1);
	*(cp + 1) = 0;
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_from,
			   &from_dir_ino);
	*(cp + 1) = a;
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}
	if (from_dir_ino == 0) {
		ret = -ENOENT;
		goto out2;
	}

	ret = check_inum_access(ctxt, fs, from_dir_ino, W_OK);
	if (ret)
		goto out2;

	/* Find parent dir of the destination and check write access */
	cp = strrchr(temp_to, '/');
	if (!cp) {
		ret = -EINVAL;
		goto out2;
	}

	a = *(cp + 1);
	*(cp + 1) = 0;
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_to,
			   &to_dir_ino);
	*(cp + 1) = a;
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}
	if (to_dir_ino == 0) {
		ret = -ENOENT;
		goto out2;
	}

	ret = check_inum_access(ctxt, fs, to_dir_ino, W_OK);
	if (ret)
		goto out2;

	/* Get ready to do the move */
	err = ext2fs_read_inode(fs, from_ino, &from_inode);
	if (err) {
		ret = translate_error(fs, from_ino, err);
		goto out2;
	}

	/* If the target exists, unlink it first */
	if (to_ino != 0) {
		ret = __op_unlink(to);
		if (ret)
			goto out2;
	}

	/* Link in the new file */
	err = ext2fs_link(fs, to_dir_ino, cp + 1, from_ino,
			  ext2_file_type(from_inode.i_mode));
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, to_dir_ino);
		if (err) {
			ret = translate_error(fs, to_dir_ino, err);
			goto out2;
		}

		err = ext2fs_link(fs, to_dir_ino, cp + 1, from_ino,
				     ext2_file_type(from_inode.i_mode));
	}
	if (err) {
		ret = translate_error(fs, to_dir_ino, err);
		goto out2;
	}

	ret = update_mtime(fs, to_dir_ino);
	if (ret)
		goto out2;

	/* Remove the old file */
	ret = unlink_file_by_name(ctxt, fs, from);
	if (ret)
		goto out2;

	/* Flush the whole mess out */
	err = ext2fs_flush2(fs, 0);
	if (err)
		ret = translate_error(fs, 0, err);

out2:
	free(temp_from);
	free(temp_to);
out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_link(const char *src, const char *dest)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	char *temp_path = strdup(dest);
	errcode_t err;
	char *node_name, a;
	ext2_ino_t parent, ino;
	struct ext2_inode_large inode;
	int ret = 0;

	if (!temp_path) {
		ret = -ENOMEM;
		goto out;
	}
	node_name = strrchr(temp_path, '/');
	if (!node_name) {
		ret = -ENOMEM;
		goto out;
	}
	node_name++;
	a = *node_name;
	*node_name = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
			   &parent);
	*node_name = a;
	if (err) {
		err = -ENOENT;
		goto out2;
	}

	ret = check_inum_access(ctxt, fs, parent, W_OK);
	if (ret)
		goto out2;


	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, src, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	inode.i_links_count++;
	ret = update_ctime(fs, ino, &inode);
	if (ret)
		goto out2;

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	err = ext2fs_link(fs, parent, node_name, ino,
			  ext2_file_type(inode.i_mode));
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, parent);
		if (err) {
			ret = translate_error(fs, parent, err);
			goto out2;
		}

		err = ext2fs_link(fs, parent, node_name, ino,
				     ext2_file_type(inode.i_mode));
	}
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out2;
	}

	ret = update_mtime(fs, parent);
	if (ret)
		goto out;

out2:
	pthread_mutex_unlock(&ff->bfl);
out:
	free(temp_path);
	return ret;
}

static int op_chmod(const char *path, mode_t mode)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t ino;
	struct ext2_inode_large inode;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	/* XXX: Fails if uid matches but u-w */
	ret = check_inum_access(ctxt, fs, ino, W_OK);
	if (ret)
		goto out;

	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	inode.i_mode &= ~0xFFF;
	inode.i_mode |= mode & 0xFFF;
	ret = update_ctime(fs, ino, &inode);
	if (ret)
		goto out;

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_chown(const char *path, uid_t owner, gid_t group)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t ino;
	struct ext2_inode_large inode;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, W_OK);
	if (ret)
		goto out;

	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	inode.i_uid = owner;
	inode.i_gid = group;
	ret = update_ctime(fs, ino, &inode);
	if (ret)
		goto out;

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_truncate(const char *path, off_t len)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t ino;
	ext2_file_t file;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, W_OK);
	if (ret)
		goto out;

	err = ext2fs_file_open(fs, ino, EXT2_FILE_WRITE, &file);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	err = ext2fs_file_set_size2(file, len);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

out2:
	err = ext2fs_file_close(file);
	if (err && !ret) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	if (!ret)
		ret = update_mtime(fs, ino);

out:
	pthread_mutex_unlock(&ff->bfl);
	return err;
}

static int __op_open(const char *path, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t ino;
	struct fuse2fs_file_handle *file;
	int check, ret = 0;

	file = calloc(1, sizeof(*file));
	if (!file)
		return -ENOMEM;

	file->open_flags = 0;
	if (fp->flags & (O_RDWR | O_WRONLY))
		file->open_flags |= EXT2_FILE_WRITE;
	if (fp->flags & O_CREAT)
		file->open_flags |= EXT2_FILE_CREATE;

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &file->ino);
	if (err || file->ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	check = R_OK;
	if (file->open_flags & EXT2_FILE_WRITE)
		check |= W_OK;
	ret = check_inum_access(ctxt, fs, file->ino, check);
	if (ret)
		goto out;
	fp->fh = (uint64_t)file;

out:
	if (ret)
		free(file);
	return ret;
}

static int op_open(const char *path, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	int ret;

	pthread_mutex_lock(&ff->bfl);
	ret = __op_open(path, fp);
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_read(const char *path, char *buf, size_t len, off_t offset,
		     struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	ext2_file_t efp;
	errcode_t err;
	unsigned int got;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_file_open(fs, fh->ino, fh->open_flags, &efp);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_llseek(efp, offset, SEEK_SET, NULL);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_read(efp, buf, len, &got);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_close(efp);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	if (fs_writeable(fs)) {
		ret = update_atime(fs, fh->ino);
		if (ret)
			goto out;
	}
out:
	pthread_mutex_unlock(&ff->bfl);
	return got ? got : ret;
}

static int op_write(const char *path, const char *buf, size_t len, off_t offset,
		      struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	ext2_file_t efp;
	errcode_t err;
	unsigned int got;
	__u64 fsize;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (!fs_writeable(fs)) {
		ret = -EROFS;
		goto out;
	}

	err = ext2fs_file_open(fs, fh->ino, fh->open_flags, &efp);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_llseek(efp, offset, SEEK_SET, NULL);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_write(efp, buf, len, &got);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_flush(efp);
	if (err) {
		got = 0;
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	/*
	 * Apparently ext2fs_file_write will dirty the inode (to allocate
	 * blocks) without bothering to write out the inode, so change the
	 * file size *after* the write, because changing the size forces
	 * the inode out to disk.
	 */
	err = ext2fs_file_get_lsize(efp, &fsize);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}
	if (offset + len > fsize) {
		fsize = offset + len;
		err = ext2fs_file_set_size2(efp, fsize);
		if (err) {
			ret = translate_error(fs, fh->ino, err);
			goto out;
		}
	}

	err = ext2fs_file_close(efp);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	ret = update_mtime(fs, fh->ino);
	if (ret)
		goto out;

out:
	pthread_mutex_unlock(&ff->bfl);
	return got ? got : ret;
}

static int op_flush(const char *path, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (fs_writeable(fs) && fh->open_flags & EXT2_FILE_WRITE) {
		err = ext2fs_flush2(fs, EXT2_FLAG_FLUSH_NO_SYNC);
		if (err)
			ret = translate_error(fs, fh->ino, err);
	}
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}

static int op_release(const char *path, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (fs_writeable(fs) && fh->open_flags & EXT2_FILE_WRITE) {
		err = ext2fs_flush2(fs, EXT2_FLAG_FLUSH_NO_SYNC);
		if (err)
			ret = translate_error(fs, fh->ino, err);
	}
	fp->fh = 0;
	pthread_mutex_unlock(&ff->bfl);

	free(fh);

	return ret;
}

static int op_fsync(const char *path, int datasync, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	errcode_t err;
	int ret = 0;

	/* For now, flush everything, even if it's slow */
	pthread_mutex_lock(&ff->bfl);
	if (fs_writeable(fs) && fh->open_flags & EXT2_FILE_WRITE) {
		err = ext2fs_flush2(fs, 0);
		if (err)
			ret = translate_error(fs, fh->ino, err);
	}
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}

static int op_statfs(const char *path, struct statvfs *buf)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	uint64_t fsid, *f;

	buf->f_bsize = fs->blocksize;
	buf->f_frsize = 0;
	buf->f_blocks = fs->super->s_blocks_count;
	buf->f_bfree = fs->super->s_free_blocks_count;
	if (fs->super->s_free_blocks_count < fs->super->s_r_blocks_count)
		buf->f_bavail = 0;
	else
		buf->f_bavail = fs->super->s_free_blocks_count -
				fs->super->s_r_blocks_count;
	buf->f_files = fs->super->s_inodes_count;
	buf->f_ffree = fs->super->s_free_inodes_count;
	buf->f_favail = fs->super->s_free_inodes_count;
	f = (uint64_t *)fs->super->s_uuid;
	fsid = *f;
	f++;
	fsid ^= *f;
	buf->f_fsid = fsid;
	buf->f_flag = 0;
	if (fs->flags & EXT2_FLAG_RW)
		buf->f_flag |= ST_RDONLY;
	buf->f_namemax = EXT2_NAME_LEN;

	return 0;
}

static int op_getxattr(const char *path, const char *key, char *value,
		       size_t len)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct ext2_xattr_handle *h;
	void *ptr;
	unsigned int plen;
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (!EXT2_HAS_COMPAT_FEATURE(fs->super,
				     EXT2_FEATURE_COMPAT_EXT_ATTR)) {
		ret = -ENOTSUP;
		goto out;
	}

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, R_OK);
	if (ret)
		goto out;

	err = ext2fs_xattrs_open(fs, ino, &h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	err = ext2fs_xattrs_read(h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	err = ext2fs_xattr_get(h, key, &ptr, &plen);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	if (!len) {
		ret = plen;
	} else if (len < plen) {
		ret = -ERANGE;
	} else {
		memcpy(value, ptr, plen);
		ret = plen;
	}

	ext2fs_free_mem(&ptr);
out2:
	err = ext2fs_xattrs_close(&h);
	if (err)
		ret = translate_error(fs, ino, err);
out:
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}

static int count_buffer_space(char *name, char *value, void *data)
{
	unsigned int *x = data;

	*x = *x + strlen(name) + 1;
	return 0;
}

static int copy_names(char *name, char *value, void *data)
{
	char **b = data;

	strncpy(*b, name, strlen(name));
	*b = *b + strlen(name) + 1;

	return 0;
}

static int op_listxattr(const char *path, char *names, size_t len)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct ext2_xattr_handle *h;
	unsigned int bufsz;
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (!EXT2_HAS_COMPAT_FEATURE(fs->super,
				     EXT2_FEATURE_COMPAT_EXT_ATTR)) {
		ret = -ENOTSUP;
		goto out;
	}

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, R_OK);
	if (ret)
		goto out2;

	err = ext2fs_xattrs_open(fs, ino, &h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	err = ext2fs_xattrs_read(h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	/* Count buffer space needed for names */
	bufsz = 0;
	err = ext2fs_xattrs_iterate(h, count_buffer_space, &bufsz);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	if (len == 0) {
		ret = bufsz;
		goto out2;
	} else if (len < bufsz) {
		ret = -ERANGE;
		goto out2;
	}

	/* Copy names out */
	memset(names, 0, len);
	err = ext2fs_xattrs_iterate(h, copy_names, &names);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}
	ret = bufsz;
out2:
	err = ext2fs_xattrs_close(&h);
	if (err)
		ret = translate_error(fs, ino, err);
out:
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}

static int op_setxattr(const char *path, const char *key, const char *value,
		       size_t len, int flags)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct ext2_xattr_handle *h;
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (!EXT2_HAS_COMPAT_FEATURE(fs->super,
				     EXT2_FEATURE_COMPAT_EXT_ATTR)) {
		ret = -ENOTSUP;
		goto out;
	}

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, W_OK);
	if (ret)
		goto out;

	err = ext2fs_xattrs_open(fs, ino, &h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	err = ext2fs_xattrs_read(h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	err = ext2fs_xattr_set(h, key, value, len);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	err = ext2fs_xattrs_write(h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

out2:
	err = ext2fs_xattrs_close(&h);
	if (err)
		ret = translate_error(fs, ino, err);
out:
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}

static int op_removexattr(const char *path, const char *key)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct ext2_xattr_handle *h;
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (!EXT2_HAS_COMPAT_FEATURE(fs->super,
				     EXT2_FEATURE_COMPAT_EXT_ATTR)) {
		ret = -ENOTSUP;
		goto out;
	}

	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, W_OK);
	if (ret)
		goto out;

	err = ext2fs_xattrs_open(fs, ino, &h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	err = ext2fs_xattrs_read(h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	err = ext2fs_xattr_remove(h, key);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

	err = ext2fs_xattrs_write(h);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out2;
	}

out2:
	err = ext2fs_xattrs_close(&h);
	if (err)
		ret = translate_error(fs, ino, err);
out:
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}

struct readdir_iter {
	void *buf;
	fuse_fill_dir_t func;
};

static int op_readdir_iter(ext2_ino_t dir, int entry,
			   struct ext2_dir_entry *dirent, int offset,
			   int blocksize, char *buf, void *data)
{
	struct readdir_iter *i = data;
	struct stat statbuf;
	char namebuf[EXT2_NAME_LEN + 1];
	int ret;

	memcpy(namebuf, dirent->name, dirent->name_len & 0xFF);
	namebuf[dirent->name_len & 0xFF] = 0;
	statbuf.st_ino = dirent->inode;
	statbuf.st_mode = S_IFREG;
	ret = i->func(i->buf, namebuf, NULL, 0);
	if (ret)
		return DIRENT_ABORT;

	return 0;
}

static int op_readdir(const char *path, void *buf, fuse_fill_dir_t fill_func,
		      off_t offset, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	errcode_t err;
	ext2_ino_t ino;
	struct readdir_iter i;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	i.buf = buf;
	i.func = fill_func;
	err = ext2fs_dir_iterate2(fs, fh->ino, 0, NULL, op_readdir_iter, &i);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	if (fs_writeable(fs)) {
		ret = update_atime(fs, fh->ino);
		if (ret)
			goto out;
	}
out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_access(const char *path, int mask)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t ino;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err || ino == 0) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, mask);
	if (ret)
		goto out;

out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

static int op_create(const char *path, mode_t mode, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct ext3_extent_header *eh;
	ext2_ino_t parent, child;
	char *temp_path = strdup(path);
	errcode_t err;
	char *node_name, a;
	int filetype, i;
	struct ext2_inode_large inode;
	int ret = 0;

	if (!temp_path) {
		ret = -ENOMEM;
		goto out;
	}
	node_name = strrchr(temp_path, '/');
	if (!node_name) {
		ret = -ENOMEM;
		goto out;
	}
	node_name++;
	a = *node_name;
	*node_name = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path,
			   &parent);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out2;
	}

	err = check_inum_access(ctxt, fs, parent, W_OK);
	if (err)
		goto out;

	*node_name = a;

	filetype = ext2_file_type(mode);

	err = ext2fs_new_inode(fs, parent, mode, 0, &child);
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out2;
	}

	err = ext2fs_link(fs, parent, node_name, child, filetype);
	if (err == EXT2_ET_DIR_NO_SPACE) {
		err = ext2fs_expand_dir(fs, parent);
		if (err) {
			ret = translate_error(fs, parent, err);
			goto out2;
		}

		err = ext2fs_link(fs, parent, node_name, child,
				     filetype);
	}
	if (err) {
		ret = translate_error(fs, parent, err);
		goto out2;
	}

	ret = update_mtime(fs, parent);
	if (ret)
		goto out2;

	memset(&inode, 0, sizeof(inode));
	inode.i_mode = mode;
	inode.i_links_count = 1;
	inode.i_extra_isize = sizeof(struct ext2_inode_large) -
		EXT2_GOOD_OLD_INODE_SIZE;
	if (fs->super->s_feature_incompat & EXT3_FEATURE_INCOMPAT_EXTENTS) {
		inode.i_flags = EXT4_EXTENTS_FL;

		/* This must be initialized, even for a zero byte file. */
		eh = (struct ext3_extent_header *) &inode.i_block[0];
		eh->eh_magic = ext2fs_cpu_to_le16(EXT3_EXT_MAGIC);
		eh->eh_depth = 0;
		eh->eh_entries = 0;
		i = (sizeof(inode.i_block) - sizeof(*eh)) /
			sizeof(struct ext3_extent);
		eh->eh_max = ext2fs_cpu_to_le16(i);
	}

	err = ext2fs_write_new_inode(fs, child, (struct ext2_inode *)&inode);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	inode.i_generation = ff->next_generation++;
	init_times(&inode);
	err = ext2fs_write_inode_full(fs, child, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	ext2fs_inode_alloc_stats2(fs, child, 1, 0);

	err = ext2fs_flush2(fs, EXT2_FLAG_FLUSH_NO_SYNC);
	if (err) {
		ret = translate_error(fs, child, err);
		goto out2;
	}

	ret = __op_open(path, fp);
	if (ret)
		goto out2;
out2:
	pthread_mutex_unlock(&ff->bfl);
out:
	free(temp_path);
	return ret;
}

static int op_ftruncate(const char *path, off_t len, struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	ext2_file_t efp;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	if (!fs_writeable(fs)) {
		ret = -EROFS;
		goto out;
	}

	err = ext2fs_file_open(fs, fh->ino, fh->open_flags, &efp);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_set_size2(efp, len);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	err = ext2fs_file_close(efp);
	if (err) {
		ret = translate_error(fs, fh->ino, err);
		goto out;
	}

	ret = update_mtime(fs, fh->ino);
	if (ret)
		goto out;

out:
	pthread_mutex_unlock(&ff->bfl);
	return 0;
}

static int op_fgetattr(const char *path, struct stat *statbuf,
		       struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	ret = stat_inode(fs, fh->ino, statbuf);
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}

static int op_utimens(const char *path, const struct timespec tv[2])
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	errcode_t err;
	ext2_ino_t ino;
	struct ext2_inode_large inode;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	ret = check_inum_access(ctxt, fs, ino, W_OK);
	if (ret)
		goto out;

	err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

	EXT4_INODE_SET_XTIME(i_atime, tv, &inode);
	EXT4_INODE_SET_XTIME(i_mtime, tv + 1, &inode);
	ret = update_ctime(fs, ino, &inode);
	if (ret)
		goto out;

	err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

out:
	pthread_mutex_unlock(&ff->bfl);
	return 0;
}

#ifdef SUPPORT_I_FLAGS
static int ioctl_getflags(ext2_filsys fs, struct fuse2fs_file_handle *fh,
			  void *data)
{
	errcode_t err;
	struct ext2_inode_large inode;

	err = ext2fs_read_inode_full(fs, fh->ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err)
		return -EIO;

	*(__u32 *)data = inode.i_flags & EXT2_FL_USER_VISIBLE;
	return 0;
}

#define FUSE2FS_MODIFIABLE_IFLAGS \
	(EXT2_IMMUTABLE_FL | EXT2_APPEND_FL | EXT2_NODUMP_FL | \
	 EXT2_NOATIME_FL | EXT3_JOURNAL_DATA_FL | EXT2_DIRSYNC_FL | \
	 EXT2_TOPDIR_FL)

int ioctl_setflags(ext2_filsys fs, struct fuse2fs_file_handle *fh, void *data)
{
	errcode_t err;
	struct ext2_inode_large inode;
	int ret;
	__u32 flags = *(__u32 *)data;
	struct fuse_context *ctxt = fuse_get_context();

	ret = check_flags_access(ctxt, fs, fh->ino, W_OK);
	if (ret)
		return ret;

	err = ext2fs_read_inode_full(fs, fh->ino, (struct ext2_inode *)&inode,
				     sizeof(inode));
	if (err)
		return -EIO;

	if ((inode.i_flags ^ flags) & ~FUSE2FS_MODIFIABLE_IFLAGS)
		return -EINVAL;

	inode.i_flags = inode.i_flags & ~FUSE2FS_MODIFIABLE_IFLAGS |
			flags & FUSE2FS_MODIFIABLE_IFLAGS;

	err = ext2fs_write_inode_full(fs, fh->ino, (struct ext2_inode *)&inode,
				      sizeof(inode));
	if (err)
		return -EIO;

	return 0;
}
#endif /* SUPPORT_I_FLAGS */

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 8)
static int op_ioctl(const char *path, int cmd, void *arg,
		      struct fuse_file_info *fp, unsigned int flags, void *data)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	switch (cmd) {
#ifdef SUPPORT_I_FLAGS
	case EXT2_IOC_GETFLAGS:
		ret = ioctl_getflags(fs, fh, data);
		break;
	case EXT2_IOC_SETFLAGS:
		ret = ioctl_setflags(fs, fh, data);
		break;
#endif
	default:
		ret = -ENOTTY;
	}
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}
#endif /* FUSE 28 */

static int op_bmap(const char *path, size_t blocksize, uint64_t *idx)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	ext2_ino_t ino;
	errcode_t err;
	int ret = 0;

	pthread_mutex_lock(&ff->bfl);
	err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
	if (err) {
		ret = translate_error(fs, 0, err);
		goto out;
	}

	err = ext2fs_bmap2(fs, ino, NULL, NULL, 0, *idx, 0, (blk64_t *)idx);
	if (err) {
		ret = translate_error(fs, ino, err);
		goto out;
	}

out:
	pthread_mutex_unlock(&ff->bfl);
	return ret;
}

#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
static int fallocate_helper(struct fuse_file_info *fp, int mode, off_t offset,
			    off_t len)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	blk64_t blk, end, x;
	__u64 fsize;
	ext2_file_t efp;
	struct ext2_inode_large inode;
	errcode_t err;
	int ret = 0;

	/* Allocate a bunch of blocks */
	end = (offset + len - 1) / fs->blocksize;
	for (blk = offset / fs->blocksize; blk <= end; blk++) {
		err = ext2fs_bmap2(fs, fh->ino, NULL, NULL, BMAP_ALLOC, blk,
				   0, &x);
		if (err)
			return translate_error(fs, fh->ino, err);
	}

	/* Update i_size */
	if (!(mode & FL_KEEP_SIZE_FLAG)) {
		err = ext2fs_file_open(fs, fh->ino, fh->open_flags, &efp);
		if (err)
			return translate_error(fs, fh->ino, err);

		err = ext2fs_file_get_lsize(efp, &fsize);
		if (err) {
			ret = translate_error(fs, fh->ino, err);
			goto out_isize;
		}
		if (offset + len > fsize) {
			fsize = offset + len;
			err = ext2fs_file_set_size2(efp, fsize);
			if (err) {
				ret = translate_error(fs, fh->ino, err);
				goto out_isize;
			}
		}

out_isize:
		err = ext2fs_file_close(efp);
		if (ret)
			return ret;
		if (err)
			return translate_error(fs, fh->ino, err);
	}

	return update_mtime(fs, fh->ino);
}

static int punch_helper(struct fuse_file_info *fp, int mode, off_t offset,
			off_t len)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	struct fuse2fs_file_handle *fh = (struct fuse2fs_file_handle *)fp->fh;
	blk64_t blk, start, end, x;
	__u64 fsize;
	ext2_file_t efp;
	struct ext2_inode_large inode;
	errcode_t err;
	int ret = 0;

	/* kernel ext4 punch requires this flag to be set */
	if (!(mode & FL_KEEP_SIZE_FLAG))
		return -EINVAL;

	if (len < fs->blocksize)
		return 0;

	/* Punch out a bunch of blocks */
	start = (offset + fs->blocksize - 1) / fs->blocksize;
	end = (offset + len - fs->blocksize) / fs->blocksize;

	if (start > end)
		return -EINVAL;

	err = ext2fs_punch(fs, fh->ino, NULL, NULL, start, end);
	if (err)
		return translate_error(fs, fh->ino, err);

	return update_mtime(fs, fh->ino);
}

static int op_fallocate(const char *path, int mode, off_t offset, off_t len,
			struct fuse_file_info *fp)
{
	struct fuse_context *ctxt = fuse_get_context();
	struct fuse2fs *ff = (struct fuse2fs *)ctxt->private_data;
	ext2_filsys fs = ff->fs;
	int ret;

	/* Catch unknown flags */
	if (mode & ~(FL_PUNCH_HOLE_FLAG | FL_KEEP_SIZE_FLAG))
		return -EINVAL;

	pthread_mutex_lock(&ff->bfl);
	if (!fs_writeable(fs)) {
		ret = -EROFS;
		goto out;
	}
	if (mode & FL_PUNCH_HOLE_FLAG)
		ret = punch_helper(fp, mode, offset, len);
	else
		ret = fallocate_helper(fp, mode, offset, len);
out:
	pthread_mutex_unlock(&ff->bfl);

	return ret;
}
#endif /* FUSE 29 */

static struct fuse_operations fs_ops = {
	.init = op_init,
	.destroy = op_destroy,
	.getattr = op_getattr,
	.readlink = op_readlink,
	.mknod = op_mknod,
	.mkdir = op_mkdir,
	.unlink = op_unlink,
	.rmdir = op_rmdir,
	.symlink = op_symlink,
	.rename = op_rename,
	.link = op_link,
	.chmod = op_chmod,
	.chown = op_chown,
	.truncate = op_truncate,
	.open = op_open,
	.read = op_read,
	.write = op_write,
	.statfs = op_statfs,
	.flush = op_flush,
	.release = op_release,
	.fsync = op_fsync,
	.setxattr = op_setxattr,
	.getxattr = op_getxattr,
	.listxattr = op_listxattr,
	.removexattr = op_removexattr,
	.opendir = op_open,
	.readdir = op_readdir,
	.releasedir = op_release,
	.fsyncdir = op_fsync,
	.access = op_access,
	.create = op_create,
	.ftruncate = op_ftruncate,
	.fgetattr = op_fgetattr,
	.utimens = op_utimens,
	.bmap = op_bmap,
#ifdef SUPERFLUOUS
	.lock = op_lock,
	.poll = op_poll,
#endif
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 8)
	.ioctl = op_ioctl,
	.flag_nullpath_ok = 1,
#endif
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 9)
	.flag_nopath = 1,
	.fallocate = op_fallocate,
#endif
};

static int get_random_bytes(void *p, size_t sz)
{
	int fd;
	ssize_t r;

	fd = open("/dev/random", O_RDONLY);
	if (fd < 0) {
		perror("/dev/random");
		return 0;
	}

	r = read(fd, p, sz);

	close(fd);
	return r == sz;
}

int main(int argc, char *argv[])
{
	errcode_t err;
	ext2_filsys fs;
	char *tok, *arg, *logfile;
	int i;
	int readwrite = 1, panic_on_error = 0;
	struct fuse2fs *ff;
	char extra_args[BUFSIZ];
	int ret = 0, flags = EXT2_FLAG_64BITS | EXT2_FLAG_EXCLUSIVE;

	if (argc < 2) {
		printf("Usage: %s dev mntpt [-o options] [fuse_args]\n",
		       argv[0]);
		return 1;
	}

	for (i = 1; i < argc - 1; i++) {
		if (strcmp(argv[i], "-o"))
			continue;
		arg = argv[i + 1];
		while ((tok = strtok(arg, ","))) {
			arg = NULL;
			if (!strcmp(tok, "ro"))
				readwrite = 0;
			else if (!strcmp(tok, "errors=panic"))
				panic_on_error = 1;
		}
	}

	if (!readwrite)
		printf("Mounting read-only.\n");

#ifdef ENABLE_NLS
	setlocale(LC_MESSAGES, "");
	setlocale(LC_CTYPE, "");
	bindtextdomain(NLS_CAT_NAME, LOCALEDIR);
	textdomain(NLS_CAT_NAME);
	set_com_err_gettext(gettext);
#endif
	add_error_table(&et_ext2_error_table);

	ff = calloc(1, sizeof(*ff));
	if (!ff) {
		perror("init");
		return 1;
	}
	ff->panic_on_error = panic_on_error;

	/* Set up error logging */
	logfile = getenv("FUSE2FS_LOGFILE");
	if (logfile) {
		ff->err_fp = fopen(logfile, "a");
		if (!ff->err_fp) {
			perror(logfile);
			goto out_nofs;
		}
	} else
		ff->err_fp = stderr;

	/* Start up the fs (while we still can use stdout) */
	ret = 2;
	if (readwrite)
		flags |= EXT2_FLAG_RW;
	err = ext2fs_open2(argv[1], NULL, flags, 0, 0, unix_io_manager, &fs);
	if (err) {
		printf("%s: %s.\n", argv[1], error_message(err));
		printf("Please run e2fsck -fy %s.\n", argv[1]);
		goto out_nofs;
	}
	ff->fs = fs;
	fs->priv_data = ff;

	ret = 3;
	if (EXT2_HAS_INCOMPAT_FEATURE(fs->super,
				      EXT3_FEATURE_INCOMPAT_RECOVER)) {
		printf("Journal needs recovery; running `e2fsck -E "
		       "journal_only' is required.\n");
		goto out;
	}

	if (readwrite) {
		if (EXT2_HAS_COMPAT_FEATURE(fs->super,
					    EXT3_FEATURE_COMPAT_HAS_JOURNAL))
			printf("Journal mode will not be used.\n");
		err = ext2fs_read_inode_bitmap(fs);
		if (err) {
			translate_error(fs, 0, err);
			goto out;
		}
		err = ext2fs_read_block_bitmap(fs);
		if (err) {
			translate_error(fs, 0, err);
			goto out;
		}
	}

	if (!(fs->super->s_state & EXT2_VALID_FS))
		printf("Warning: Mounting unchecked fs, running e2fsck "
		       "is recommended.\n");
	if (fs->super->s_max_mnt_count > 0 &&
	    fs->super->s_mnt_count >= fs->super->s_max_mnt_count)
		printf("Warning: Maximal mount count reached, running "
		       "e2fsck is recommended.\n");
	if (fs->super->s_checkinterval > 0 &&
	    fs->super->s_lastcheck + fs->super->s_checkinterval <= time(0))
		printf("Warning: Check time reached; running e2fsck "
		       "is recommended.\n");
	if (fs->super->s_last_orphan)
		printf("Orphans detected; running e2fsck is recommended.\n");

	if (fs->super->s_state & EXT2_ERROR_FS) {
		printf("Errors detected; running e2fsck is required.\n");
		goto out;
	}

	/* Initialize generation counter */
	get_random_bytes(&ff->next_generation, sizeof(unsigned int));

	/* Stuff in some fuse parameters of our own */
	snprintf(extra_args, BUFSIZ, "-okernel_cache,subtype=ext4,use_ino,"
		 "fsname=%s", argv[1]);
	argv[0] = argv[1];
	argv[1] = argv[2];
	argv[2] = extra_args;

	pthread_mutex_init(&ff->bfl, NULL);
	fuse_main(argc, argv, &fs_ops, ff);
	pthread_mutex_destroy(&ff->bfl);

	ret = 0;
out:
	err = ext2fs_close(fs);
	if (err)
		ret = translate_error(fs, 0, err);
out_nofs:
	free(ff);

	return ret;
}

static int __translate_error(ext2_filsys fs, errcode_t err, ext2_ino_t ino,
			     const char *file, int line)
{
	struct timespec now;
	int ret;
	struct fuse2fs *ff = fs->priv_data;
	int is_err = 0;

	/* Translate ext2 error to unix error code */
	switch (err) {
	case EXT2_ET_NO_MEMORY:
	case EXT2_ET_TDB_ERR_OOM:
		ret = -ENOMEM;
		break;
	case EXT2_ET_INVALID_ARGUMENT:
	case EXT2_ET_LLSEEK_FAILED:
		ret = -EINVAL;
		break;
	case EXT2_ET_NO_DIRECTORY:
		ret = -ENOTDIR;
		break;
	case EXT2_ET_FILE_NOT_FOUND:
		ret = -ENOENT;
		break;
	case EXT2_ET_DIR_NO_SPACE:
		is_err = 1;
	case EXT2_ET_TOOSMALL:
	case EXT2_ET_BLOCK_ALLOC_FAIL:
	case EXT2_ET_INODE_ALLOC_FAIL:
	case EXT2_ET_EA_NO_SPACE:
		ret = -ENOSPC;
		break;
	case EXT2_ET_SYMLINK_LOOP:
		ret = -EMLINK;
		break;
	case EXT2_ET_FILE_TOO_BIG:
		ret = -EFBIG;
		break;
	case EXT2_ET_TDB_ERR_EXISTS:
	case EXT2_ET_FILE_EXISTS:
		ret = -EEXIST;
		break;
	case EXT2_ET_MMP_FAILED:
	case EXT2_ET_MMP_FSCK_ON:
		ret = -EBUSY;
		break;
	case EXT2_ET_EA_KEY_NOT_FOUND:
		ret = -ENODATA;
		break;
	default:
		is_err = 1;
		ret = -EIO;
		break;
	}

	if (!is_err)
		return ret;

	if (ino)
		fprintf(ff->err_fp, "FUSE2FS (%s): %s (inode #%d) at %s:%d.\n",
			fs && fs->device_name ? fs->device_name : "???",
			error_message(err), ino, file, line);
	else
		fprintf(ff->err_fp, "FUSE2FS (%s): %s at %s:%d.\n",
			fs && fs->device_name ? fs->device_name : "???",
			error_message(err), file, line);
	fflush(ff->err_fp);

	/* Make a note in the error log */
	get_now(&now);
	fs->super->s_last_error_time = now.tv_sec;
	fs->super->s_last_error_ino = ino;
	fs->super->s_last_error_line = line;
	fs->super->s_last_error_block = 0;
	strncpy(fs->super->s_last_error_func, file,
		sizeof(fs->super->s_last_error_func));
	if (fs->super->s_first_error_time == 0) {
		fs->super->s_first_error_time = now.tv_sec;
		fs->super->s_first_error_ino = ino;
		fs->super->s_first_error_line = line;
		fs->super->s_first_error_block = 0;
		strncpy(fs->super->s_first_error_func, file,
			sizeof(fs->super->s_first_error_func));
	}

	fs->super->s_error_count++;
	ext2fs_mark_super_dirty(fs);
	ext2fs_flush(fs);
	if (ff->panic_on_error)
		abort();

	return ret;
}
