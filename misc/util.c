/*
 * util.c --- helper functions used by tune2fs and mke2fs
 *
 * Copyright 1995, 1996, 1997, 1998, 1999, 2000 by Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include "config.h"
#include <stdio.h>
#include <string.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LINUX_MAJOR_H
#include <linux/major.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <time.h>

#include "et/com_err.h"
#include "e2p/e2p.h"
#include "ext2fs/ext2_fs.h"
#include "ext2fs/ext2fs.h"
#include "nls-enable.h"
#include "blkid/blkid.h"

#include <fcntl.h>

#include "util.h"

int	journal_size;
int	journal_flags;
char	*journal_device;

/* For saving the hard links */
int hdlink_cnt = HDLINK_CNT;

#ifndef HAVE_STRCASECMP
int strcasecmp (char *s1, char *s2)
{
	while (*s1 && *s2) {
		int ch1 = *s1++, ch2 = *s2++;
		if (isupper (ch1))
			ch1 = tolower (ch1);
		if (isupper (ch2))
			ch2 = tolower (ch2);
		if (ch1 != ch2)
			return ch1 - ch2;
	}
	return *s1 ? 1 : *s2 ? -1 : 0;
}
#endif

/*
 * Given argv[0], return the program name.
 */
char *get_progname(char *argv_zero)
{
	char	*cp;

	cp = strrchr(argv_zero, '/');
	if (!cp )
		return argv_zero;
	else
		return cp+1;
}

void proceed_question(void)
{
	char buf[256];
	const char *short_yes = _("yY");

	fflush(stdout);
	fflush(stderr);
	fputs(_("Proceed anyway? (y,n) "), stdout);
	buf[0] = 0;
	if (!fgets(buf, sizeof(buf), stdin) ||
	    strchr(short_yes, buf[0]) == 0)
		exit(1);
}

void check_plausibility(const char *device)
{
	int val;
	ext2fs_struct_stat s;

	val = ext2fs_stat(device, &s);

	if(val == -1) {
		fprintf(stderr, _("Could not stat %s --- %s\n"),
			device, error_message(errno));
		if (errno == ENOENT)
			fputs(_("\nThe device apparently does not exist; "
				"did you specify it correctly?\n"), stderr);
		exit(1);
	}
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
	/* On FreeBSD, all disk devices are character specials */
	if (!S_ISBLK(s.st_mode) && !S_ISCHR(s.st_mode))
#else
	if (!S_ISBLK(s.st_mode))
#endif
	{
		printf(_("%s is not a block special device.\n"), device);
		proceed_question();
		return;
	}

#ifdef HAVE_LINUX_MAJOR_H
#ifndef MAJOR
#define MAJOR(dev)	((dev)>>8)
#define MINOR(dev)	((dev) & 0xff)
#endif
#ifndef SCSI_BLK_MAJOR
#ifdef SCSI_DISK0_MAJOR
#ifdef SCSI_DISK8_MAJOR
#define SCSI_DISK_MAJOR(M) ((M) == SCSI_DISK0_MAJOR || \
  ((M) >= SCSI_DISK1_MAJOR && (M) <= SCSI_DISK7_MAJOR) || \
  ((M) >= SCSI_DISK8_MAJOR && (M) <= SCSI_DISK15_MAJOR))
#else
#define SCSI_DISK_MAJOR(M) ((M) == SCSI_DISK0_MAJOR || \
  ((M) >= SCSI_DISK1_MAJOR && (M) <= SCSI_DISK7_MAJOR))
#endif /* defined(SCSI_DISK8_MAJOR) */
#define SCSI_BLK_MAJOR(M) (SCSI_DISK_MAJOR((M)) || (M) == SCSI_CDROM_MAJOR)
#else
#define SCSI_BLK_MAJOR(M)  ((M) == SCSI_DISK_MAJOR || (M) == SCSI_CDROM_MAJOR)
#endif /* defined(SCSI_DISK0_MAJOR) */
#endif /* defined(SCSI_BLK_MAJOR) */
	if (((MAJOR(s.st_rdev) == HD_MAJOR &&
	      MINOR(s.st_rdev)%64 == 0) ||
	     (SCSI_BLK_MAJOR(MAJOR(s.st_rdev)) &&
	      MINOR(s.st_rdev)%16 == 0))) {
		printf(_("%s is entire device, not just one partition!\n"),
		       device);
		proceed_question();
	}
#endif
}

void check_mount(const char *device, int force, const char *type)
{
	errcode_t	retval;
	int		mount_flags;

	retval = ext2fs_check_if_mounted(device, &mount_flags);
	if (retval) {
		com_err("ext2fs_check_if_mount", retval,
			_("while determining whether %s is mounted."),
			device);
		return;
	}
	if (mount_flags & EXT2_MF_MOUNTED) {
		fprintf(stderr, _("%s is mounted; "), device);
		if (force > 2) {
			fputs(_("mke2fs forced anyway.  Hope /etc/mtab is "
				"incorrect.\n"), stderr);
			return;
		}
	abort_mke2fs:
		fprintf(stderr, _("will not make a %s here!\n"), type);
		exit(1);
	}
	if (mount_flags & EXT2_MF_BUSY) {
		fprintf(stderr, _("%s is apparently in use by the system; "),
			device);
		if (force > 2) {
			fputs(_("mke2fs forced anyway.\n"), stderr);
			return;
		}
		goto abort_mke2fs;
	}
}

void parse_journal_opts(const char *opts)
{
	char	*buf, *token, *next, *p, *arg;
	int	len;
	int	journal_usage = 0;

	len = strlen(opts);
	buf = malloc(len+1);
	if (!buf) {
		fputs(_("Couldn't allocate memory to parse journal "
			"options!\n"), stderr);
		exit(1);
	}
	strcpy(buf, opts);
	for (token = buf; token && *token; token = next) {
		p = strchr(token, ',');
		next = 0;
		if (p) {
			*p = 0;
			next = p+1;
		}
		arg = strchr(token, '=');
		if (arg) {
			*arg = 0;
			arg++;
		}
#if 0
		printf("Journal option=%s, argument=%s\n", token,
		       arg ? arg : "NONE");
#endif
		if (strcmp(token, "device") == 0) {
			journal_device = blkid_get_devname(NULL, arg, NULL);
			if (!journal_device) {
				if (arg)
					fprintf(stderr, _("\nCould not find "
						"journal device matching %s\n"),
						arg);
				journal_usage++;
				continue;
			}
		} else if (strcmp(token, "size") == 0) {
			if (!arg) {
				journal_usage++;
				continue;
			}
			journal_size = strtoul(arg, &p, 0);
			if (*p)
				journal_usage++;
		} else if (strcmp(token, "v1_superblock") == 0) {
			journal_flags |= EXT2_MKJOURNAL_V1_SUPER;
			continue;
		} else
			journal_usage++;
	}
	if (journal_usage) {
		fputs(_("\nBad journal options specified.\n\n"
			"Journal options are separated by commas, "
			"and may take an argument which\n"
			"\tis set off by an equals ('=') sign.\n\n"
			"Valid journal options are:\n"
			"\tsize=<journal size in megabytes>\n"
			"\tdevice=<journal device>\n\n"
			"The journal size must be between "
			"1024 and 10240000 filesystem blocks.\n\n"), stderr);
		free(buf);
		exit(1);
	}
	free(buf);
}

/*
 * Determine the number of journal blocks to use, either via
 * user-specified # of megabytes, or via some intelligently selected
 * defaults.
 *
 * Find a reasonable journal file size (in blocks) given the number of blocks
 * in the filesystem.  For very small filesystems, it is not reasonable to
 * have a journal that fills more than half of the filesystem.
 */
unsigned int figure_journal_size(int size, ext2_filsys fs)
{
	int j_blocks;

	j_blocks = ext2fs_default_journal_size(ext2fs_blocks_count(fs->super));
	if (j_blocks < 0) {
		fputs(_("\nFilesystem too small for a journal\n"), stderr);
		return 0;
	}

	if (size > 0) {
		j_blocks = size * 1024 / (fs->blocksize	/ 1024);
		if (j_blocks < 1024 || j_blocks > 10240000) {
			fprintf(stderr, _("\nThe requested journal "
				"size is %d blocks; it must be\n"
				"between 1024 and 10240000 blocks.  "
				"Aborting.\n"),
				j_blocks);
			exit(1);
		}
		if ((unsigned) j_blocks > ext2fs_free_blocks_count(fs->super) / 2) {
			fputs(_("\nJournal size too big for filesystem.\n"),
			      stderr);
			exit(1);
		}
	}
	return j_blocks;
}

void print_check_message(int mnt, unsigned int check)
{
	if (mnt < 0)
		mnt = 0;
	if (!mnt && !check)
		return;
	printf(_("This filesystem will be automatically "
		 "checked every %d mounts or\n"
		 "%g days, whichever comes first.  "
		 "Use tune2fs -c or -i to override.\n"),
	       mnt, ((double) check) / (3600 * 24));
}

void dump_mmp_msg(struct mmp_struct *mmp, const char *msg)
{

	if (msg)
		printf("MMP check failed: %s\n", msg);
	if (mmp) {
		time_t t = mmp->mmp_time;

		printf("MMP error info: last update: %s node: %s device: %s\n",
		       ctime(&t), mmp->mmp_nodename, mmp->mmp_bdevname);
	}
}

/* Fill the uid, gid, mode and time for the inode */
static void fill_inode(struct ext2_inode *inode, struct stat *st)
{
	if (st != NULL) {
		inode->i_uid = st->st_uid;
		inode->i_gid = st->st_gid;
		inode->i_mode |= st->st_mode;
		inode->i_atime = st->st_atime;
		inode->i_mtime = st->st_mtime;
		inode->i_ctime = st->st_ctime;
	}
}

/* Set the uid, gid, mode and time for the inode */
errcode_t set_inode_extra(ext2_ino_t cwd, ext2_ino_t ino, struct stat *st)
{
	errcode_t		retval;
	struct ext2_inode	inode;
	char			*func_name = "set_inode_extra";

	retval = ext2fs_read_inode(current_fs, ino, &inode);
        if (retval) {
		com_err(func_name, retval, "while reading inode %u", ino);
		return retval;
	}

	fill_inode(&inode, st);

	retval = ext2fs_write_inode(current_fs, ino, &inode);
	if (retval) {
		com_err(func_name, retval, "while writing inode %u", ino);
		return retval;
	}
}

/* Make a special file which is block, character and fifo */
errcode_t do_mknod_internal(ext2_ino_t cwd, const char *name, struct stat *st)
{
	ext2_ino_t		ino;
	errcode_t 		retval;
	struct ext2_inode	inode;
	char			*func_name = "do_mknod_internal";
	unsigned long		major, minor, mode;
	int			filetype;

	switch(st->st_mode & S_IFMT) {
		case S_IFCHR:
			mode = LINUX_S_IFCHR;
			filetype = EXT2_FT_CHRDEV;
			break;
		case S_IFBLK:
			mode = LINUX_S_IFBLK;
			filetype =  EXT2_FT_BLKDEV;
			break;
		case S_IFIFO:
			mode = LINUX_S_IFIFO;
			filetype = EXT2_FT_FIFO;
			break;
	}

	if (!(current_fs->flags & EXT2_FLAG_RW)) {
		com_err(func_name, 0, "Filesystem opened read/only");
		return -1;
	}
	retval = ext2fs_new_inode(current_fs, cwd, 010755, 0, &ino);
	if (retval) {
		com_err(func_name, retval, 0);
		return retval;
	}
	printf("Allocated inode: %u\n", ino);
	retval = ext2fs_link(current_fs, cwd, name, ino, filetype);
	if (retval == EXT2_ET_DIR_NO_SPACE) {
		retval = ext2fs_expand_dir(current_fs, cwd);
		if (retval) {
			com_err(func_name, retval, "while expanding directory");
			return retval;
		}
		retval = ext2fs_link(current_fs, cwd, name, ino, filetype);
	}
	if (retval) {
		com_err(name, retval, 0);
		return -1;
	}
        if (ext2fs_test_inode_bitmap2(current_fs->inode_map, ino))
		com_err(func_name, 0, "Warning: inode already set");
	ext2fs_inode_alloc_stats2(current_fs, ino, +1, 0);
	memset(&inode, 0, sizeof(inode));
	inode.i_mode = mode;
	inode.i_atime = inode.i_ctime = inode.i_mtime =
		current_fs->now ? current_fs->now : time(0);

	major = major(st->st_rdev);
	minor = minor(st->st_rdev);

	if ((major < 256) && (minor < 256)) {
		inode.i_block[0] = major * 256 + minor;
		inode.i_block[1] = 0;
	} else {
		inode.i_block[0] = 0;
		inode.i_block[1] = (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
	}
	inode.i_links_count = 1;

	retval = ext2fs_write_new_inode(current_fs, ino, &inode);
	if (retval)
		com_err(func_name, retval, "while creating inode %u", ino);

	return retval;
}

/* Make a symlink name -> target */
errcode_t do_symlink_internal(ext2_ino_t cwd, const char *name, char *target)
{
	char			*cp;
	ext2_ino_t		parent_ino;
	errcode_t		retval;
	struct ext2_inode	inode;
	struct stat		st;

	cp = strrchr(name, '/');
	if (cp) {
		*cp = 0;
		if ((retval =  ext2fs_namei(current_fs, root, cwd, name, &parent_ino))){
			com_err(name, retval, 0);
			return retval;
		}
		name = cp+1;
	} else {
		parent_ino = cwd;
		name = name;
	}

try_again:
	retval = ext2fs_symlink(current_fs, parent_ino, 0, name, target);
	if (retval == EXT2_ET_DIR_NO_SPACE) {
		retval = ext2fs_expand_dir(current_fs, parent_ino);
		if (retval) {
			com_err("do_symlink_internal", retval, "while expanding directory");
			return retval;
		}
		goto try_again;
	}
	if (retval) {
		com_err("ext2fs_symlink", retval, 0);
		return retval;
	}

}

static errcode_t copy_file(int fd, ext2_ino_t ino)
{
	ext2_file_t	e2_file;
	errcode_t	retval;
	int		got;
	unsigned int	written;
	char		buf[8192];
	char		*ptr;

	retval = ext2fs_file_open(current_fs, ino, EXT2_FILE_WRITE, &e2_file);
	if (retval)
		return retval;

	while (1) {
		got = read(fd, buf, sizeof(buf));
		if (got == 0)
			break;
		if (got < 0) {
			retval = errno;
			goto fail;
		}
		ptr = buf;
		while (got > 0) {
			retval = ext2fs_file_write(e2_file, ptr,
						   got, &written);
			if (retval)
				goto fail;

			got -= written;
			ptr += written;
		}
	}
	retval = ext2fs_file_close(e2_file);
	return retval;

fail:
	(void) ext2fs_file_close(e2_file);
	return retval;
}

/* Make a directory in the fs */
errcode_t do_mkdir_internal(ext2_ino_t cwd, const char *name, struct stat *st)
{
	char			*cp;
	ext2_ino_t		parent_ino, ino;
	errcode_t		retval;
	struct ext2_inode	inode;
	char			*func_name = "do_mkdir_internal";


	cp = strrchr(name, '/');
	if (cp) {
		*cp = 0;
		if ((retval =  ext2fs_namei(current_fs, root, cwd, name, &parent_ino))){
			com_err(name, retval, 0);
			return retval;
		}
		name = cp+1;
	} else {
		parent_ino = cwd;
		name = name;
	}

try_again:
	retval = ext2fs_mkdir(current_fs, parent_ino, 0, name);
	if (retval == EXT2_ET_DIR_NO_SPACE) {
		retval = ext2fs_expand_dir(current_fs, parent_ino);
		if (retval) {
			com_err(func_name, retval, "while expanding directory");
			return retval;
		}
		goto try_again;
	}
	if (retval) {
		com_err("ext2fs_mkdir", retval, 0);
		return retval;
	}
}

/* Copy the native file to the fs */
errcode_t do_write_internal(ext2_ino_t cwd, const char *src, const char *dest)
{
	int		fd;
	struct stat	statbuf;
	ext2_ino_t	ino;
	errcode_t	retval;
	struct		ext2_inode inode;
	char		*func_name = "do_write_internal";
	int		hdlink;

	fd = open(src, O_RDONLY);
	if (fd < 0) {
		com_err(src, errno, 0);
		return errno;
	}
	if (fstat(fd, &statbuf) < 0) {
		com_err(src, errno, 0);
		close(fd);
		return errno;
	}

	retval = ext2fs_namei(current_fs, root, cwd, dest, &ino);
	if (retval == 0) {
		com_err(func_name, 0, "The file '%s' already exists\n", dest);
		close(fd);
		return errno;
	}

	retval = ext2fs_new_inode(current_fs, cwd, 010755, 0, &ino);
	if (retval) {
		com_err(func_name, retval, 0);
		close(fd);
		return errno;
	}
	printf("Allocated inode: %u\n", ino);
	retval = ext2fs_link(current_fs, cwd, dest, ino, EXT2_FT_REG_FILE);
	if (retval == EXT2_ET_DIR_NO_SPACE) {
		retval = ext2fs_expand_dir(current_fs, cwd);
		if (retval) {
			com_err(func_name, retval, "while expanding directory");
			close(fd);
			return errno;
		}
		retval = ext2fs_link(current_fs, cwd, dest, ino, EXT2_FT_REG_FILE);
	}
	if (retval) {
		com_err(dest, retval, 0);
		close(fd);
		return errno;
	}
        if (ext2fs_test_inode_bitmap2(current_fs->inode_map, ino))
		com_err(func_name, 0, "Warning: inode already set");
	ext2fs_inode_alloc_stats2(current_fs, ino, +1, 0);
	memset(&inode, 0, sizeof(inode));
	inode.i_mode = (statbuf.st_mode & ~LINUX_S_IFMT) | LINUX_S_IFREG;
	inode.i_atime = inode.i_ctime = inode.i_mtime =
		current_fs->now ? current_fs->now : time(0);
	inode.i_links_count = 1;
	inode.i_size = statbuf.st_size;
	if (current_fs->super->s_feature_incompat &
	    EXT3_FEATURE_INCOMPAT_EXTENTS) {
		int i;
		struct ext3_extent_header *eh;

		eh = (struct ext3_extent_header *) &inode.i_block[0];
		eh->eh_depth = 0;
		eh->eh_entries = 0;
		eh->eh_magic = EXT3_EXT_MAGIC;
		i = (sizeof(inode.i_block) - sizeof(*eh)) /
			sizeof(struct ext3_extent);
		eh->eh_max = ext2fs_cpu_to_le16(i);
		inode.i_flags |= EXT4_EXTENTS_FL;
	}

	if ((retval = ext2fs_write_new_inode(current_fs, ino, &inode))) {
		com_err(func_name, retval, "while creating inode %u", ino);
		close(fd);
		return errno;
	}
	if (LINUX_S_ISREG(inode.i_mode)) {
		retval = copy_file(fd, ino);
		if (retval)
			com_err("copy_file", retval, 0);
	}
	close(fd);

	return 0;
}

/* Copy files from source_dir to fs */
errcode_t populate_fs(ext2_ino_t parent_ino, const char *source_dir)
{
	const char	*name;
	DIR		*dh;
	struct dirent	*dent;
	struct stat	st;
	char		ln_target[PATH_MAX];
	char		*func_name = "populate_fs";
	ext2_ino_t	ino;
	errcode_t	retval;
	int		read_cnt;

	root = EXT2_ROOT_INO;

	if (chdir(source_dir) < 0) {
		com_err(func_name, errno,
			_("while changing working directory to \"%s\""), source_dir);
		return errno;
	}

	if (!(dh = opendir("."))) {
		com_err(func_name, errno,
			_("while openning directory \"%s\""), source_dir);
		return errno;
	}

	while((dent = readdir(dh))) {
		if((!strcmp(dent->d_name, ".")) || (!strcmp(dent->d_name, "..")))
			continue;
		lstat(dent->d_name, &st);
		name = dent->d_name;

		switch(st.st_mode & S_IFMT) {
			case S_IFCHR:
			case S_IFBLK:
			case S_IFIFO:
				if ((retval = do_mknod_internal(parent_ino, name, &st))) {
					com_err(func_name, retval,
						_("while creating special file \"%s\""), name);
					return retval;
				}
				break;
			case S_IFSOCK:
				/* FIXME: there is no make sockect function atm. */
				com_err(func_name, 0,
					_("ignoring sockect file\"%s\""), name);
				break;
			case S_IFLNK:
				if((read_cnt = readlink(name, ln_target, sizeof(ln_target))) == -1) {
					com_err(func_name, errno,
						_("while trying to readlink \"%s\""), name);
					return errno;
				}
				ln_target[read_cnt] = '\0';
				if ((retval = do_symlink_internal(parent_ino, name, ln_target))) {
					com_err(func_name, retval,
						_("while writing symlink\"%s\""), name);
					return retval;
				}
				break;
			case S_IFREG:
				if ((retval = do_write_internal(parent_ino, name, name))) {
					com_err(func_name, retval,
						_("while writing file \"%s\""), name);
					return retval;
				}
				break;
			case S_IFDIR:
				if ((retval = do_mkdir_internal(parent_ino, name, &st))) {
					com_err(func_name, retval,
						_("while making dir \"%s\""), name);
					return retval;
				}
				if ((retval = ext2fs_namei(current_fs, root, parent_ino, name, &ino))) {
					com_err(name, retval, 0);
						return retval;
				}
				/* Populate the dir recursively*/
				retval = populate_fs(ino, name);
				if (retval) {
					com_err(func_name, retval, _("while adding dir \"%s\""), name);
					return retval;
				}
				chdir("..");
				break;
			default:
				com_err(func_name, 0,
					_("ignoring entry \"%s\""), name);
		}

		if ((retval =  ext2fs_namei(current_fs, root, parent_ino, name, &ino))){
			com_err(name, retval, 0);
			return retval;
		}

		if ((retval = set_inode_extra(parent_ino, ino, &st))) {
			com_err(func_name, retval,
				_("while setting inode for \"%s\""), name);
			return retval;
		}
	}
	closedir(dh);
	return retval;
}
