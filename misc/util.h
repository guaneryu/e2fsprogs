/*
 * util.h --- header file defining prototypes for helper functions
 * used by tune2fs and mke2fs
 *
 * Copyright 2000 by Theodore Ts'o.
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU Public
 * License.
 * %End-Header%
 */

extern int	 journal_size;
extern int	 journal_flags;
extern char	*journal_device;

/* For struct stat */
#include <sys/types.h>
#include <sys/stat.h>

struct hdlink_s
{
	ext2_ino_t src_ino;
	ext2_ino_t dst_ino;
};

struct hdlinks_s
{
	int count;
	struct hdlink_s *hdl;
};

struct hdlinks_s hdlinks;

ext2_filsys	current_fs;
ext2_ino_t	root;

/* For saving the hard links */
#define HDLINK_CNT	4
extern int hdlink_cnt;

#ifndef HAVE_STRCASECMP
extern int strcasecmp (char *s1, char *s2);
#endif
extern char *get_progname(char *argv_zero);
extern void proceed_question(void);
extern void check_plausibility(const char *device);
extern void parse_journal_opts(const char *opts);
extern void check_mount(const char *device, int force, const char *type);
extern unsigned int figure_journal_size(int size, ext2_filsys fs);
extern void print_check_message(int, unsigned int);
extern void dump_mmp_msg(struct mmp_struct *mmp, const char *msg);

/* For populating the filesystem */
extern errcode_t populate_fs(ext2_ino_t parent_ino, const char *source_dir);
extern errcode_t do_mknod_internal(ext2_ino_t cwd, const char *name, struct stat *st);
extern errcode_t do_symlink_internal(ext2_ino_t cwd, const char *name, char *target);
extern errcode_t do_mkdir_internal(ext2_ino_t cwd, const char *name, struct stat *st);
extern errcode_t do_write_internal(ext2_ino_t cwd, const char *src, const char *dest);
