#ifndef FILE_VIEW_H
#define FILE_VIEW_H

struct file_view {
	size_t      size; /* Size of file plus one */
	const char *path; /* Path to file */
	char       *src;  /* Memory-mapped file contents */
};

void init_file_view_readonly(struct file_view *, const char *);
void init_file_view_readwrite(struct file_view *, const char *);

#endif
