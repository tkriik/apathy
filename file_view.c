#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <assert.h>
#include <stddef.h>

#include "file_view.h"
#include "util.h"

static void *
mmap_file(const char *path, size_t *sizep, int prot)
{
	assert(path != NULL);
	assert(sizep != NULL);

	struct stat sb;

	int fd = open(path, O_RDONLY);
	if (fd == -1)
		ERR( "failed to open file at '%s'", path);

	if (fstat(fd, &sb) == -1)
		ERR( "failed to read file status for %s", path);

	*sizep = (size_t)sb.st_size;
	void *p = mmap(NULL, (size_t)sb.st_size + 1, prot, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		ERR("failed to map %s into memory", path);

	return p;
}

void
init_file_view_readonly(struct file_view *file_view, const char *path)
{
	file_view->src = mmap_file(path, &file_view->size, PROT_READ);
	file_view->path = path;
}

void
init_file_view_readwrite(struct file_view *file_view, const char *path)
{
	file_view->src = mmap_file(path, &file_view->size, PROT_READ | PROT_WRITE);
	file_view->path = path;
}
