#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

int main(void)
{
	int fd = open("/dev/kiomem", O_RDWR);
	if (fd < 0) {
		perror("open(/dev/kiomem failed");
		return -1;
	}

	void *mem = mmap(NULL, 64, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_LOCKED, fd, 0);
	if ((void *)-1 == mem) {
		perror("mmap() failed");
		return -1;
	}

	printf("%x\n", *(int *)mem);
	*(int *)mem = 0xdefaced;
	printf("%x\n", *(int *)mem);

	unsigned long addr = (unsigned long)mem;
	ssize_t sz = write(fd, &addr, sizeof(addr));
	if (sizeof(mem) != sz) {
		perror("write() failed");
		return -1;
	}

	uint64_t dma;
	sz = read(fd, &dma, sizeof(dma));
	if (sizeof(dma) != sz) {
		perror("read() failed");
		return -1;
	}

	printf("%llx\n", (long long)dma);

	return 0;
}
