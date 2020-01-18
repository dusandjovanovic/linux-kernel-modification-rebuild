#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define __NR_sys_change_priority 436

int main() {
	long __return = syscall(436, 2620, 1, 1, 0);
	printf("sys_call returned: %ld", __return);
	return 0;
}
