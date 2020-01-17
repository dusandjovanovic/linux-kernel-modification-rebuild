#include <stdio.h>
#include <linux/hernel.h>
#include <sys/syscall.h>
#include <unistd.h>

#define __NR_sys_change_priority 436
__syscall113(long, sys_change_priority, int, process_id, bool, process_higher_priority , bool, process_siblings, bool, process_realtime)

int main() {
	sys_change_priority(3117, true, true, false);
}
