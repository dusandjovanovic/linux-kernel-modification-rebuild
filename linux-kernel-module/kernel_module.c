#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>

static int process_id = 0;
module_param(process_id, int, 0644);
MODULE_PARM_DESC(process_id, "Recipent process by id.");

static bool process_higher_priority = true;
module_param(process_higher_priority, bool, 0644);
MODULE_PARM_DESC(process_higher_priority, "Recipent process's priority will be incremented/decremented.");

static bool process_siblings = false;
module_param(process_siblings, bool, 0644);
MODULE_PARM_DESC(process_siblings, "Recipent process's siblings should/not be affected.");

static bool process_realtime = false;
module_param(process_realtime, bool, 0644);
MODULE_PARM_DESC(process_realtime, "Recipent process could be given realtime priority.");

static struct task_struct* normalize(void) {
    struct task_struct* target_process;
    if (process_id == 0)
        target_process = current;
    else
        target_process = pid_task(find_vpid(process_id), PIDTYPE_PID);

    return target_process;
}

static int __init kernel_module_init(void)
{
    struct task_struct* process;
    process = normalize();

    pr_alert("Commiting changes for process w/ pid %d\n", process->pid);
    if (process_siblings)
        pr_alert("Changes will be applied to all siblings of the process\n");

    struct task_struct* task_sibling;
    struct list_head* task_list;

    list_for_each(task_list, &(process->parent)->children) {
        task_sibling = list_entry(task_list, struct task_struct, sibling);
        if (task_sibling->pid == process->pid || process_siblings)
        {
            pr_alert("Changing priority level from %d for pID(%d)\n", task_sibling->static_prio, process->pid);

            unsigned int new_static_prio = process_higher_priority ? task_sibling->static_prio - 1 : task_sibling->static_prio + 1;
            
            task_sibling->static_prio = new_static_prio;
            pr_alert("Commited %d priority level for pID(%d)\n", new_static_prio, process->pid);
            if (process_realtime) {
                task_sibling->policy = SCHED_RR;
                pr_alert("Commited SCHED_RR priority policy for pID(%d)\n", process->pid);
            }
        }
    }

    return 0;
}

static void __exit kernel_module_exit(void)
{
    pr_alert("Unloading module\n");
}

module_init(kernel_module_init);
module_exit(kernel_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KERNEL_MODULE");
MODULE_AUTHOR("DUSAN");
