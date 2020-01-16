# Modifikacija i rebuild-ovanje Linux kernela

Zadatak: Modifikuje se prioritet procesa i parametri raspoređivanja procesa, tako da se utiče na algoritam raspoređivanja za proces sa zadatim PID-om i eventualno grupu procesa "braće/sestara".

## Upravljanje i rasporedjivanje procesa

Upravljanje izvršavanjem procesa je jedan od zadataka kernela. Kao primer, koristiće se trenutna stabilna verzija 5.4.12.

Za vođenje evidencije o svim procesima, kernel se oslanja na *deskriptore procesa* definisane strukturom `struct task_struct` sa izvorom u `<include/linux/sched.h>`. Na stack-u svakog procesa koja se izvršava se nalazi pokazivač na ovu strukturu, a kernel, sa druge strane, poseduje listu svih deskriptora procesa koji se izvršavaju. Takođe, makro `current` može se koristiti sa pribavljanje informacija o procesu koji se trenutno izvršava.

```c
struct task_struct {
 volatile long state; /* -1 unrunnable, 0 runnable, >0 stopped */
 void *stack;
 …
 unsigned int flags; /* per process flags */
 …
 struct mm_struct *mm;
 …
 pid_t pid;
 pid_t tgid;
 …
 struct task_struct __rcu *real_parent; /* real parent process */
 struct list_head children; /* list of my children */
 struct list_head sibling; /* linkage in my parent's children list */
 …
 int prio, static_prio, normal_prio;
 unsigned int rt_priority;
 const struct sched_class *sched_class;
 struct sched_entity se;
 struct sched_rt_entity rt;
 …
 unsigned int policy;
 cpumask_t cpus_allowed;
 …
}
```

Prilikom pokretanja procesa, operativni sistem alocira potrebnu memoriju za deskriptor i istu oslobađa nakon prekidanja procesa. Interno, koristi se **dvostruko-spregnuta lančana lista** deskriptora svih aktivnih procesa.

Linux je operativni sistem koji dozvoljava izvršavanje više simultanih procesa na jednom procesoru istovremeno. Na jedno-procesorskom (jedno-jezgralnom) sistemu, u jednom trenutku može biti izvršavan samo jedan proces, rasporedjivanjem procesa se daje privid konkurentosti. Deo kernela koji vodi računa o tome koji proces će se u nekom trenutku izvršavati je *process scheduler*. Ovaj modul određuje koji će se proces sledeći izvršavati i održava redosled onih procesa koji čekaju. Deo vremena koji proces dobija naziva se *timeslice*, a suspendovanje procesa od strane kernela *preemption* do koga može doći nakon isteka pomenutog vremena.

Polja `task_struct` strukture koja se koriste u procesu raspoređivanja:
1. `prio` određuje nivo prioriteta procesa u sistemu
2. `rt_priority` takođe, samo za real-time procese
3. `sched_entity` za grupno raspoređivanje
4. `policy` određuje polisu raspoređivanja procesa što može da dovede do posebnih odluka (npr. `SCHED_OTHER` ili `SCHED_RR`)
5. `cpus_allowed` određuje afinitet ka jezgrima procesora

### Prioritet procesa

Prioritet se zasniva na vrednosti dodeljenoj od strane kernela koja upravlja daljim odlukama pri raspoređivanju. Porede se vrednosti više procesa i izvlači zaključak koji je "važniji", a samim tim i koji proces će dobiti deo procesorskog vremena. Svaki proces dobija `nice` atribut i granicama od -20 do +19. Što je ovaj atribut veći, prioritet procesa je manji jer je "bolji" prema ostalim procesima.

```
       <— veći prioritet
 -20 _ _ _ _ _  0  _ _ _ _ _ +19
```

Pored običnih procesa čiji se `nice` atributi razmatraju, postoje i *real-time procesi*. Ovi procesi garantuju svoje izvršenje u jasnim vremenskim granicama. Njihovi prioriteti su u granicama od 0 do +99 gde veća vrednost znači i veći prioritet. Ovi procesi su važniji od prethodnih i imaće prednost.


```
       veći prioritet ——>
 0 _ _ _ _ _ _ _ _ _ _ _ _ _ +99
 
```

Dva pomenuta atributa su u `task_struct` strukturi prisutna redom kao `prio` i `rt_priority`.

Interno, kernel formira skalu u opsegu od 0 do +139 za razmatranje prioriteta svih aktivnih procesa. Skala je inverotvana i manje vrednosti znače veći prioritet. Vrednosti od 0 do +99 su rezervisani za real-time procese, a preostalih +100 do +139 (koji su preslikani sa skale -20 do +19) za normalne procese.

```
                      <— veći prioritet
0_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _99_100_ _ _ _ _ _ _ _ _ _ _139
              real-time                           normal
 
```

Svi atributi `task_struct` strukture koji na kraju određuju prioritet su `int prio`, `static_prio`, `normal_prio` i
`unsigned int rt_priority`. `static_prio` je vrednost statiči postavljena od strane korisnika ili eventualno od strane kernela izvedena iz `nice` vrednosti. `normal_prio` sadrži vrednost izvedenu iz prethodne i polise dodeljene procesu. Procesi istih vrednosti `static_prio` atributa ali različitih polisa će imati različite vrednosti `normal_prio`. `prio` je dinamički prioritet na koji kernel utiče ukoliko treba da se podigne ili spusti nivo zastupljenosti procesa.

### Promena prioriteta procesa

Takođe, nakon promene `static_prio` atributa dolazi do preračunavanja `prio` vrednosti po:

`process->prio = effective_prio(process);`

U ovom prelazu se računa i atribut normalnog prioriteta `normal_prio`. Ako je u pitanju real-time proces gleda se `rt_priority`, a za obične procese se samo preuzima setovana vrednost `static_prio` i koristi za predefinisanje više atributa što na kraju uključuje i `prio`, odnosno `nice` vrednost.

`https://github.com/torvalds/linux/blob/master/kernel/sched/core.c`

```c
/*
 * Calculate the current priority, i.e. the priority
 * taken into account by the scheduler. This value might
 * be boosted by RT tasks, or might be boosted by
 * interactivity modifiers. Will be RT if the task got
 * RT-boosted. If not then it returns p->normal_prio.
 */
static int effective_prio(struct task_struct *p)
{
	p->normal_prio = normal_prio(p);
	/*
	 * If we are RT tasks or we were boosted to RT priority,
	 * keep the priority unchanged. Otherwise, update priority
	 * to the normal priority:
	 */
	if (!rt_prio(p->prio))
		return p->normal_prio;
	return p->prio;
}
```

```c
/*
 * __normal_prio - return the priority that is based on the static prio
 */
static inline int __normal_prio(struct task_struct *p)
{
	return p->static_prio;
}

/*
 * Calculate the expected normal priority: i.e. priority
 * without taking RT-inheritance into account. Might be
 * boosted by interactivity modifiers. Changes upon fork,
 * setprio syscalls, and whenever the interactivity
 * estimator recalculates.
 */
static inline int normal_prio(struct task_struct *p)
{
	int prio;

	if (task_has_dl_policy(p))
		prio = MAX_DL_PRIO-1;
	else if (task_has_rt_policy(p))
		prio = MAX_RT_PRIO-1 - p->rt_priority;
	else
		prio = __normal_prio(p);
	return prio;
}
```
