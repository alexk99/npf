/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <semaphore.h>

#include "stand/npf_stand.h"
#include "npf_portmap.h"
#include "MersenneTwister.h"

static unsigned			nsec = 10; /* seconds */

pthread_t *thr;

uint64_t num_iterations = 40000000000;

static pthread_barrier_t	barrier;
static unsigned			nworkers;
static volatile bool		stop;
void* mersenne_twister;

#define	CACHE_LINE_SIZE		64

npf_portmap_hash_t* pmh;

sem_t begin_sema[4];
sem_t end_sema;

static void *
test1_worker(void *arg)
{
	const unsigned id = (uintptr_t)arg;

	while (true) {
		/* wait for start signal */
		sem_wait(&begin_sema[id]);
		pthread_barrier_wait(&barrier);

		if (stop)
			break;

		/* random delay */
		while (mersenne_twister_integer(mersenne_twister) % 8 != 0) {}
		//usleep(random() % 1000);

		if (id == 0) {
			// printf("get\n");
			npf_portmap_get(pmh, 1);
		}
		else if (id == 1) {
			// printf("return\n");
			assert(npf_portmap_return(pmh, 1) == 0);
		}
		else if (id == 2) {
			// printf("return\n");
			npf_portmap_get(pmh, 1);
		}

		/* notify transaction complete */
		sem_post(&end_sema);
	}

	pthread_exit(NULL);
	return NULL;
}

static void
ding(int sig)
{
	(void)sig;
	stop = true;
}


static uint32_t
portmap_gc_list_size(void)
{
	/* determine size of gc list */
	npf_portmap_entry_t *e = pmh->gc_list;
	uint32_t cnt = 0;

	while (e != NULL) {
		e = e->next;
		cnt++;
	}

	return cnt;
}

static void
run_test_1(void)
{
	uint64_t last_iter = 0;
	uint64_t i;
	pmh = npf_portmap_init();

	/* Initialize the semaphores */
	sem_init(&begin_sema[0], 0, 0);
	sem_init(&begin_sema[1], 0, 0);
	sem_init(&end_sema, 0, 0);

	stop = false;
	uint64_t cnt1 = 0;
	uint32_t gc_size;

	/* 2 worerks: put and return */
	uint32_t nworkers = 2;
	thr = calloc(nworkers, sizeof(pthread_t));
	pthread_barrier_init(&barrier, NULL, nworkers);

	for (i=0; i<nworkers; i++) {
		if ((errno = pthread_create(&thr[i], NULL,
		    test1_worker, (void *)(uintptr_t)i)) != 0) {
			err(EXIT_FAILURE, "pthread_create");
		}
	}

	for (i=0; i<num_iterations; i++) {
		npf_portmap_entry_t* pme = npf_portmap_get(pmh, 1);

		/* signal both threads to start */
		// printf("start iteration %u\n", i);
		sem_post(&begin_sema[0]);
		sem_post(&begin_sema[1]);

		/* Wait for both threads */
		// printf("stop iteration %u\n", i);
		sem_wait(&end_sema);
		sem_wait(&end_sema);

		/* check test results */
		npf_portmap_entry_t* pme2 = npf_portmap_get(pmh, 1);
		assert(pme2->p_refcnt == 2);
		gc_size = portmap_gc_list_size();
		if (pme2 == pme) {
			/* put was before return, so no new pm was created */
			assert(gc_size == 0);
			cnt1++;
			// printf("no NEW pm\n");
		}
		else {
			assert(gc_size == 1);
			// printf("new pm created\n");
		}

		/* delete pm */
		assert(npf_portmap_return(pmh, 1) == 0);
		assert(npf_portmap_return(pmh, 1) == 0);

		gc_size = portmap_gc_list_size();
		// printf("gcsize after cleanup %u\n", gc_size);
		if (pme2 == pme) {
			assert(gc_size == 1);
		}
		else {
			assert(gc_size == 2);
		}

		npf_portmap_gc(pmh);
		gc_size = portmap_gc_list_size();
		assert(gc_size == 0);

		if (last_iter != (i >> 20))
			printf("cnt1 = %lu\n", cnt1);

		last_iter = i >> 20;
	}

	/* stop the workers */
	stop = true;
	sem_post(&begin_sema[0]);
	sem_post(&begin_sema[1]);

	/* wait workers to end */
	for (unsigned i = 0; i < nworkers; i++)
		pthread_join(thr[i], NULL);

	pthread_barrier_destroy(&barrier);

	printf("cnt1 = %lu\n", cnt1);
}

static void
run_test_2(void)
{
	uint64_t last_iter = 0;
	uint64_t i;
	pmh = npf_portmap_init();

	/* Initialize the semaphores */
	sem_init(&begin_sema[0], 0, 0);
	sem_init(&begin_sema[1], 0, 0);
	sem_init(&begin_sema[2], 0, 0);
	sem_init(&end_sema, 0, 0);

	stop = false;
	uint64_t cnt1 = 0;
	uint32_t gc_size;

	/* 2 worerks: put and return */
	uint32_t nworkers = 3;
	thr = calloc(nworkers, sizeof(pthread_t));
	pthread_barrier_init(&barrier, NULL, nworkers);

	for (i=0; i<nworkers; i++) {
		if ((errno = pthread_create(&thr[i], NULL,
		    test1_worker, (void *)(uintptr_t)i)) != 0) {
			err(EXIT_FAILURE, "pthread_create");
		}
	}

	for (i=0; i<num_iterations; i++) {
		npf_portmap_entry_t* pme = npf_portmap_get(pmh, 1);
		assert(pme->p_refcnt == 1);

		/* signal both threads to start */
		// printf("start iteration %u\n", i);
		sem_post(&begin_sema[0]);
		sem_post(&begin_sema[1]);
		sem_post(&begin_sema[2]);

		/* Wait for both threads */
		// printf("stop iteration %u\n", i);
		sem_wait(&end_sema);
		sem_wait(&end_sema);
		sem_wait(&end_sema);

		/* check test results */
		npf_portmap_entry_t* pme2 = npf_portmap_get(pmh, 1);
		assert(pme2->p_refcnt == 3);
		gc_size = portmap_gc_list_size();
		if (pme2 == pme) {
			/* put was before return, so no new pm was created */
			assert(gc_size == 0);
			cnt1++;
			// printf("no NEW pm\n");
		}
		else {
			assert(gc_size == 1);
			// printf("new pm created\n");
		}

		/* delete pm */
		assert(npf_portmap_return(pmh, 1) == 0);
		assert(npf_portmap_return(pmh, 1) == 0);
		assert(npf_portmap_return(pmh, 1) == 0);

		gc_size = portmap_gc_list_size();
		// printf("gcsize after cleanup %u\n", gc_size);
		if (pme2 == pme) {
			assert(gc_size == 1);
		}
		else {
			assert(gc_size == 2);
		}

		npf_portmap_gc(pmh);
		gc_size = portmap_gc_list_size();
		assert(gc_size == 0);

		if (last_iter != (i >> 20))
			printf("cnt1 %lu of %lu, %lu\n", cnt1, i, i - cnt1);

		last_iter = i >> 20;
	}

	/* stop the workers */
	stop = true;
	sem_post(&begin_sema[0]);
	sem_post(&begin_sema[1]);
	sem_post(&begin_sema[2]);

	/* wait workers to end */
	for (unsigned i = 0; i < nworkers; i++)
		pthread_join(thr[i], NULL);

	pthread_barrier_destroy(&barrier);

	printf("cnt1 %lu of %lu\n", cnt1, num_iterations);
}

int
main(int argc, char **argv)
{
	if (argc >= 2) {
		nsec = (unsigned)atoi(argv[1]);
	}

	mersenne_twister = mersenne_twister_create(1);

	run_test_2();

	puts("ok");
	return 0;
}
