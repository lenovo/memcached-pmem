/*
 * Copyright 2018 Lenovo
 *
 * Licensed under the BSD-3 license. see LICENSE.Lenovo.txt for full text
 */
#include "memcached.h"
#include <stddef.h>
#include <string.h>

#define PSLAB_POOL_SIG "PMCH"
#define PSLAB_POOL_SIG_SIZE 4
#define PSLAB_POOL_VER_SIZE 12
#define PSLAB_ALIGN_MASK 0xfffffff8

#pragma pack(1)

/* persistent slab pool */
typedef struct {
    char        signature[PSLAB_POOL_SIG_SIZE];
    uint32_t    length; /* 8 bytes aligned */
    char        version[PSLAB_POOL_VER_SIZE];
    uint8_t     reserved;
    uint8_t     checksum[2];
    uint8_t     valid;  /* not checksumed */

    uint64_t    process_started;
    uint32_t    flush_time[2];

    uint32_t    slab_num;
    uint32_t    slab_page_size;
    uint32_t    slabclass_num;
    uint32_t    slabclass_sizes[];
} pslab_pool_t;

#define PSLAB_LINKED 1
#define PSLAB_CHUNKED 2
#define PSLAB_CHUNK 4

typedef struct {
    uint8_t     id;
    uint8_t     flags;       /* non-persistent */
    uint8_t     reserved[6]; /* make slab[] 8 bytes aligned */
    uint32_t    size;
    uint8_t     slab[];
} pslab_t;

#pragma pack()

#define PSLAB_FRAME_SIZE(pm) (sizeof (pslab_t) + (pm)->slab_page_size)
#define PSLAB_FIRST_FRAME(pm) ((pslab_t *)((char *)(pm) + (pm)->length))
#define PSLAB_NEXT_FRAME(pm, fp) \
    ((fp) ? (pslab_t *)((char *)(fp) + PSLAB_FRAME_SIZE(pm)) : \
    PSLAB_FIRST_FRAME(pm))
#define PSLAB_SLAB2FRAME(slab) \
    ((slab) ? (pslab_t *)((char *)(slab) - sizeof (pslab_t)) : NULL)

#define PSLAB_WALK_FROM(fp, s) \
    assert(pslab_start != NULL || ((char *) (s) - (char *) pslab_start) \
            % PSLAB_FRAME_SIZE(pslab_pool) == 0); \
    (fp) = (s) ? (s) : pslab_start; \
    for (int _i = (s) ? ((char *)(s) - (char *) pslab_start) \
            / PSLAB_FRAME_SIZE(pslab_pool) : 0; \
        (fp) >= pslab_start && (fp) < pslab_end; \
        _i++, (fp) = PSLAB_NEXT_FRAME(pslab_pool, (fp)))
#define PSLAB_WALK_ID() (_i)
#define PSLAB_WALK(fp) PSLAB_WALK_FROM((fp), NULL)

static pslab_pool_t *pslab_pool;
static pslab_t *pslab_start, *pslab_end;

uint64_t pslab_addr2off(void *addr) {
    return ((char *) addr >= (char *) pslab_start) ?
        (char *) addr - (char *) pslab_start : 0;
}

#define pslab_off2addr(off) ((off) ? (void *) ((char *)pslab_start + (off)) : NULL)

#define pslab_addr2slab(addr) ((char *) (addr) >= (char *) pslab_start ? \
    (pslab_t *) ((char *)(addr) - ((char *)(addr) - (char *) pslab_start) % \
    PSLAB_FRAME_SIZE(pslab_pool)) : NULL)

int pslab_contains(char *p) {
    if (p >= (char *) pslab_start && p < (char *) pslab_end)
        return 1;
    return 0;
}

void pslab_use_slab(void *p, int id, unsigned int size) {
    pslab_t *fp = PSLAB_SLAB2FRAME(p);
    fp->size = size;
    pmem_member_persist(fp, size);
    fp->id = id;
    pmem_member_persist(fp, id);
}

void *pslab_get_free_slab(void *slab) {
    static pslab_t *cur = NULL;
    pslab_t *fp = PSLAB_SLAB2FRAME(slab);

    if (fp == NULL)
        cur = fp;
    else if (fp != cur)
        return NULL;
    PSLAB_WALK_FROM(fp, PSLAB_NEXT_FRAME(pslab_pool, cur)) {
        if (fp->id == 0 || (fp->flags & (PSLAB_LINKED | PSLAB_CHUNK)) == 0) {
            cur = fp;
            return fp->slab;
        }
    }
    cur = NULL;
    return NULL;
}

static uint8_t pslab_chksum0;

static uint8_t pslab_do_checksum(void *buf, uint32_t len) {
    uint8_t sum = 0;
    uint8_t *end = (uint8_t *)buf + len;
    uint8_t *cur = buf;

    while (cur < end)
        sum = (uint8_t) (sum + *(cur++));
    return sum;
}

#define pslab_do_checksum_member(p, m) \
    pslab_do_checksum(&(p)->m, sizeof ((p)->m))

static void pslab_checksum_init() {
    assert(pslab_pool != NULL);
    pslab_chksum0 = 0;
    pslab_chksum0 += pslab_do_checksum(pslab_pool,
        offsetof(pslab_pool_t, checksum));
    pslab_chksum0 += pslab_do_checksum_member(pslab_pool, process_started);
    pslab_chksum0 += pslab_do_checksum(&pslab_pool->slab_num,
        pslab_pool->length - offsetof(pslab_pool_t, slab_num));
}

static uint8_t pslab_checksum_check(int i) {
    uint8_t sum = pslab_chksum0;
    sum += pslab_do_checksum_member(pslab_pool, checksum[i]);
    sum += pslab_do_checksum_member(pslab_pool, flush_time[i]);
    return sum;
}

static void pslab_checksum_update(int sum, int i) {
    pslab_pool->checksum[i] = (uint8_t) (~(pslab_chksum0 + sum) + 1);
}

void pslab_update_flushtime(uint32_t time) {
    int i = (pslab_pool->valid - 1) ^ 1;

    pslab_pool->flush_time[i] = time;
    pslab_checksum_update(pslab_do_checksum(&time, sizeof (time)), i);
    pmem_member_flush(pslab_pool, flush_time);
    pmem_member_persist(pslab_pool, checksum);

    pslab_pool->valid = i + 1;
    pmem_member_persist(pslab_pool, valid);
}

time_t pslab_process_started(time_t process_started) {
    static time_t process_started_new;

    if (process_started) {
        process_started_new = process_started;
        return pslab_pool->process_started;
    } else {
        return process_started_new;
    }
}

int pslab_do_recover() {
    pslab_t *fp;
    uint8_t *ptr;
    int i, size, perslab;

    settings.oldest_live = pslab_pool->flush_time[pslab_pool->valid - 1];

    /* current_time will be resetted by clock_handler afterwards. Set
     * it temporarily, so that functions depending on it can be reused
     * during recovery */
    current_time = process_started - pslab_pool->process_started;

    PSLAB_WALK(fp) {
        fp->flags = 0;
    }

    /* check for linked and chunked slabs and mark all chunks */
    PSLAB_WALK(fp) {
        if (fp->id == 0)
            continue;
        size = fp->size;
        perslab = pslab_pool->slab_page_size / size;
        for (i = 0, ptr = fp->slab; i < perslab; i++, ptr += size) {
            item *it = (item *) ptr;

            if (it->it_flags & ITEM_LINKED) {
                if (item_is_flushed(it) ||
                        (it->exptime != 0 && it->exptime <= current_time)) {
                    it->it_flags = ITEM_PSLAB;
                    pmem_member_persist(it, it_flags);
                } else {
                    fp->flags |= PSLAB_LINKED;
                    if (it->it_flags & ITEM_CHUNKED)
                        fp->flags |= PSLAB_CHUNKED;
                }
            } else if (it->it_flags & ITEM_CHUNK) {
                ((item_chunk *)it)->head = NULL; /* non-persistent */
            }
        }
    }

    /* relink alive chunks */
    PSLAB_WALK(fp) {
        if (fp->id == 0 || (fp->flags & PSLAB_CHUNKED) == 0)
            continue;

        size = fp->size;
        perslab = pslab_pool->slab_page_size / size;
        for (i = 0, ptr = fp->slab; i < perslab; i++, ptr += size) {
            item *it = (item *) ptr;

            if ((it->it_flags & ITEM_LINKED) && (it->it_flags & ITEM_CHUNKED)) {
                item_chunk *nch;
                item_chunk *ch = (item_chunk *) ITEM_data(it);
                ch->head = it;
                while ((nch = pslab_off2addr(ch->next_poff)) != NULL) {
                    pslab_t *nfp = pslab_addr2slab(nch);
                    nfp->flags |= PSLAB_CHUNK;

                    nch->head = it;
                    ch->next = nch;
                    nch->prev = ch;
                    ch = nch;
                }
            }
        }
    }

    /* relink linked slabs and free free ones */
    PSLAB_WALK(fp) {
        int id;

        if (fp->id == 0 || (fp->flags & (PSLAB_LINKED | PSLAB_CHUNK)) == 0)
            continue;

        if (do_slabs_renewslab(fp->id, (char *)fp->slab) == 0)
            return -1;

        id = fp->id;
        size = fp->size;
        perslab = pslab_pool->slab_page_size / size;
        for (i = 0, ptr = fp->slab; i < perslab; i++, ptr += size) {
            item *it = (item *) ptr;
            if (it->it_flags & ITEM_LINKED) {
                do_slab_realloc(it, id);
                do_item_relink(it, hash(ITEM_key(it), it->nkey));
            } else if ((it->it_flags & ITEM_CHUNK) == 0 ||
                    ((item_chunk *)it)->head == NULL) {
                assert((it->it_flags & ITEM_CHUNKED) == 0);
                do_slabs_free(ptr, 0, id);
            }
        }
    }

    return 0;
}

int pslab_pre_recover(char *name, uint32_t *slab_sizes, int slab_max,
        int slab_page_size) {
    size_t mapped_len;
    int is_pmem;
    int i;

    if ((pslab_pool = pmem_map_file(name, 0, PMEM_FILE_EXCL,
            0, &mapped_len, &is_pmem)) == NULL) {
        fprintf(stderr, "pmem_map_file failed\n");
        return -1;
    }
    if (!is_pmem && (pslab_force == false)) {
        fprintf(stderr, "%s is not persistent memory\n", name);
        return -1;
    }
    if (strncmp(pslab_pool->signature, PSLAB_POOL_SIG, PSLAB_POOL_SIG_SIZE) != 0) {
        fprintf(stderr, "pslab pool unknown signature\n");
        return -1;
    }
    pslab_checksum_init();
    if (pslab_checksum_check(pslab_pool->valid - 1)) {
        fprintf(stderr, "pslab pool bad checksum\n");
        return -1;
    }
    if (strncmp(pslab_pool->version, VERSION, PSLAB_POOL_VER_SIZE) != 0) {
        fprintf(stderr, "pslab pool version mismatch\n");
        return -1;
    }
    if (pslab_pool->slab_page_size != slab_page_size) {
        fprintf(stderr, "pslab pool slab size mismatch\n");
        return -1;
    }

    assert(slab_max > pslab_pool->slabclass_num);
    for (i = 0; i < pslab_pool->slabclass_num; i++)
        slab_sizes[i] = pslab_pool->slabclass_sizes[i];
    slab_sizes[i] = 0;

    pslab_start = PSLAB_FIRST_FRAME(pslab_pool);
    pslab_end = (pslab_t *) ((char *) pslab_start + pslab_pool->slab_num
       * PSLAB_FRAME_SIZE(pslab_pool));

    return 0;
}

bool pslab_force;

int pslab_create(char *pool_name, uint32_t pool_size, uint32_t slab_page_size,
        uint32_t *slabclass_sizes, int slabclass_num) {

    size_t mapped_len;
    int is_pmem;
    uint32_t length;
    pslab_t *fp;
    int i;

    if ((pslab_pool = pmem_map_file(pool_name, pool_size,
            PMEM_FILE_CREATE, 0666, &mapped_len, &is_pmem)) == NULL) {
        fprintf(stderr, "pmem_map_file failed\n");
        return -1;
    }
    if (!is_pmem && (pslab_force == false)) {
        fprintf(stderr, "%s is not persistent memory\n", pool_name);
        return -1;
    }

    length = (sizeof (pslab_pool_t) + sizeof (pslab_pool->slabclass_sizes[0])
        * slabclass_num + 7) & PSLAB_ALIGN_MASK;
    pmem_memset_nodrain(pslab_pool, 0, length);

    (void) memcpy(pslab_pool->signature, PSLAB_POOL_SIG, PSLAB_POOL_SIG_SIZE);
    pslab_pool->length = length;
    snprintf(pslab_pool->version, PSLAB_POOL_VER_SIZE, VERSION);
    pslab_pool->slab_page_size = slab_page_size;
    pslab_pool->slab_num = (pool_size - pslab_pool->length)
        / PSLAB_FRAME_SIZE(pslab_pool);

    pslab_start = PSLAB_FIRST_FRAME(pslab_pool);
    pslab_end = (pslab_t *) ((char *) pslab_start + pslab_pool->slab_num
        * PSLAB_FRAME_SIZE(pslab_pool));

    PSLAB_WALK(fp) {
        pmem_memset_nodrain(fp, 0, sizeof (pslab_t));
    }

    pslab_pool->slabclass_num = slabclass_num;
    for (i = 0; i < slabclass_num; i++)
        pslab_pool->slabclass_sizes[i] = slabclass_sizes[i];

    assert(process_started != 0);
    pslab_pool->process_started = (uint64_t) process_started;

    pslab_checksum_init();
    pslab_checksum_update(0, 0);

    pmem_persist(pslab_pool, pslab_pool->length);

    pslab_pool->valid = 1;
    pmem_member_persist(pslab_pool, valid);

    return 0;
}
