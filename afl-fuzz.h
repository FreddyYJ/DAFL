//
// Created by root on 3/11/24.
//

#ifndef DAFL_AFL_FUZZ_H
#define DAFL_AFL_FUZZ_H
#include "types.h"

struct proximity_score {
  u64 original;
  double adjusted;
  u32 covered;
  u32 *dfg_count_map; // Sparse map: [count]
  u32 *dfg_dense_map; // Dense map: [index, count]
};

struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
  trim_done,                      /* Trimmed?                         */
  was_fuzzed,                     /* Had any fuzzing done yet?        */
  handled_in_cycle,               /* Was handled in current cycle?    */
  passed_det,                     /* Deterministic stages passed?     */
  has_new_cov,                    /* Triggers new coverage?           */
  var_behavior,                   /* Variable behavior?               */
  favored,                        /* Currently favored?               */
  fs_redundant,                   /* Marked as redundant in the fs?   */
  removed;                        /* Removed from queue?              */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
  exec_cksum;                     /* Checksum of the execution trace  */

  struct proximity_score prox_score;  /* Proximity score of the test case */
  u32 entry_id;                       /* The ID assigned to the test case */

  u64 exec_us,                        /* Execution time (us)              */
  handicap,                       /* Number of queue cycles behind    */
  depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next;           /* Next element, if any             */

};

// Define the vector structure
struct vector {
  struct queue_entry **data;
  size_t size;     // Number of elements currently in the vector
  size_t capacity; // Capacity of the vector (allocated memory size)
};

// Function to initialize a new vector
struct vector* create_vector() {
  struct vector* vec = ck_alloc(sizeof(struct vector));
  if (vec == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  vec->data = NULL;
  vec->size = 0;
  vec->capacity = 0;
  return vec;
}

// Function to add an element to the end of the vector
void push_back(struct vector* vec, struct queue_entry* element) {
  if (vec->size >= vec->capacity) {
    // Increase capacity by doubling it
    vec->capacity = (vec->capacity == 0) ? 8 : vec->capacity * 2;
    vec->data = (struct queue_entry**)ck_realloc(vec->data, vec->capacity * sizeof(struct queue_entry*));
    if (vec->data == NULL) {
      printf("Memory allocation failed.\n");
      exit(EXIT_FAILURE);
    }
  }
  vec->data[vec->size++] = element;
}

void free_vector(struct vector* vec) {
    ck_free(vec->data);
    ck_free(vec);
}

// Hashmap
struct key_value_pair {
  u32 key;
  struct queue_entry* value;
  struct key_value_pair* next;
};

struct hashmap {
  u32 size;
  u32 table_size;
  struct key_value_pair** table;
};

struct hashmap* create_hashmap(u32 table_size) {
  struct hashmap* map = ck_alloc(sizeof(struct hashmap));
  if (map == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  map->size = 0;
  map->table_size = table_size;
  map->table = ck_alloc(table_size * sizeof(struct key_value_pair*));
  if (map->table == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  for (u32 i = 0; i < table_size; i++) {
    map->table[i] = NULL;
  }
  return map;
}

u32 fit_hashmap(u32 key, u32 table_size) {
  return key % table_size;
}

void resize_table(struct hashmap *map) {

  u32 new_table_size = map->table_size * 2;
  struct key_value_pair **new_table = ck_alloc(new_table_size * sizeof(struct key_value_pair*));
  if (new_table == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  for (int i = 0; i < map->table_size; i++) {
    struct key_value_pair* pair = map->table[i];
    while (pair != NULL) {
      struct key_value_pair *next = pair->next;
      u32 index = fit_hashmap(pair->key, new_table_size);
      pair->next = new_table[index];
      new_table[index] = pair;
      pair = next;
    }
  }
  ck_free(map->table);
  map->table = new_table;
  map->table_size = new_table_size;

}

// Function to insert a key-value pair into the hash map
void insert(struct hashmap* map, u32 key, struct queue_entry* value) {
  u32 index = fit_hashmap(key, map->table_size);
  struct key_value_pair* newPair = ck_alloc(sizeof(struct key_value_pair));
  if (newPair == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  newPair->key = key;
  newPair->value = value;
  newPair->next = map->table[index];
  map->table[index] = newPair;
  map->size++;
  if (map->size > map->table_size / 2) {
    resize_table(map);
  }
}

struct key_value_pair* get_from_hashmap(struct hashmap* map, u32 key) {
  u32 index = fit_hashmap(key, map->table_size);
  struct key_value_pair* pair = map->table[index];
  while (pair != NULL) {
    if (pair->key == key) {
      return pair;
    }
    pair = pair->next;
  }
  return NULL;
}

void free_hashmap(struct hashmap* map) {
  for (u32 i = 0; i < map->table_size; i++) {
    struct key_value_pair* pair = map->table[i];
    while (pair != NULL) {
      struct key_value_pair* next = pair->next;
      ck_free(pair);
      pair = next;
    }
  }
  ck_free(map->table);
  ck_free(map);
}

#endif //DAFL_AFL_FUZZ_H
