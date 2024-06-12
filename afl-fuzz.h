//
// Created by root on 3/11/24.
//

#ifndef DAFL_AFL_FUZZ_H
#define DAFL_AFL_FUZZ_H
#include "types.h"
#include "debug.h"

// For interval tree: should be power of 2
#define INTERVAL_SIZE 1024

struct proximity_score {
  u64 original;
  double adjusted;
  u32 covered;
  u32 *dfg_count_map; // Sparse map: [count]
  u32 *dfg_dense_map; // Dense map: [index, count]
};

struct dfg_node_info {
  u32 idx;
  u32 score;
  u32 max_paths;
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
  exec_cksum,                     /* Checksum of the execution trace  */
  dfg_cksum;

  struct proximity_score prox_score;  /* Proximity score of the test case */
  u32 entry_id;                       /* The ID assigned to the test case */
  s32 rank;                           /* Pareto rank of the test case     */

  u64 exec_us,                        /* Execution time (us)              */
  handicap,                       /* Number of queue cycles behind    */
  depth;                          /* Path depth                       */

  u8* trace_mini;                     /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next;           /* Next element, if any             */
  struct queue_entry *next_moo;       /* Next element in the MOO queue    */
  struct queue_entry *prev_moo;       /* Prev element in MOO queue */

};

u32 quantize_location(double loc) {
  return (u32)(loc * INTERVAL_SIZE);
}

// Binary tree
struct interval_node {
  u32 start;
  u32 end;
  u64 count;
  u64 score;
  struct interval_node *left;
  struct interval_node *right;
};

struct interval_tree {
  u64 count[INTERVAL_SIZE];
  u64 score[INTERVAL_SIZE];
  struct interval_node *root;
};

struct interval_node *interval_node_create(u32 start, u32 end);

void interval_node_free(struct interval_node *node);

double interval_tree_query(struct interval_tree *tree, struct interval_node *node);

double interval_node_ratio(struct interval_node *node);

struct interval_node *interval_node_insert(struct interval_tree *tree, struct interval_node *node, u32 key, u32 value);

struct interval_tree *interval_tree_create();

void interval_tree_free(struct interval_tree *tree);

void interval_tree_insert(struct interval_tree *tree, u32 key, u32 value);

u32 interval_node_select(struct interval_node *node);

u32 interval_tree_select(struct interval_tree *tree);

// Define the vector structure
struct vector {
  struct queue_entry **data;
  size_t size;     // Number of elements currently in the vector
  size_t capacity; // Capacity of the vector (allocated memory size)
};

// Function to initialize a new vector
struct vector* vector_create(void) {
  struct vector* vec = ck_alloc(sizeof(struct vector));
  if (vec == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  vec->size = 0;
  vec->capacity = 0;
  vec->data = NULL;
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

void vector_push_front(struct vector *vec, struct queue_entry *element) {
  push_back(vec, element);
  for (u32 i = vec->size - 1; i > 0; i--) {
    vec->data[i] = vec->data[i - 1];
  }
  vec->data[0] = element;
}

struct queue_entry * vector_pop_front(struct vector *vec) {
  if (vec->size == 0) return NULL;
  struct queue_entry *entry = vec->data[0];
  for (u32 i = 0; i < vec->size - 1; i++) {
    vec->data[i] = vec->data[i + 1];
  }
  vec->size--;
  return entry;
}

void vector_free(struct vector* vec) {
  ck_free(vec->data);
  ck_free(vec);
}

struct vector *list_to_vector(struct queue_entry *list) {
  struct vector *vec = vector_create();
  struct queue_entry *q = list;
  while (q != NULL) {
    push_back(vec, q);
    q = q->next_moo;
  }
  return vec;
}

struct queue_entry *vector_to_list(struct vector *vec) {
  struct queue_entry *list = NULL;
  struct queue_entry *prev = NULL;
  for (u32 i = 0; i < vec->size; i++) {
    // Construct the list, skip the NULL entries
    struct queue_entry *entry = vec->data[i];
    if (entry) {
      entry->prev_moo = prev;
      entry->next_moo = NULL;
      if (prev) prev->next_moo = entry;
      prev = entry;
      if (!list) list = entry;
    }
  }
  return list;
}

struct queue_entry* vector_get(struct vector* vec, u32 index) {
  if (index >= vec->size) {
    return NULL;
  }
  return vec->data[index];
}

void vector_set(struct vector* vec, u32 index, struct queue_entry* element) {
  if (index < vec->size) {
    vec->data[index] = element;
  }
}

u32 vector_size(struct vector* vec) {
  return vec->size;
}

// Hashmap
struct key_value_pair {
  u32 key;
  void* value;
  struct key_value_pair* next;
};

struct hashmap {
  u32 size;
  u32 table_size;
  struct key_value_pair** table;
};

typedef void (*hashmap_iterate_fn)(u32 key, void* value);

struct hashmap* hashmap_create(u32 table_size) {
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

static u32 hashmap_fit(u32 key, u32 table_size) {
  return key % table_size;
}

static void hashmap_resize(struct hashmap *map) {

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
      u32 index = hashmap_fit(pair->key, new_table_size);
      pair->next = new_table[index];
      new_table[index] = pair;
      pair = next;
    }
  }
  ck_free(map->table);
  map->table = new_table;
  map->table_size = new_table_size;

}

u32 hashmap_size(struct hashmap* map) {
  return map->size;
}

// Function to insert a key-value pair into the hash map
void hashmap_insert(struct hashmap* map, u32 key, void* value) {
  u32 index = hashmap_fit(key, map->table_size);
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
    hashmap_resize(map);
  }
}

void hashmap_remove(struct hashmap *map, u32 key) {
  u32 index = hashmap_fit(key, map->table_size);
  struct key_value_pair* pair = map->table[index];
  struct key_value_pair* prev = NULL;
  while (pair != NULL) {
    if (pair->key == key) {
      if (!prev) {
        map->table[index] = pair->next;
      } else {
        prev->next = pair->next;
      }
      map->size--;
      ck_free(pair);
      return;
    }
    prev = pair;
    pair = pair->next;
  }
}

struct key_value_pair* hashmap_get(struct hashmap* map, u32 key) {
  u32 index = hashmap_fit(key, map->table_size);
  struct key_value_pair* pair = map->table[index];
  while (pair != NULL) {
    if (pair->key == key) {
      return pair;
    }
    pair = pair->next;
  }
  return NULL;
}

void hashmap_iterate(struct hashmap *map, hashmap_iterate_fn func) {
  for (u32 i = 0; i < map->table_size; i++) {
    struct key_value_pair *pair = map->table[i];
    while (pair != NULL) {
      func(pair->key, pair->value);
      pair = pair->next;
    }
  }
}

void hashmap_free(struct hashmap* map) {
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

struct vertical_entry {
  u32 hash;
  u32 use_count;
  struct vector *entries;
  struct vertical_entry *next;
  struct hashmap *value_map;  // valuation hash
};

struct vertical_manager {
  struct hashmap *map; // path -> vertical_entry
  struct vertical_entry *head;
  struct vertical_entry *old;
  struct interval_tree *tree;
  u64 start_time;
  u8 dynamic_mode;
  u8 use_vertical;
};

struct vertical_entry *vertical_entry_create(u32 hash) {
  struct vertical_entry *entry = ck_alloc(sizeof(struct vertical_entry));
  entry->hash = hash;
  entry->use_count = 0;
  entry->entries = vector_create();
  entry->next = NULL;
  entry->value_map = hashmap_create(8);
  return entry;
}

void vertical_entry_add(struct vertical_manager *manager, struct vertical_entry *entry, struct queue_entry *q, struct key_value_pair *kvp) {
  if (!q) return;
  if (vector_size(entry->entries) == 0) {
    push_back(entry->entries, q);
    // This is the first seed for this dug-path
    // Insert the entry to the queue
    // If valuation is unique, insert to the front
    if (!manager->head || !kvp) {
      entry->next = manager->head;
      manager->head = entry;
    } else {
      // If valuation is not unique, insert to the end
      struct vertical_entry *ve = manager->head;
      while (ve->next != NULL) {
        ve = ve->next;
      }
      ve->next = entry;
      entry->next = NULL;
    }
  } else {
    // If valuation is unique, move to the front
    if (!kvp) {
      vector_push_front(entry->entries, q);
      struct vertical_entry *ve = manager->head;
      struct vertical_entry *prev = NULL;
      while (ve != NULL) {
        if (ve == entry) {
          if (prev) {
            prev->next = ve->next;
            ve->next = manager->head;
            manager->head = ve;
          }
          break;
        }
        prev = ve;
        ve = ve->next;
      }
    } else {
      push_back(entry->entries, q);
    }
  }
}

struct vertical_manager *vertical_manager_create();

struct vertical_entry *vertical_manager_select(struct vertical_manager *manager);

u8 vertical_manager_select_mode(struct vertical_manager *manager);

u8 vertical_manager_get_mode(struct vertical_manager *manager) {
  return manager->use_vertical;
}

void vertical_manager_set_mode(struct vertical_manager *manager, u8 use_vertical) {
  manager->use_vertical = use_vertical;
}

void vertical_manager_insert_to_old(struct vertical_manager *manager, struct vertical_entry *entry) {
  if (manager->old == NULL) {
    manager->old = entry;
  } else {
    struct vertical_entry *ve = manager->old;
    while (ve->next != NULL) {
      ve = ve->next;
    }
    ve->next = entry;
  }
}

void vertical_manager_free(struct vertical_manager *manager) {
  if (manager == NULL) return;
  hashmap_free(manager->map);
  struct vertical_entry *entry = manager->head;
  while (entry != NULL) {
    struct vertical_entry *next = entry->next;
    vector_free(entry->entries);
    hashmap_free(entry->value_map);
    ck_free(entry);
    entry = next;
  }
  entry = manager->old;
  while (entry != NULL) {
    struct vertical_entry *next = entry->next;
    vector_free(entry->entries);
    hashmap_free(entry->value_map);
    ck_free(entry);
    entry = next;
  }
  interval_tree_free(manager->tree);
  ck_free(manager);
}


#endif //DAFL_AFL_FUZZ_H
