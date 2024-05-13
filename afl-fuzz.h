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

};

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */
inline u32 UR(u32 limit);

u32 quantize_location(double loc) {
  return (u32)(loc * INTERVAL_SIZE);
}

// Binary tree
struct interval_node {
  u8 split;
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

struct interval_node *interval_node_create(u32 start, u32 end) {
  struct interval_node *node = ck_alloc(sizeof(struct interval_node));
  if (node == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  node->split = 0;
  node->start = start;
  node->end = end;
  node->count = 0;
  node->score = 0;
  node->left = NULL;
  node->right = NULL;
  if (end > start) {
    u32 mid = (start + end) / 2;
    node->left = interval_node_create(start, mid);
    node->right = interval_node_create(mid + 1, end);
  }
  return node;
}

void interval_node_free(struct interval_node *node) {
  if (node == NULL) {
    return;
  }
  interval_node_free(node->left);
  interval_node_free(node->right);
  ck_free(node);
}

double interval_tree_query(struct interval_tree *tree, struct interval_node *node) {
  u64 total_count = 0;
  u64 total_score = 0;
  for (u32 i = node->start; i <= node->end; i++) {
    total_count += tree->count[i];
    total_score += tree->score[i];
  }
  node->count = total_count;
  node->score = total_score;
  if (total_count == 0) return 0.0;
  return (double)total_score / (double)total_count;
}

double interval_node_ratio(struct interval_node *node) {
  if (!node) return 0.0;
  if (node->count == 0) return 0.0;
  return (double)(node->score) / (double)(node->count);
}

u8 should_split(double a, double b) {
  if (a == 0.0 || b == 0.0) return 0;
  if (a < b) {
    return (b / a) > 1.5;
  } else {
    return (a / b) > 1.5;
  }
}

void interval_node_split(struct interval_tree *tree, struct interval_node *node) {
  node->split = 0;
  if ((node->end - node->start) < 2) {
    return;
  }
  u32 mid = (node->start + node->end) / 2;
  node->left = interval_node_create(node->start, mid, 1);
  node->right = interval_node_create(mid + 1, node->end, 1);
  interval_tree_query(tree, node->left);
  interval_tree_query(tree, node->right);
}

struct interval_node *interval_node_insert(struct interval_tree *tree, struct interval_node *node, u32 key, u32 value) {
  if (!node) return node;
  node->count++;
  node->score += value;
  if (node->end - node->start < 2) {
    return node;
  }
  u32 mid = (node->start + node->end) / 2;
  if (node->left && node->right) {
    if (key <= mid) {
      interval_node_insert(tree, node->left, key, value);
    } else {
      interval_node_insert(tree, node->right, key, value);
    }
    if (!node->split) {
      double left_ratio = interval_node_ratio(node->left);
      double right_ratio = interval_node_ratio(node->right);
      if (should_split(left_ratio, right_ratio)) {
        node->split = 1;
        if (left_ratio > right_ratio) {
          if (key <= mid) interval_node_insert(tree, node->left, key, value);
        } else {
          if (key > mid) interval_node_insert(tree, node->right, key, value);
        }
      }
    }
  }
}

struct interval_tree *interval_tree_create() {
  struct interval_tree *tree = ck_alloc(sizeof(struct interval_tree));
  if (tree == NULL) {
    printf("Memory allocation failed.\n");
    exit(EXIT_FAILURE);
  }
  tree->root = interval_node_create(0, INTERVAL_SIZE - 1, 1);
  return tree;
}

void interval_tree_free(struct interval_tree *tree) {
  interval_node_free(tree->root);
  ck_free(tree);
}

void interval_tree_insert(struct interval_tree *tree, u32 key, u32 value) {
  if (!tree) return;
  if (key >= INTERVAL_SIZE) {
    fprintf(stderr, "Key out of range: %u\n", key);
    return;
  }
  tree->count[key]++;
  tree->score[key] += value;
  interval_node_insert(tree, tree->root, key, value);
}

u32 interval_tree_select(struct interval_tree *tree) {
  if (!tree || tree->count < INTERVAL_SIZE) {
    return UR(INTERVAL_SIZE);
  }

}

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
  struct queue_entry *tail = NULL;
  for (u32 i = 0; i < vec->size; i++) {
    // Construct the list, skip the NULL entries
    struct queue_entry *entry = vec->data[i];
    if (entry) {
      if (!list) list = entry;
      if (tail) tail->next_moo = entry;
      tail = entry;
      tail->next_moo = NULL;
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

#endif //DAFL_AFL_FUZZ_H
