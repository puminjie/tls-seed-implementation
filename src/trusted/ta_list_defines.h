/**
 * @file ta_list_defines.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define the macros to implement a generic list
 */

#ifndef __TA_LIST_DEFINES_H__
#define __TA_LIST_DEFINES_H__

#include <string.h>
#include <inttypes.h>
#include "ta_defines.h"
#include "ta_buf.h"

/**
 * @brief Define the virtual function table for the parent with regard to the child
 * @param type1 the parent type
 * @parem type2 the child type
 */
#ifdef PRINT_LIST
#define DEFINE_HLIST_OPS(type1, type2) \
  typedef struct type1##_ops { \
    type2##_t *(*create)(type1##_t *parent, buf_t *name, void *data); \
    SEED_Result (*init)(type2##_t *child, void *data); \
    int (*add)(type1##_t *parent, type2##_t *child); \
    type2##_t *(*del)(type1##_t *parent, type2##_t *child); \
    SEED_Result (*free)(type2##_t *child); \
    type2##_t *(*get)(type1##_t *parent, buf_t *name); \
    void (*print)(type1##_t *parent); \
  } type1##_ops_t;
#else
#define DEFINE_HLIST_OPS(type1, type2) \
  typedef struct type1##_ops { \
    type2##_t *(*create)(type1##_t *parent, buf_t *name, void *data); \
    SEED_Result (*init)(type2##_t *child, void *data); \
    int (*add)(type1##_t *parent, type2##_t *child); \
    type2##_t *(*del)(type1##_t *parent, type2##_t *child); \
    SEED_Result (*free)(type2##_t *child); \
    type2##_t *(*get)(type1##_t *parent, buf_t *name); \
    void (*print)(type1##_t *parent); \
  } type1##_ops_t;
#endif /* PRINT_LIST */

/**
 * @brief Declare the functions for the parent with regard to the child
 * @param type1 the parent type
 * @param type2 the child type
 */
#ifdef PRINT_LIST
#define DECLARE_FUNC(type1, type2) \
  type2##_t *create_##type2(type1##_t *parent, buf_t *name, void *data); \
  SEED_Result init_##type2(type2##_t *child, void *data); \
  SEED_Result add_##type2##_to_##type1(type1##_t *parent, type2##_t *child); \
  type2##_t *del_##type2##_from_##type1(type1##_t *parent, type2##_t *child); \
  SEED_Result free_##type2(type2##_t *child); \
  type2##_t *get_##type2##_from_##type1##_by_name(type1##_t *parent, buf_t *name); \
  void print_##type2##_in_##type1(type1##_t *head); \
  \
  static type1##_ops_t type1##_ops = { \
    .create = create_##type2, \
    .init = init_##type2, \
    .add = add_##type2##_to_##type1, \
    .del = del_##type2##_from_##type1, \
    .free = free_##type2, \
    .get = get_##type2##_from_##type1##_by_name, \
    .print = print_##type2##_in_##type1, \
  };
#else
#define DECLARE_FUNC(type1, type2) \
  type2##_t *create_##type2(type1##_t *parent, buf_t *name, void *data); \
  SEED_Result init_##type2(type2##_t *child, void *data); \
  SEED_Result add_##type2##_to_##type1(type1##_t *parent, type2##_t *child); \
  type2##_t *del_##type2##_from_##type1(type1##_t *parent, type2##_t *child); \
  SEED_Result free_##type2(type2##_t *child); \
  type2##_t *get_##type2##_from_##type1##_by_name(type1##_t *parent, buf_t *name); \
  \
  static type1##_ops_t type1##_ops = { \
    .create = create_##type2, \
    .init = init_##type2, \
    .add = add_##type2##_to_##type1, \
    .del = del_##type2##_from_##type1, \
    .free = free_##type2, \
    .get = get_##type2##_from_##type1##_by_name, \
  };
#endif /* PRINT_LIST */

#define DECLARE_DEFAULT_FUNC(type) \
  buf_t *type##_get_name(type##_t *p);

/**
 * @brief Get the name of the record
 * @param type the type of the record
 */
#define IMPLEMENT_GENERIC_GET_NAME(type) \
  buf_t *type##_get_name(type##_t *p) \
  { \
    return p->name; \
  }\

/**
 * @brief Implement the create function that creates the child node
 * @param parent the list of which the new node is added
 * @param name the name of the record
 * @param nlen the length of the name
 * @return the new node
 */
#define IMPLEMENT_CREATE_FUNC(type1, type2) \
  type2##_t *create_##type2(type1##_t *parent, buf_t *name, void *data) \
  { \
    type2##_t *child; \
    child = (type2##_t *)malloc(sizeof(type2##_t)); \
    if (!child) return NULL; \
    memset(child, 0x0, sizeof(type2##_t)); \
    if (name) child->name = name; \
    \
    if (parent->ops->init) \
      parent->ops->init(child, data); \
    parent->ops->add(parent, child); \
    return child; \
  }

/**
 * @brief Implement the add function that adds the child node in the parent
 * list
 * @param type1 the parent's type
 * @param type2 the child's type
 */
#define IMPLEMENT_ADD_FUNC(type1, type2) \
  SEED_Result add_##type2##_to_##type1(type1##_t *parent, type2##_t *child) \
  { \
    type2##_t *curr;\
    \
    if (parent->num == 0) \
    { \
      parent->head = child; \
      child->prev = NULL; \
      child->next = NULL; \
    } \
    else \
    { \
      curr = parent->head; \
      while (curr->next) \
        curr = curr->next; \
      curr->next = child; \
      child->prev = curr; \
    } \
    \
    parent->num++; \
    \
    return SEED_SUCCESS; \
  };

/**
 * @brief Implement the del function that deletes the child node from the
 * parent list (Note that this does not free the removed node)
 * @param type1 the parent's type
 * @param type2 the child's type
 */
#define IMPLEMENT_DEL_FUNC(type1, type2) \
  type2##_t *del_##type2##_from_##type1(type1##_t *parent, type2##_t *child) \
  { \
    type2##_t *curr; \
    if (parent->num <= 0) \
      return NULL; \
    \
    curr = parent->head; \
    \
    do { \
      if (curr == child) \
        break; \
      curr = curr->next; \
    } while (curr); \
    \
    if (!curr) \
      return NULL; \
    \
    if (curr->prev) \
      curr->prev->next = child->next; \
    \
    if (curr->next) \
      curr->next->prev = child->prev; \
    \
    parent->num--;\
    return curr; \
  }

/**
 * @brief Implement the get function that gets the child node by its name
 * @param type1 the parent's type
 * @param type2 the child's type
 * @param parent the parent list
 * @param name the name structure to look into (if it is NULL, then get the
 * first record in the list)
 * @return the record with the name
 */
#define IMPLEMENT_GET_FUNC(type1, type2) \
  type2##_t *get_##type2##_from_##type1##_by_name(type1##_t *parent, buf_t *name) \
  { \
    type2##_t *curr; \
    \
    if (parent->num <= 0) \
      return NULL; \
    \
    curr = parent->head; \
    \
    if (!name) \
    { \
      if (curr->next) \
      { \
        parent->head = curr->next; \
      } \
      else \
      { \
        parent->head = NULL; \
      } \
      parent->num--; \
      return curr; \
    } \
    \
    while (curr) \
    { \
      if (curr->name->max == name->max) \
      { \
        if (!strncmp((const char *)curr->name->data, (const char *)name->data, name->max)) \
          break; \
        curr = curr->next; \
      } \
      else \
      { \
        curr = curr->next; \
      } \
    } \
    \
    return curr; \
  }

/**
 * @brief Implement the print function that prints all the child nodes in the
 * parent list
 * @param type1 the parent's type
 * @param type2 the child's type
 */
#ifdef PRINT_LIST
#define IMPLEMENT_PRINT_FUNC(type1, type2) \
  void print_##type2##_in_##type1(type1##_t *p) \
  { \
    int idx; \
    type2##_t *curr; \
    \
    idx = 0; \
    \
    if (p->num <= 0) \
      printf("[%s] Nothing is in the list\n", #type1);\
    else { \
      curr = p->head; \
      while(curr) \
      { \
        if (curr->name) \
        { \
          printf("[%s] index: %d, num of records: %d, name: %s, nlen: %d, next: %p\n", #type1, idx++,\
            p->num, curr->name->data, curr->name->max, curr->next); \
        } \
        else \
        { \
          printf("[%s] index: %d, num of records: %d, curr: %p, next: %p\n", #type1, idx++, curr, curr->next); \
        } \
        curr = curr->next; \
      } \
    } \
  }
#else
#define IMPLEMENT_PRINT_FUNC(type1, type2)
#endif /* PRINT_LIST */
#endif /* __TA_LIST_DEFINES_H__ */
