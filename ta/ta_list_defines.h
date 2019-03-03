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
#include <tee_api_defines.h>
#include "ta_buf.h"

/**
 * @brief Define the virtual function table for the parent with regard to the child
 * @param type1 the parent type
 * @parem type2 the child type
 */
#ifdef DEBUG
#define DEFINE_HLIST_OPS(type1, type2) \
  struct type1##_ops { \
    struct type2##_st *(*create)(struct type1##_st *parent, struct buf_st *name, \
        void *data); \
    TEE_Result (*init)(struct type2##_st *child, void *data); \
    int (*add)(struct type1##_st *parent, struct type2##_st *child); \
    struct type2##_st *(*del)(struct type1##_st *parent, struct type2##_st *child); \
    TEE_Result (*free)(struct type2##_st *child); \
    struct type2##_st *(*get)(struct type1##_st *parent, struct buf_st *name); \
    void (*print)(struct type1##_st *parent); \
  };
#else
#define DEFINE_HLIST_OPS(type1, type2) \
  struct type1##_ops { \
    struct type2##_st *(*create)(struct type1##_st *parent, struct buf_st *name, \
        void *data); \
    TEE_Result (*init)(struct type2##_st *child, void *data); \
    int (*add)(struct type1##_st *parent, struct type2##_st *child); \
    struct type2##_st *(*del)(struct type1##_st *parent, struct type2##_st *child); \
    TEE_Result (*free)(struct type2##_st *child); \
    struct type2##_st *(*get)(struct type1##_st *parent, struct buf_st *name); \
    void (*print)(struct type1##_st *parent); \
  };
#endif /* DEBUG */

/**
 * @brief Declare the functions for the parent with regard to the child
 * @param type1 the parent type
 * @param type2 the child type
 */
#ifdef DEBUG
#define DECLARE_FUNC(type1, type2) \
  struct type2##_st *create_##type2(struct type1##_st *parent, struct buf_st *name, \
      void *data); \
  TEE_Result init_##type2(struct type2##_st *child, void *data); \
  TEE_Result add_##type2##_to_##type1(struct type1##_st *parent, struct type2##_st *child); \
  struct type2##_st *del_##type2##_from_##type1(struct type1##_st *parent, \
      struct type2##_st *child); \
  TEE_Result free_##type2(struct type2##_st *child); \
  struct type2##_st *get_##type2##_from_##type1##_by_name(struct type1##_st *parent, \
      struct buf_st *name); \
  void print_##type2##_in_##type1(struct type1##_st *head); \
  \
  static struct type1##_ops type1##_ops = { \
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
  struct type2##_st *create_##type2(struct type1##_st *parent, struct buf_st *name, \
      void *data); \
  TEE_Result init_##type2(struct type2##_st *child, void *data); \
  TEE_Result add_##type2##_to_##type1(struct type1##_st *parent, struct type2##_st *child); \
  struct type2##_st *del_##type2##_from_##type1(struct type1##_st *parent, \
      struct type2##_st *child); \
  TEE_Result free_##type2(struct type2##_st *child); \
  struct type2##_st *get_##type2##_from_##type1##_by_name(struct type1##_st *parent, \
      struct buf_st *name); \
  \
  static struct type1##_ops type1##_ops = { \
    .create = create_##type2, \
    .init = init_##type2, \
    .add = add_##type2##_to_##type1, \
    .del = del_##type2##_from_##type1, \
    .free = free_##type2, \
    .get = get_##type2##_from_##type1##_by_name, \
  };
#endif /* DEBUG */

#define DECLARE_DEFAULT_FUNC(type) \
  struct buf_st *type##_get_name(struct type##_st *p);

/**
 * @brief Get the name of the record
 * @param type the type of the record
 */
#define IMPLEMENT_GENERIC_GET_NAME(type) \
  struct buf_st *type##_get_name(struct type##_st *p) \
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
  struct type2##_st *create_##type2(struct type1##_st *parent, struct buf_st *name, \
      void *data) \
  { \
    struct type2##_st *child; \
    child = (struct type2##_st *)malloc(sizeof(struct type2##_st)); \
    if (!child) return TEE_ERROR_OUT_OF_MEMORY; \
    memset(child, 0x0, sizeof(struct type2##_st)); \
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
  TEE_Result add_##type2##_to_##type1(struct type1##_st *parent, struct type2##_st *child) \
  { \
    struct type2##_st *curr;\
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
    return TEE_SUCCESS; \
  };

/**
 * @brief Implement the del function that deletes the child node from the
 * parent list (Note that this does not free the removed node)
 * @param type1 the parent's type
 * @param type2 the child's type
 */
#define IMPLEMENT_DEL_FUNC(type1, type2) \
  struct type2##_st *del_##type2##_from_##type1(struct type1##_st *parent, \
      struct type2##_st *child) \
  { \
    struct type2##_st *curr; \
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
  struct type2##_st *get_##type2##_from_##type1##_by_name(struct type1##_st *parent, \
      struct buf_st *name) \
  { \
    struct type2##_st *curr; \
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
      if (curr->name->len == name->len) \
      { \
        if (!strncmp(curr->name->data, name->data, name->len)) \
          break; \
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
#ifdef DEBUG
#define IMPLEMENT_PRINT_FUNC(type1, type2) \
  void print_##type2##_in_##type1(struct type1##_st *p) \
  { \
    int idx; \
    struct type2##_st *curr; \
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
          printf("[%s] index: %d, num of records: %d, name: %s, nlen: %d\n", #type1, idx++,\
            p->num, curr->name->data, curr->name->len); \
        } \
        else \
        { \
          printf("[%s] index: %d, num of records: %d, curr: %p\n", #type1, idx++, curr); \
        } \
        curr = curr->next; \
      } \
    } \
  }
#else
#define IMPLEMENT_PRINT_FUNC(type1, type2)
#endif /* DEBUG */
#endif /* __TA_LIST_DEFINES_H__ */
