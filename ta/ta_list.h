/**
 * @file ta_list.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define user interfaces to use a generic list
 */

#ifndef __TA_LIST_H__
#define __TA_LIST_H__

#include "ta_list_defines.h"

/**
 * @brief To declare the necessary declarations in the header file (for parent)
 */
#define DECLARE_PARENT_OF(type) \
  struct type##_st; \
  struct type##_ops; 

/**
 * @brief To declare the necessary declarations in the header file (for child)
 */
#define DECLARE_CHILD_OF(type) \
  struct type##_st; \
  struct buf_st * type##_get_name(struct type##_st *p);

/**
 * @brief To declare default fields for the parent list
 */
#define DECLARE_DEFAULT_PARENT_FIELDS(type1, type2) \
  struct buf_st *name; \
  uint32_t num; \
  struct type1##_st *prev; \
  struct type1##_st *next; \
  struct type1##_ops *ops; \
  struct type2##_st *head; \
  struct buf_st *(*get_name)(struct type1##_st *p);

/**
 * @brief To declare default fields for the child node
 */
#define DECLARE_DEFAULT_CHILD_FIELDS(type) \
  struct buf_st *name; \
  uint32_t num; \
  struct type##_st *prev; \
  struct type##_st *next; \
  struct buf_st *(*get_name)(struct type##_st *p);

/**
 * @brief Declare the list operations
 */
#define DECLARE_LIST_OPS(type1, type2) \
  DEFINE_HLIST_OPS(type1, type2) \
  DECLARE_FUNC(type1, type2) \
  DECLARE_DEFAULT_FUNC(type1)

/**
 * @brief Implement the default functions for the parent
 */
#ifdef DEBUG
#define IMPLEMENT_DEFAULT_PARENT_FUNC(type1, type2) \
  IMPLEMENT_GENERIC_GET_NAME(type1) \
  IMPLEMENT_CREATE_FUNC(type1, type2) \
  IMPLEMENT_ADD_FUNC(type1, type2) \
  IMPLEMENT_DEL_FUNC(type1, type2) \
  IMPLEMENT_GET_FUNC(type1, type2) \
  IMPLEMENT_PRINT_FUNC(type1, type2)
#else
#define IMPLEMENT_DEFAULT_PARENT_FUNC(type1, type2) \
  IMPLEMENT_GENERIC_GET_NAME(type1) \
  IMPLEMENT_CREATE_FUNC(type1, type2) \
  IMPLEMENT_ADD_FUNC(type1, type2) \
  IMPLEMENT_DEL_FUNC(type1, type2) \
  IMPLEMENT_GET_FUNC(type1, type2)
#endif /* DEBUG */

/**
 * @brief Implement the default functions for the child
 */
#define IMPLEMENT_DEFAULT_CHILD_FUNC(type) \
  IMPLEMENT_GENERIC_GET_NAME(type)

/**
 * @brief Initialize the structure in the source code
 */
#define INIT_LIST(type, var, data) \
  var = (struct type##_st *)malloc(sizeof(struct type##_st)); \
  memset(var, 0x0, sizeof(struct type##_st)); \
  init_##type(var, data);

#define DEFAULT_PARENT_INIT_FUNC(type, var) \
  var->get_name = type##_get_name; \
  var->ops = &(type##_ops);

#define DEFAULT_CHILD_INIT_FUNC(type, var) \
  var->get_name = type##_get_name;

#define DEFAULT_FREE(var) \
  if (var->name) \
  { \
    free_buf(var->name); \
  }

#endif /* __TA_LIST_H__ */
