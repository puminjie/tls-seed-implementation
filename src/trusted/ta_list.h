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
  typedef struct type##_st type##_t; \
  typedef struct type##_ops type##_ops_t; 

/**
 * @brief To declare the necessary declarations in the header file (for child)
 */
#define DECLARE_CHILD_OF(type) \
  typedef struct type##_st type##_t; \
  buf_t * type##_get_name(type##_t *p);

/**
 * @brief To declare default fields for the parent list
 */
#define DECLARE_DEFAULT_PARENT_FIELDS(type1, type2) \
  buf_t *name; \
  uint32_t num; \
  type1##_t *prev; \
  type1##_t *next; \
  type1##_ops_t *ops; \
  type2##_t *head; \
  buf_t *(*get_name)(type1##_t *p);

/**
 * @brief To declare default fields for the child node
 */
#define DECLARE_DEFAULT_CHILD_FIELDS(type) \
  buf_t *name; \
  uint32_t num; \
  type##_t *prev; \
  type##_t *next; \
  buf_t *(*get_name)(type##_t *p);

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
#ifdef PRINT_LIST
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
#endif /* PRINT_LIST */

/**
 * @brief Implement the default functions for the child
 */
#define IMPLEMENT_DEFAULT_CHILD_FUNC(type) \
  IMPLEMENT_GENERIC_GET_NAME(type)

/**
 * @brief Initialize the structure in the source code
 */
#define INIT_LIST(type, var, data) \
  var = (type##_t *)malloc(sizeof(type##_t)); \
  memset(var, 0x0, sizeof(type##_t)); \
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
