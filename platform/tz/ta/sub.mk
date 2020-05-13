ROOT_DIRECTORY=../../..
TRUSTED_DIRECTORY=$(ROOT_DIRECTORY)/src/trusted
global-incdirs-y += $(ROOT_DIRECTORY)/include $(TRUSTED_DIRECTORY)
srcs-y += ta_edge.c 
srcs-y += $(wildcard $(TRUSTED_DIRECTORY)/*.c)
