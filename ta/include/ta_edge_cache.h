/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __TA_EDGE_CACHE_H__
#define __TA_EDGE_CACHE_H__

/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */

#define TA_EDGE_CACHE_UUID { 0x4e282c65, 0xee7c, 0x415e, \
		{ 0xb3, 0x85, 0xb3, 0xf7, 0xc4, 0x47, 0xde, 0xd6} }

/* The TAFs ID implemented in this TA */

/* TLS related operation (NW to SW) */

#define TA_EDGE_CACHE_CMD_INIT            0 
// initialize the managers of the EC.

#define TA_EDGE_CACHE_CMD_TLS             1 
// execute the TLS operation

#define TA_EDGE_CACHE_CMD_SHUTDOWN        2
// shutdown the TLS context

#define TA_EDGE_CACHE_CMD_GET_DOMAIN      3 
// load the domain list from the trusted (platform) authority 

#define TA_EDGE_CACHE_CMD_GET_CC          4  
// get the CC from the origins

#define TA_EDGE_CACHE_CMD_GET_DATA_INIT   5
#define TA_EDGE_CACHE_CMD_GET_DATA        6 
// fetch the data from the origins

#define TA_EDGE_CACHE_CMD_POLL_FETCH      7
// check whether there is any request for fetching

#define TA_EDGE_CACHE_CMD_POLL_DATA       8
// check whether the data fetching is finished

#define TA_EDGE_CACHE_CMD_POLL_IO         9
// check whether the file I/O is requested

#define TA_EDGE_CACHE_CMD_LOAD            10
// file load operation

#define TA_EDGE_CACHE_CMD_STORE           11
// file store operation

#define TA_EDGE_CACHE_CMD_TEST            12 // test command
// test the primitive operations

/* Direction to the host application forwarder */
#define TA_EDGE_CACHE_NXT_TLS             TA_EDGE_CACHE_CMD_TLS
// arg: none, alen: 0

#define TA_EDGE_CACHE_NXT_LOAD            TA_EDGE_CACHE_CMD_LOAD
// arg: last bytes (4 bytes), length of path (2 bytes), file path, 
// alen: length of the file path + 6

#define TA_EDGE_CACHE_NXT_STORE           TA_EDGE_CACHE_CMD_STORE
// arg: last bytes (4 bytes, 0000), length of path (2 bytes), file path, sealed file, 
// alen: length of the file and the file path + 6

#define TA_EDGE_CACHE_NXT_GET_DOMAIN      TA_EDGE_CACHE_CMD_GET_DOMAIN
// arg: address info, alen: length of the address info

#define TA_EDGE_CACHE_NXT_GET_CC          TA_EDGE_CACHE_CMD_GET_CC
// arg: address info, alen: length of the address info

#define TA_EDGE_CACHE_NXT_GET_DATA_INIT   TA_EDGE_CACHE_CMD_GET_DATA_INIT
// arg: address info, alen: length of the address info

#define TA_EDGE_CACHE_NXT_GET_DATA        TA_EDGE_CACHE_CMD_GET_DATA
// arg: address info, alen: length of the address info

#define TA_EDGE_CACHE_NXT_POLL_DATA       TA_EDGE_CACHE_CMD_POLL_DATA

#define TA_EDGE_CACHE_NXT_POLL_FETCH      TA_EDGE_CACHE_CMD_POLL_FETCH

#define TA_EDGE_CACHE_NXT_POLL_IO         TA_EDGE_CACHE_CMD_POLL_IO

#define TA_EDGE_CACHE_NXT_EXIT            128
// arg: none, alen: 0

// Init setting for the command context
#define TA_EDGE_CACHE_INIT_INITIALIZER  TA_EDGE_CACHE_CMD_INIT
#define TA_EDGE_CACHE_INIT_FRONTEND     TA_EDGE_CACHE_CMD_TLS
#define TA_EDGE_CACHE_INIT_BACKEND      TA_EDGE_CACHE_CMD_POLL_FETCH
#define TA_EDGE_CACHE_INIT_FILE_IO      TA_EDGE_CACHE_CMD_POLL_IO

/* ATTESTATION TA UUID & CMD */
#define TA_ATTESTATION_UUID { 0x3d5ba597, 0x924a, 0x4b57, \
    { 0x90, 0x23, 0x38, 0xe4, 0x49, 0x56, 0xc1, 0xb3} }

#define TA_ATTESTATION_CMD_GET_DIGEST 0

#endif /* __TA_EDGE_CACHE_H__ */
