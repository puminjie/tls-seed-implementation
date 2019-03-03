#ifndef __TA_IO_PROCESS_H__
#define __TA_IO_PROCESS_H__

#define n2s(c,s)        ((s=(((unsigned int)((c)[0]))<< 8)| \
                            (((unsigned int)((c)[1]))    )),c+=2)

#define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

#define l2n3(l,c)       ((c[0]=(unsigned char)(((l)>>16)&0xff), \
                          c[1]=(unsigned char)(((l)>> 8)&0xff), \
                          c[2]=(unsigned char)(((l)    )&0xff)),c+=3)

#define n2d4(c,d)       (d =((uint32_t)(*((c)++)))<<24, \
						 d|=((uint32_t)(*((c)++)))<<16, \
						 d|=((uint32_t)(*((c)++)))<< 8, \
						 d|=((uint32_t)(*((c)++))))

#define d2n4(d,c)		(*((c)++)=(unsigned char)(((d)>>24)&0xff), \
						 *((c)++)=(unsigned char)(((d)>>16)&0xff), \
						 *((c)++)=(unsigned char)(((d)>> 8)&0xff), \
						 *((c)++)=(unsigned char)(((d)    )&0xff))

#define n2t8(c,t)       (t =((uint64_t)(*((c)++)))<<56, \
                         t|=((uint64_t)(*((c)++)))<<48, \
                         t|=((uint64_t)(*((c)++)))<<40, \
                         t|=((uint64_t)(*((c)++)))<<32, \
                         t|=((uint64_t)(*((c)++)))<<24, \
                         t|=((uint64_t)(*((c)++)))<<16, \
                         t|=((uint64_t)(*((c)++)))<< 8, \
                         t|=((uint64_t)(*((c)++))))

#define t2n8(l,c)       (*((c)++)=(unsigned char)(((l)>>56)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>48)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))

#endif /* __TA_IO_PROCESS_H__ */
