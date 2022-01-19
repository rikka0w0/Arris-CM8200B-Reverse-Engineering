/*
 * LZW decoder
 * Copyright (c) 2003 Fabrice Bellard.
 * Copyright (c) 2006 Konstantin Shishkov.
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#ifdef COMPRESSED_CONFIG_FILE

#include "firmware_extractor.h"
#include "cms_lzw.h"



static const uint16_t mask[17] =
{
    0x0000, 0x0001, 0x0003, 0x0007,
    0x000F, 0x001F, 0x003F, 0x007F,
    0x00FF, 0x01FF, 0x03FF, 0x07FF,
    0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF
};


enum FF_LZW_MODES{
    FF_LZW_GIF,
    FF_LZW_TIFF
};


/* get one code from stream */
static int lzw_get_code(LZWDecoderState *s)
{
    int c;

    /* always use TIFF mode */

    while (s->bbits < s->cursize) {
        s->bbuf = (s->bbuf << 8) | (*s->pbuf++);
        s->bbits += 8;
    }
    //    printf("TIFF: bbuf=0x%08x bbits=%d cursize=%d\n", s->bbuf, s->bbits, s->cursize);
    c = s->bbuf >> (s->bbits - s->cursize);

    s->bbits -= s->cursize;

    //    printf("bbits=%d c=0x%08x curmask=0x%08x\n", s->bbits, c, s->curmask);
    return c & s->curmask;
}


void ff_lzw_decode_tail(LZWDecoderState *s)
{
    /* always use TIFF mode */
    s->pbuf= s->ebuf;
}


CmsRet cmsLzw_initDecoder(LZWDecoderState **p, UINT8 *inbuf, UINT32 inbuf_size)
{
    LZWDecoderState *s;
    int mode = FF_LZW_TIFF;  /* always use TIFF mode */
    int csize = 8;  /* the encoder side has this hardcoded, so hardcode here too */

    *p = (LZWDecoderState *) cmsMem_alloc(sizeof(LZWDecoderState), ALLOC_ZEROIZE);
    if (*p == NULL)
    {
       cmsLog_error("could not allocate %d bytes for decoder state", sizeof(LZWDecoderState));
       return CMSRET_RESOURCE_EXCEEDED;
    }
    else
    {
       cmsLog_debug("%d bytes allocated for decoder state", sizeof(LZWDecoderState));
    }

    s = *p;

    /* read buffer */
    s->pbuf = inbuf;
    s->ebuf = s->pbuf + inbuf_size;
    s->bbuf = 0;
    s->bbits = 0;
    s->bs = 0;

    /* decoder */
    s->codesize = csize;
    s->cursize = s->codesize + 1;
    s->curmask = mask[s->cursize];
    s->top_slot = 1 << s->cursize;
    s->clear_code = 1 << s->codesize;
    s->end_code = s->clear_code + 1;
    s->slot = s->newcodes = s->clear_code + 2;
    s->oc = s->fc = -1;
    s->sp = s->stack;

    s->mode = mode;
    s->extra_slot = (s->mode == FF_LZW_TIFF);

    return CMSRET_SUCCESS;
}


SINT32 cmsLzw_decode(LZWDecoderState *s, UINT8 *outbuf, UINT32 outlen)
{
    UINT32 l;
    int c, code, oc, fc;
    uint8_t *sp;

    if (s->end_code < 0)
        return -1;

    l = outlen;
    sp = s->sp;
    oc = s->oc;
    fc = s->fc;

    for (;;) {

        while (sp > s->stack) {
           //           printf("transfer stack to buf, sp=0x%02x buf=%p\n", *sp, outbuf);
            *outbuf++ = *(--sp);
            if ((--l) == 0)
                goto the_end;
        }

        c = lzw_get_code(s);
        if (c == s->end_code) {
            cmsLog_debug("got end code %d", c);
            break;
        } else if (c == s->clear_code) {
            cmsLog_debug("got clear code %d", c);
            s->cursize = s->codesize + 1;
            s->curmask = mask[s->cursize];
            s->slot = s->newcodes;
            s->top_slot = 1 << s->cursize;
            fc= oc= -1;
        } else {
            code = c;
            //            printf("got valid code %d (0x%02x)\n", c, c);

            if (code == s->slot && fc>=0) {
                *sp++ = fc;
                code = oc;
            }else if(code >= s->slot) {
                cmsLog_error("code %d greater than slot %d", code, s->slot);
                break;
            }

            while (code >= s->newcodes) {
               //               printf("transfer suffix to to sp \n");
                *sp++ = s->suffix[code];
                code = s->prefix[code];
            }

            //            printf("sp=%p gets code %d\n", sp, code);
            *sp++ = code;


            if (s->slot < s->top_slot && oc>=0) {
               //                printf("suffix[%d]=%d prefix[%d]=%d\n", s->slot, code, s->slot, oc);
                s->suffix[s->slot] = code;
                s->prefix[s->slot++] = oc;
            }
            fc = code;
            oc = c;

            if (s->slot >= s->top_slot - s->extra_slot) {
                if (s->cursize < LZW_MAXBITS) {
                    s->top_slot <<= 1;
                    s->curmask = mask[++s->cursize];
                    //                    printf("new top_slot=0x%x curmask=0x%x\n", s->top_slot, s->curmask);
                }
            }
        }
    }  // end of for loop


    s->end_code = -1;
  the_end:
    s->sp = sp;
    s->oc = oc;
    s->fc = fc;

    cmsLog_debug("about to return, outlen=%d l=%d\n", outlen, l);
    return outlen - l;
}



void cmsLzw_cleanupDecoder(LZWDecoderState **s)
{
   cmsMem_free(*s);
   *s = NULL;
}



#endif /* COMPRESSED_CONFIG_FILE */
