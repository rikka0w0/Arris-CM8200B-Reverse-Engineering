static const char *title =\
"Broadcom Consumer Router Firmware payload extractor"
;
static const float VERSION = 1.01f;

static const char *copyright = \
"Copyright 2015-2016 TJ <hacker@iam.tj>\n"
"Licensed on the terms of the GNU General Public License version 2 or later\n"
"Includes FFMPEG LZW library code with Broadcom CMS modifications\n"
;

static const char *help = \
"For routers using the Broadcom CFE ((Customer Premises Equipment) CPE Firmware Environment) and firmware update files.\n\n"

"Extracts ROMD and LZW payloads from firmware files.\n\n"

"The program will list and optionally extract/decompress the payloads:\n\n"
"$ ./fwex -d /tmp/zyxel/V100AAKL14C0.bin\n"
"Broadcom Consumer Router Firmware payload extractor\n"
"Version: 1.00\n"
"Copyright 2015-2016 TJ <hacker@iam.tj>\n"
"Licensed on the terms of the GNU General Public License version 2 or later\n"
"Includes FFMPEG LZW library code with Broadcom CMS modifications\n"
"\n"
"Found ROMD payload 0\n"
"  written to /tmp/zyxel/V100AAKL14C0.bin.00.bin\n"
"Image Offset:  0x00020000 (131072)\n"
"0000 Tag Version: 6\n"
"0004 Signature 1: MSTC_6006 (Model: 6006)\n"
"0018 Signature 2: ver. 2.0\n"
"0026 Chip ID: 63268\n"
"002c Board ID: 963168VX\n"
"003c Big Endian: Yes\n"
"003e Image Len: 25952256 (0x018c0000)\n"
"008e External Version: 1.00(AAKL.14)C0\n"
"00ae Internal Version: 1.00(AAKL.14)C0\n"
"00ce Image Next: 1\n"
"00d8 Image Validation Token: 0x1c633f00\n"
"00ec Tag Validation Token:   0xbdde4316\n"
"     Calculated Image CRC32: 0x1c633f00\n"
"     Calculated Tag   CRC32: 0xbdde4316\n"
"\n"
"Found LZW compressed payload 1\n"
"  compressed: 23265 decompressed: 80030 bytes\n"
"  written to /tmp/zyxel/V100AAKL14C0.bin.01.bin\n"
"Image Offset:  0x018e0020 (26083360)\n"
"0000 Image Next: 0\n"
"0001 Image Type: IMGDEF (0)\n"
"0003 Image Signature: 0\n"
"0005 Image Len: 23305 (0x00005b09)\n"
"0018 Image Validation Token: 0xd78f9ceb\n"
"001c Tag Validation Token:   0x8681f430\n"
"     Calculated Image CRC32: 0xd78f9ceb\n"
"     Calculated Tag CRC32:   0x8681f430\n"
"\n"
;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#define BCMTAG_EXE_USE 1

#include "heap_reap.h"
#include "bcmTag.h"
#include "firmware_extractor.h"
#include "cms_lzw.h"

static unsigned int MESSAGE_SIZE = 1024;

static const char *image_type[] = {"IMGDEF", "ROMD", "HPNA"};

static char *filename = NULL;
static unsigned int opt_decompress, opt_list, opt_quiet;
static const char *msg_err_memalloc = "unable to allocate memory for %s (%lu bytes)\n";
static const char *lzw_prefix_string = COMPRESSED_CONFIG_HEADER;

static void
pr_usage(int verbose)
{
  fprintf(stderr,
    "Usage: %s [options] [filename]\n"
    "  -h               show additional help\n"
    "  -d               extracts payloads to same directory as 'filename'\n"
    "  -l               list payloads\n"
    "\n"
    "%s",
    PROGRAM_NAME,
    verbose ? help : ""
  );
}

static void
pr_error_exit(unsigned int usage, const char *error, ...)
{
 va_list args;
 char error_message[MESSAGE_SIZE + 1];

 if (errno != 0) {
   perror(NULL);
 }
 if (error) {
   va_start(args, error);
   (void) vsnprintf(error_message, MESSAGE_SIZE + 1, error, args);
   va_end(args);
 fprintf(stderr, "Error: %s\n", error_message);
 }

 if (usage) pr_usage(usage);

 heap_and_reap(NULL-1, 0, 0);
 exit(EXIT_FAILURE);
}

/* calculate standard CRC32
 *
 * @param data pointer to start of input data
 * @param len  length in bytes of data to be checksummed
 * @param crc32 seed value (Broadcom use 0xffffffff)
 */
unsigned int crc32(const unsigned char *data, ssize_t len, unsigned int crc)
{
   for ( ; len > 0; --len ) {
     crc = (crc >> 8) ^ Crc32_table[ (crc ^ *data++) & 0xff ];
   }
   return crc;
}

int decompress(int fd) {
  int result = 0;
  unsigned int crc_header, crc_payload;
  unsigned char *buffer = NULL;
  unsigned long header_len = sizeof(FILE_TAG);

  unsigned int offset = 0;
  unsigned int count = 0;
  unsigned int next = 1;
  void *payload = NULL;
  void *plaintext = NULL;
  char *filename_lzw = NULL;
  int fd_out = -1;
  SINT32 bytes, total_bytes = 0;
  unsigned int f_lzw_len = strlen(filename) + 8; // filename.00.lzw
  mode_t fd_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

  while (next) {
    unsigned long len = 0;
    crc_header = crc_payload = 0xffffffff;

    if (count) // switch struct type after initial file header
      header_len = sizeof(IMAGE_TAG);

    lseek(fd, offset, SEEK_SET);
    if (opt_list)
      printf("Header Offset: 0x%08x (%u)\n", offset, offset);

    if ( (buffer = heap_and_reap(NULL, header_len, 1)) != NULL) {
      ssize_t qty;
      if ( (qty = read(fd, buffer, header_len)) < header_len) {
        if (!opt_quiet)
          fprintf(stderr, "warning: only able to read %ld of %ld bytes\n", qty, header_len);
        header_len = qty;
      }

      PFILE_TAG pfile = (PFILE_TAG) buffer;
      PIMAGE_TAG pimage = (PIMAGE_TAG) buffer;

      if (!count) {
        next = *(unsigned char *)(pfile->imageNext);
        len = atol(pfile->totalImageLen);
        offset = 0x20000;
      } else {
        next = *(unsigned char *)(pimage->imageNext);
        len = atol(pimage->imageLen);
        offset += sizeof(IMAGE_TAG);
      }

      crc_header = crc32(buffer, header_len - (count ? CRC_LEN : TOKEN_LEN), crc_header);

      // read payload and calculate CRC32
      lseek(fd, offset, SEEK_SET);
      if ( (payload = heap_and_reap(NULL, len, 1)) != NULL) {

        if ( (qty = read(fd, payload, len)) < len) {
          fprintf(stderr, "skipping CRC calculation: only able to read %ld of %ld bytes\n", qty, len);
        } else {
          crc_payload = crc32(payload, len, crc_payload);

          if (opt_decompress) {

            // allocate memory first time it is needed
            if (!filename_lzw)
              if((filename_lzw = heap_and_reap(NULL, f_lzw_len, 1)) == NULL)
                pr_error_exit(0, msg_err_memalloc, "filename_lzw", f_lzw_len);

            snprintf(filename_lzw, f_lzw_len, "%s.%02x.bin", filename, count);

            if ((fd_out = open(filename_lzw, O_WRONLY | O_CREAT, fd_mode)) == -1)
              pr_error_exit(0, "unable to open '%s' for writing\n", filename_lzw);

          }

          if (strncmp((char *)payload, lzw_prefix_string, strlen(lzw_prefix_string)) != 0) {

            printf("Found %s payload %u\n", (count == 0 ? "ROMD" : "unknown"), count);
            if (opt_decompress)
              write(fd_out, payload, len);

          } else {
            printf("Found LZW compressed payload %u\n", count);
            unsigned int plaintext_len = len * 100;

            if ((plaintext = heap_and_reap(NULL, plaintext_len, 1)) != NULL) {
              LZWDecoderState *decoder_state = NULL;

              cmsLzw_initDecoder(&decoder_state, payload + COMPRESSED_CONFIG_HEADER_LENGTH, len - COMPRESSED_CONFIG_HEADER_LENGTH);

              do {
                bytes = cmsLzw_decode(decoder_state, plaintext, plaintext_len);
                total_bytes += bytes;
                if (opt_decompress) {
                  write(fd_out, plaintext, bytes);
                }
              } while (bytes == plaintext_len);

              cmsLzw_cleanupDecoder(&decoder_state);
              heap_and_reap(plaintext, 0, 0);

              printf("  compressed: %lu decompressed: %u bytes\n", len - COMPRESSED_CONFIG_HEADER_LENGTH, total_bytes);

            } else {
              pr_error_exit(0, msg_err_memalloc, "decompressor", plaintext_len);
            }
          }
          if (opt_decompress) {
            printf("  written to %s\n", filename_lzw);
            close(fd_out);
          }

          heap_and_reap(payload, 0, 0);
        }
      } else {
        close(fd);
        pr_error_exit(0, msg_err_memalloc, "payload", len);
      }

      if (!count) {
        printf("Image Offset:  0x%08x (%u)\n", offset, offset);
        printf("%04lx Tag Version: %s\n"
               "%04lx Signature 1: %s (Model: %s)\n"
               "%04lx Signature 2: %s\n"
               "%04lx Chip ID: %s\n"
               "%04lx Board ID: %s\n"
               "%04lx Big Endian: %s\n"
               "%04lx Image Len: %s (0x%08lx)\n"
               "%04lx External Version: %s\n"
               "%04lx Internal Version: %s\n"
               "%04lx Image Next: %u\n"
               "%04lx Image Validation Token: 0x%08x\n"
               "%04lx Tag Validation Token:   0x%08x\n"
               "     Calculated Image CRC32: 0x%08x\n"
               "     Calculated Tag   CRC32: 0x%08x\n"
               "\n",
               offsetof(struct _FILE_TAG, tagVersion), pfile->tagVersion,
               offsetof(struct _FILE_TAG, signiture_1), pfile->signiture_1, pfile->signiture_1 + strlen(pfile->signiture_1) + 1,
               offsetof(struct _FILE_TAG, signiture_2), pfile->signiture_2,
               offsetof(struct _FILE_TAG, chipId), pfile->chipId,
               offsetof(struct _FILE_TAG, boardId), pfile->boardId,
               offsetof(struct _FILE_TAG, bigEndian), *pfile->bigEndian == '1' ? "Yes" : "No",
               offsetof(struct _FILE_TAG, totalImageLen), pfile->totalImageLen, len,
               offsetof(struct _FILE_TAG, externalversion), pfile->externalversion,
               offsetof(struct _FILE_TAG, internalversion), pfile->internalversion,
               offsetof(struct _FILE_TAG, imageNext), next,
               offsetof(struct _FILE_TAG, imageValidationToken), ntohl( *((unsigned int *)(pfile->imageValidationToken)) ),
               offsetof(struct _FILE_TAG, tagValidationToken), ntohl( *((unsigned int *)(pfile->tagValidationToken)) ),
               crc_payload,
               crc_header
        );
      } else {
        printf("Image Offset:  0x%08x (%u)\n", offset, offset);
        printf("%04lx Image Next: %u\n"
               "%04lx Image Type: %s (%lu)\n"
               "%04lx Image Signature: %u\n"
               "%04lx Image Len: %s (0x%08lx)\n"
               "%04lx Image Validation Token: 0x%08x\n"
               "%04lx Tag Validation Token:   0x%08x\n"
               "     Calculated Image CRC32: 0x%08x\n"
               "     Calculated Tag CRC32:   0x%08x\n"
               "\n",
               offsetof(struct _IMAGE_TAG, imageNext), next,
               offsetof(struct _IMAGE_TAG, imageType), image_type[atol(pimage->imageType)], atol(pimage->imageType),
               offsetof(struct _IMAGE_TAG, imageSignature), (unsigned int)*pimage->imageSignature,
               offsetof(struct _IMAGE_TAG, imageLen), pimage->imageLen, len,
               offsetof(struct _IMAGE_TAG, imageValidationToken), ntohl( *((unsigned int *)(pimage->imageValidationToken)) ),
               offsetof(struct _IMAGE_TAG, tagValidationToken), ntohl( *((unsigned int *)(pimage->tagValidationToken)) ),
               crc_payload,
               crc_header
        );
      }
      // next seek point will be end of current payload
      offset += len;

      heap_and_reap(buffer, 0, 0);

      ++count;

    } else {
      close(fd);
      pr_error_exit(0, "unable to allocate memory (%ld bytes)\n", header_len);
    }
  }

  return result;
}

int
main(int argc, char **argv)
{
  unsigned int arg;
  int fd, fd_mode;

  opt_decompress = opt_list = opt_quiet = 0;

  fprintf(stderr, "%s\nVersion: %0.2f\n%s\n", title, VERSION, copyright);

  for (arg = 1; arg < (unsigned) argc; ++arg) {
    char *p = argv[arg];
    size_t arg_len = strlen(p);

    if (p[0] == '-') {
      if(p[1] != 0) {
        switch (p[1]) {
          case 'h': // help
            pr_usage(1);
            goto end;
            break;
          case 'd': // decompress
            opt_decompress = 1;
            break;
          case 'l': // list payloads
            opt_list = 1;
            break;
        }
      } else {
        pr_error_exit(0, "cannot read data from stdin; provide a filename");
      }
      continue;
    }
    else if (!filename) { // remaining non-option must be the filename
      filename = p;
    } else {
      if (!opt_quiet)
        fprintf(stderr, "Can only process one file; ignoring '%s'\n", p);
    }

    if (opt_decompress == 1) {
      ++opt_decompress;
    }
    else if (opt_list == 1) {
      ++opt_list;
    }
  }

  fd_mode = O_RDONLY;

  if (filename) {
   if ((fd = open(filename, fd_mode)) > 0) {
     decompress(fd);
     close(fd);
    } else {
      fprintf(stderr, "Unable to open for %s (%s)\n", "reading" , filename );
    }
  } else {
    pr_usage(0);
  }

end:
  heap_and_reap(NULL-1, 0, 0);
  return 0;
}

