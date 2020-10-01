static const char *title =\
"Broadcom Consumer Router Firmware Header Dump"
;
static const float VERSION = 1.05f;

static const char *copyright = \
"Copyright 2015-2016 TJ <hacker@iam.tj>\n"
"Licensed on the terms of the GNU General Public License version 3\n"
;

static const char *help = \
"For routers using the Broadcom CFE ((Customer Premises Equipment) CPE Firmware Environment) and firmware update files.\n\n"

"Displays the fields of the firmware update file header structure.\n\n"
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

#define BCMTAG_EXE_USE 1

#include "heap_reap.h"
#include "bcmTag.h"

static unsigned int MESSAGE_SIZE = 1024;

static char *image_type[] = {"IMGDEF", "ROMD", "HPNA"};

static void
pr_usage(int verbose)
{
  fprintf(stderr,
    "Usage:\n"
    "  -h  show additional help\n"
    "\n"
    "%s",
    verbose ? help : ""
  );
}

static void
pr_error_exit(unsigned int usage, const char *error, ...)
{
 va_list args;
 char error_message[MESSAGE_SIZE + 1];

 if (!error) return;

 va_start(args, error);
 (void) vsnprintf(error_message, MESSAGE_SIZE + 1, error, args);
 va_end(args);
 fprintf(stderr, "Error: %s\n", error_message);

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


int
main(int argc, char **argv)
{
  unsigned int arg, crc_header, crc_payload;
  char *filename = NULL;
  int fd, fd_mode;
  unsigned char *buffer = NULL;
  unsigned long header_len = sizeof(FILE_TAG);
  char *format_spec_user = "%-12s Manufacturer: %s Model: %s CRC32: %08x Length: %ld File: %s\n";
  char *format_spec_test = "%-12s %s %s %08x %ld\n";
  char *format_spec = format_spec_user; // default output format

  unsigned int opt_quiet;
  
  opt_quiet = 0;

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
  }


  fd_mode = O_RDONLY;

  if (filename) {
   if ((fd = open(filename, fd_mode)) > 0) {

     unsigned int offset = 0;
     unsigned int count = 0;
     unsigned int next = 1;
     void *payload = NULL;

     while (next) {
       unsigned long len = 0;
       crc_header = crc_payload = 0xffffffff;

       if (count) // switch struct type after initial file header
         header_len = sizeof(IMAGE_TAG);

       lseek(fd, offset, SEEK_SET);
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

             heap_and_reap(payload, 0, 0);
           }
         } else {
           close(fd);
           pr_error_exit(0, "unable to allocate memory (%ld bytes)\n", len);
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
                  "%04lx CFE Address: %s (0x%08lx)\n"
                  "%04lx CFE Len: %s (0x%08lx)\n"
                  "%04lx Root FS Address: %s (0x%08lx)\n"
                  "%04lx Root FS Len: %s (0x%08lx)\n"
                  "%04lx Kernel Address: %s (0x%08lx)\n"
                  "%04lx Kernel Len: %s (0x%08lx)\n"
                  "%04lx Image Sequence: %s (0x%08x)\n"
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
                  offsetof(struct _FILE_TAG, cfeAddress), pfile->cfeAddress, atol(pfile->cfeAddress),
                  offsetof(struct _FILE_TAG, cfeLen), pfile->cfeLen, atol(pfile->cfeLen),
                  offsetof(struct _FILE_TAG, rootfsAddress), pfile->rootfsAddress, atol(pfile->rootfsAddress),
                  offsetof(struct _FILE_TAG, rootfsLen), pfile->rootfsLen, atol(pfile->rootfsLen),
                  offsetof(struct _FILE_TAG, kernelAddress), pfile->kernelAddress, atol(pfile->kernelAddress),
                  offsetof(struct _FILE_TAG, kernelLen), pfile->kernelLen, atol(pfile->kernelLen),
                  offsetof(struct _FILE_TAG, imageSequence), pfile->imageSequence, atoi(pfile->imageSequence),
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
     heap_and_reap(buffer, 0, 0);
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

