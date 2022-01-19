static const char *title =\
"Broadcom Consumer Router Firmware Header Editor"
;
static const float VERSION = 1.3f;

static const char *copyright = \
"Copyright 2015-2016 TJ <hacker@iam.tj>\n"
"Licensed on the terms of the GNU General Public License version 3\n"
;

static const char *help = \
"For routers using the Broadcom CFE ((Customer Premises Equipment) CPE Firmware Environment) and firmware update files.\n\n"

"Avoid the 'Invalid Model Id' error reported by the HTTP firmware upload page in a device with an ISP-specific Model ID (E.g. Eircom F1000 uses 6009 rather than ZyXel VMG8324/VMG8924 generic 6006.\n\n"

"This tool re-generates the header CRC32 checksum (usually at offset 0xEC - 236) of the package header structure and optionally alters the manufacturer Model ID of the firmware image.\n\n"

"To identify the current Model ID of the device's firmware connect to its terminal using telnet or ssh and query the manufacturer data that is stored in the ROM image:\n\n"

" > sys atsh\n"
" ...\n"
" Other Feature Bits     :\n"
"           4d 53 60 09 00 00 00 00-00 00 00 00 00 00 00 00\n\n"

"The first pair of bytes here are ASCII characters 'MS' (code for MitraStar)\n"
"The second pair are the Model ID '6009'\n\n"

"A firmware update file (usually has a .bin suffix) starts with a 256 byte header that describes the contents and contains data-verification checksums.\n"
"Specific to Mitrastar (MSTC), and therefore also Zyxel, the Model ID is stored in the 'signiture_1' manufacturer-specific info field starting at offset 4.\n"
"This 20-byte field is split into two parts, both ASCII zero-terminated strings:\n\n"

" a) the manufacturer ID and model ID (e.g. 'MSTC_6006')\n"
" b) the model ID (e.g. '6006')\n\n"

"By replacing the model ID with one matching the specific device and updating the header CRC32 checksum the device's HTTP firmware update interface will accept the file.\n\n"
"Example usage:\n\n"
"# display detailed help\n"
"fwheaditor -h\n"
"# display current and calculated header based on default values\n"
"fwheaditor V1.00(AAKL.13)C0.bin\n"
"# change Model ID to 6009 and write to file only if current Manufacturer is the default\n"
"fwheaditor -i 6009 -w V1.00(AAKL.13)C0.bin\n"
"# change Model ID to 6009 and write to file only if current Manufacturer is 'BRCM'\n"
"fwheaditor -i 6009 -m BRCM -w V1.00(AAHL.13).bin\n"
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
#include "heap_reap.h"

static unsigned int MESSAGE_SIZE = 1024;
static unsigned int TAG_VER_LEN = 4;
static unsigned int TAG_SIG_LEN = 20;
static unsigned int MODEL_ID_LEN = 5;
static ssize_t header_len = 236; // 0xEC; default length for Broadcom FILE_TAG header excluding TAG CRC
static char *match_manufacturer_id = "MSTC";
static char *match_model_id = "6006";
static char *model_id = "6006";

static unsigned int crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

static void
pr_usage(int verbose)
{
  fprintf(stderr,
    "Usage:\n"
    "  -i  replacement Model ID (default '%s')\n"
    "  -l  bytes to calculate new CRC32 over (default %ld)\n"
    "  -m  current Manufacturer ID to match (default '%s')\n"
    "  -M  current Model ID to match (default '%s')\n"
    "  -w  write to file (default only prints new values)\n"
    "  -s  simulate; don't write to file when -w is given\n"
    "  -t  output for automated test suite\n"
    "  -q  quiet; only display result\n"
    "  -h  show additional help\n"
    "\n"
    "%s",
    model_id,
    header_len,
    match_manufacturer_id,
    match_model_id,
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
     crc = (crc >> 8) ^ crc32_table[ (crc ^ *data++) & 0xff ];
   }
   return crc;
}


int
main(int argc, char **argv)
{
  unsigned int arg, crc;
  char *filename = NULL;
  int fd, fd_mode;
  unsigned char *buffer = NULL;
  unsigned char *model_id;
  unsigned int header_crc_offset = header_len;
  unsigned int manufacturer_id_count = 0;
  unsigned int model_id_count = 0;
  char *format_spec_user = "%-12s Manufacturer: %s Model: %s CRC32: %08x Length: %ld File: %s\n";
  char *format_spec_test = "%-12s %s %s %08x %ld\n";
  char *format_spec = format_spec_user; // default output format

  unsigned int opt_len, opt_model_id, opt_match_manufacturer_id, opt_match_model_id, opt_write, opt_quiet, opt_simulate, opt_testsuite;
  opt_len = opt_model_id = opt_match_manufacturer_id = opt_match_model_id = opt_write = opt_quiet = opt_simulate = opt_testsuite = 0;

  fprintf(stderr, "%s\nVersion: %0.2f\n%s\n", title, VERSION, copyright);

  if ((model_id = heap_and_reap(NULL, MODEL_ID_LEN, 1)) == NULL) {
    pr_error_exit(0, "Unable to allocate memory (%d bytes)\n", MODEL_ID_LEN);
  }
  memcpy(model_id, match_model_id, MODEL_ID_LEN);

  for (arg = 1; arg < (unsigned) argc; ++arg) {
    char *p = argv[arg];
    size_t arg_len = strlen(p);

    if (p[0] == '-') {
      if(p[1] != 0) {
        switch (p[1]) {
          case 'l': // length of data to generate CRC32 on
            opt_len = 1;
            break;
          case 'i': // replacement model ID
            opt_model_id = 1;
            break;
          case 'm': // match this manufacturer ID
            opt_match_manufacturer_id = 1;
            break;
          case 'M': // match this model ID
            opt_match_model_id = 1;
            break;
          case 'w': // re-write file header
            opt_write = 1;
            break;
          case 's': // simulate
            opt_simulate = 1;
            break;
          case 't': // display machine-readable output for test suite
            opt_testsuite = 1;
            format_spec = format_spec_test;
            break;
          case 'q': // quiet
            opt_quiet = 1;
            break;
          case 'h': // help
            pr_usage(1);
            goto end;
        }
      } else {
        pr_error_exit(0, "cannot read data from stdin; provide a filename");
      }
      continue;
    }

    if (opt_len == 1) {
      char *format = "%ld";
      if ( *(p+1) == 'x' || *(p+1) == 'X' ) { // hex length
        format = "%lx";
        // FIXME: p = first hex char?
      }
      if (sscanf(p, format, &header_len))
        ++opt_len;
      else
        pr_error_exit(0, "Illegal length value (%s)", p);

    } else if (opt_model_id == 1) {
      if (arg_len == 4) {
        model_id = p;
        ++opt_model_id;
      }  else {
        pr_error_exit(0, "Model Id ('%s') must be %d characters", p, MODEL_ID_LEN - 1);
      }
    } else if (opt_match_manufacturer_id == 1) {
      match_manufacturer_id = p;
      ++opt_match_manufacturer_id;
    } else if (opt_match_model_id == 1) {
      match_model_id = p;
      ++opt_match_model_id;
    } else if (!filename) { // remaining non-option must be the filename
      filename = p;
    } else {
      if (!opt_quiet)
        fprintf(stderr, "Can only process one file; ignoring '%s'\n", p);
    }
  }

  if (!opt_quiet) {
    if (opt_write == 1)
       fprintf(stdout, "%s\n", "In-place editing of header");
    
    if (opt_simulate == 1)
      fprintf(stderr, "%s\n", "Simulation mode; no file writes");
  }

  fd_mode = (opt_write && !opt_simulate) ? O_RDWR : O_RDONLY;

  if (filename) {
   if ((fd = open(filename, fd_mode)) > 0) {
     if ( (buffer = heap_and_reap(NULL, header_len + sizeof(crc), 1)) != NULL) {
       ssize_t qty;
       if ( (qty = read(fd, buffer, header_len + sizeof(crc))) < header_len) {
         if (!opt_quiet)
           fprintf(stderr, "warning: only able to read %ld of %ld bytes\n", qty, header_len);
         header_len = qty;
       }
     } else {
       close(fd);
       pr_error_exit(0, "unable to allocate memory (%ld bytes)\n", header_len);
     }
     printf( format_spec,
             opt_testsuite ? "" : "Current",
             buffer + TAG_VER_LEN,
             buffer + TAG_VER_LEN + strlen(buffer + TAG_VER_LEN) + 1,
             ntohl( *((unsigned int *)(buffer + header_crc_offset)) ),
             header_len,
             filename);

     // do the model ID replacement in the memory buffer
     if (strstr(buffer + TAG_VER_LEN, match_manufacturer_id) != NULL) {
       ++manufacturer_id_count;
       unsigned char *p = buffer + TAG_VER_LEN + strlen(match_manufacturer_id) + 1; // step over manufacturer ID
       if ( strstr(p, match_model_id) != NULL)
         ++model_id_count;
       for (; p <= buffer + TAG_VER_LEN + TAG_SIG_LEN - MODEL_ID_LEN; ++p) {
         if (strncmp(p, match_model_id, MODEL_ID_LEN) == 0) {
           memcpy(p, model_id, MODEL_ID_LEN);
           ++model_id_count;
           p = p + MODEL_ID_LEN - 1;
         }
       }
     }

     crc = crc32(buffer, header_len, 0xffffffff);

     char tmp_manufacturer[TAG_SIG_LEN];
     strcpy(tmp_manufacturer, match_manufacturer_id);
     strcat(tmp_manufacturer, "_");
     strcat(tmp_manufacturer, model_id);

     printf( format_spec,
             opt_testsuite ? "" : "Calculated",
             tmp_manufacturer,
             model_id,
             crc,
             header_len,
             filename
     );

     if (opt_write) {
       unsigned int tmp = htonl(crc);
       memcpy(buffer + header_crc_offset, &tmp, sizeof(tmp));

       if (!opt_simulate) {
         ssize_t write_len = header_len > header_crc_offset + sizeof(tmp) ? header_len : header_crc_offset + sizeof(tmp);
         lseek(fd, 0, SEEK_SET);
         write(fd, buffer, write_len);
       }

       printf( format_spec,
               opt_testsuite ? "" : "Written",
               buffer + TAG_VER_LEN,
               buffer + TAG_VER_LEN + strlen(buffer + TAG_VER_LEN) + 1,
               ntohl(*((unsigned int *)(buffer + 0xEC))),
               header_len,
               filename
       );
     }

     if (!opt_quiet) {
       fprintf(stderr, "Manufacturer ID does%s match '%s'\n",
               match_manufacturer_id == 0 ? " not" : "",
               match_manufacturer_id
       );
       if (!manufacturer_id_count)
         fprintf(stderr, "Model ID does%s match '%s' (%u replaced)\n",
                 model_id_count == 0 ? " not" : "",
                 match_model_id,
                 model_id_count - ( model_id_count == 0 ? 0 : 1 )
         );
     }

     heap_and_reap(buffer, 0, 0);
     close(fd);
    } else {
      fprintf(stderr, "Unable to open for %s (%s)\n", opt_write ? "writing" : "reading" , filename );
    }
  } else {
    pr_usage(0);
  }

end:
  heap_and_reap(NULL-1, 0, 0);
  return 0;
}

