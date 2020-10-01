static const char *title = \
"Generate Broadcom CFE seeds and passwords for many popular modem/router devices"
;
static const float VERSION = 1.4f;

static const char *copyright = \
"Copyright 2015-2016 TJ <hacker@iam.tj>\n"
"Licenced on the terms of the GNU General Public Licence version 3\n"
;

static const char *help = \
"This tool can generate passwords for use with many devices that contain Broadcom Common Firmware Environment (CFE) bootbase which has a debug mode that is enabled using the 'ATEN 1 XXXXXXXX' command, where XXXXXXXX is an eight digit hexadecimal 'password'.\n\n"

"It is NOT necessary to have the device generate a 'seed' using 'ATSE [MODEL-ID]' because this tool can generate the seed from the device's first (base) MAC address.\n\n"

"When the device generates a seed it combines the number of seconds since 1970-01-01 00:00:00 with the router MAC address. Both are encoded in a single 6-byte hexadecimal number\n\n"

"Each value is truncated to its 3 least significant bytes so, for example:\n\n"

" $ date +%F.%T; echo \"obase=16;$(date +%s)\" | bc\n"
" 2016-03-26.23:06:32\n"
" 56F715F8\n\n"

"and MAC Address: EC:43:F6:46:C0:80\n\n"

"becomes F715F8 concatenated with 46C080\n\n"

" CFE> ATSE DSL-2492GNAU-B1BC\n"
" F715F846C080   <<<< last 3 bytes of MAC address\n"
" ^^^^^^\n"
"   seconds since 1970-01-01 00:00:00 (2016-03-26 23:06:32)\n\n"

"*NOTE: the default seed after power-up is 000000 so no time value needs to be specifed if 'ATSE <model-id-string>' has not been executed on the device.\n\n"

"Access to the device's console via a serial UART port, or a network telnet/ssh session, is required to enter the password.\n\n"

"So, for a device with base MAC address (reported by the CFE during boot) E.g:\n\n"

" CFE version 1.0.38-112.118 for BCM963268 (32bit,SP,BE)\n"
"  ...\n"
" Base MAC Address                  : ec:43:f6:46:c0:80\n"
"  ...\n"
" *** Press any key to stop auto run (1 seconds) ***\n"
" CFE>\n\n"

"Using this tool do:\n\n"

" ./cfe_gen_pass -s ec:43:f6:46:c0:80 -p\n\n"

" MAC address: ec:43:f6:46:c0:80 Timestamp: 000000 Seed: 00000046c080 Password: 10f0a563\n\n"

"And on the device do:\n\n"

" CFE> ATEN 1 10f0a563\n"
" OK\n"
" *** command status = 0\n\n"

"The tool can accept a timestamp as 8 hexadecimal characters (useful for testing the algorithm):\n\n"

" ./cfe_gen_pass -t 56FA8C2B -s ec:43:f6:46:c0:80 -p\n\n"

" MAC address: ec:43:f6:46:c0:80 Timestamp: 56FA8C2B (2016-03-29 14:07:39) Seed: FA8C2B46c080 Password: 1111bda5\n\n"
;

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static const size_t TIMESTAMP_SIZE = 8;
static const size_t SEED_SIZE = 12;
static const size_t PASSWORD_SIZE = 8;
static const size_t MESSAGE_SIZE = 128;
static const size_t MAC_ADDR_SIZE = 17;
static const size_t DATESTRING_SIZE = 20;

static void
pr_usage(int verbose)
{
  fprintf(stderr,
    "Usage:\n"
    "  -s 00:01:02:03:04:05 create seed from MAC address\n"
    "  -t [00000000]        seconds since 1970-01-01 (defaults to NOW) \n"
    "  -p [SEED]            generate password (with optional seed)\n"
    "  -h                   show additional help\n"
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

 exit(EXIT_FAILURE);
}

static const unsigned int passwords[8] = {
  0x10F0A563,
  0x887852B1,
  0xC43C2958,
  0x621E14AC,
  0x310F0A56,
  0x1887852B,
  0x8C43C295,
  0xC621E14A
};

static unsigned int
generate_seed(char *mac, char *timestamp, char *seed)
{
  unsigned int result = 0;
  if (mac && strlen(mac) == MAC_ADDR_SIZE) {
    size_t i;
    char *mac_ptr = mac + 9;
    size_t ts_len = strlen(timestamp);
    if (ts_len == TIMESTAMP_SIZE) {
      for (i = 0; i < SEED_SIZE; ++i) {
        if (i < 6) // first half of seed is the truncated timestamp
          seed[i] = timestamp[i+2];
        else { // second half is the truncated MAC address
          if (*mac_ptr == ':' || *mac_ptr == '-')
            ++mac_ptr;
          seed[i] = *mac_ptr++;
        }
      }
      result = 1;
    } else
      pr_error_exit(0, "Timestamp ('%s') should be %d hexadecimal characters e.g: 56F715F8", timestamp, TIMESTAMP_SIZE);
  } else
   pr_error_exit(0, "MAC-ADDR should be %d characters, e.g: 00:01:02:03:04:05", MAC_ADDR_SIZE);

  return result;
}

static unsigned int
generate_pass(char *seed, char *password)
{
  unsigned int result = 0;

  if (seed && strlen(seed) == SEED_SIZE) {
    unsigned int timestamp, byte, key, pass;
    timestamp = byte = 0;
    if(! sscanf(seed, "%06x", &timestamp))
      pr_error_exit(1, "unable to parse seed's timestamp");
    if (! sscanf(&seed[10], "%02x", &byte))
      pr_error_exit(1, "unable to parse seed's MAC address");
    key = byte & 0x07;
    pass = (passwords[key] + timestamp) ^ timestamp;
    snprintf(password, PASSWORD_SIZE + 1,  "%08x", pass);
    result = 1;
  } else
    pr_error_exit(0, "Seed should be %d hex characters", SEED_SIZE);

  return result;
}

int
main(int argc, char **argv, char **env)
{
  int result = 0;
  unsigned int arg;
  char *MAC_ADDR = NULL;
  char timestamp[TIMESTAMP_SIZE + 1];
  char seed[SEED_SIZE + 1];
  char password[PASSWORD_SIZE + 1];
  char date_string[DATESTRING_SIZE + 1];
  unsigned int opt_seed, opt_pass, opt_ts;
  time_t ts = 0;
  struct tm *t = NULL;
  seed[0] = password[0] = timestamp[0] = 0;
  seed[SEED_SIZE] = password[PASSWORD_SIZE] = 0;
  opt_seed = opt_pass = opt_ts = 0;
  strncpy(timestamp, "00000000", TIMESTAMP_SIZE + 1);

  fprintf(stderr, "%s\nVersion: %0.2f\n%s\n", title, VERSION, copyright);

  for (arg = 1; arg < (unsigned) argc; ++arg) {
    size_t arg_len = strlen(argv[arg]);

    if (argv[arg][0] == '-') {
      switch (argv[arg][1]) {
        case 's':
          opt_seed = 1;
          break;
        case 'p':
          opt_pass = 1;
          break;
        case 't':
          opt_ts = 1;
          break;
        case 'h':
          pr_usage(1);
          exit(0);
      }
    } else if (opt_seed == 1) {
      MAC_ADDR = argv[arg];
      ++opt_seed;
    } else if (opt_pass == 1 && opt_seed == 0) {
      if (arg_len != SEED_SIZE)
        pr_error_exit(1, "seed length must be %d characters", SEED_SIZE);

      strncpy(seed, argv[arg], SEED_SIZE);
      ++opt_pass;
    } else if (opt_ts == 1) {
      if (arg_len != TIMESTAMP_SIZE)
        pr_error_exit(1, "timestamp length must be %d hexadecimal characters", TIMESTAMP_SIZE);

      strncpy(timestamp, argv[arg], TIMESTAMP_SIZE);
      ++opt_ts;
    }
  }
  if (! opt_seed && ! opt_pass) {
    pr_usage(0);
    exit(0);
  }
  else if (opt_seed && opt_seed != 2)
    pr_error_exit(1, "seed requires MAC-ADDRESS");
  else if (! opt_seed && opt_pass && opt_pass != 2)
    pr_error_exit(1, "password on its own requires a pre-generated seed");
  else if (opt_seed && opt_pass && opt_pass != 1)
    pr_error_exit(1, "generating seed and password; cannot also accept pre-generated seed");
  else if (opt_pass == 2 && opt_ts)
    pr_error_exit(1, "seed already contains a timestamp; cannot over-ride it");
  else if (opt_ts == 1 || opt_pass == 2) { // no timestamp provided; use NOW
    ts = time(NULL);
    if (ts)
      snprintf(timestamp, TIMESTAMP_SIZE + 1, "%08lX", ts);
  }

  if (opt_pass == 2) { // try to figure out the correct date-time from the seed
    // inherits the most significant 2 characters from the NOW time
    strncpy(timestamp+2, seed, 6);
    time_t tmp;
    if (sscanf(timestamp, "%08lx", &tmp))
      if (tmp > ts-3600 && tmp < ts+3600) // timestamps are so close they must be for the same date
        ts = tmp;
  }

  if(opt_ts) { // ts needs to be valid to be converted to a time string
    if(! sscanf(timestamp, "%08lx", &ts))
      pr_error_exit(1, "converting timestamp string ('%s') to number", timestamp);
  }
  t = gmtime(&ts);
  strftime(date_string, DATESTRING_SIZE, "%F %T", t);

  if (opt_seed)
    if (! generate_seed(MAC_ADDR, timestamp, seed))
      pr_error_exit(1, "unable to generate seed; aborting");
  if (opt_pass)
    if (! generate_pass(seed, password))
      pr_error_exit(0, "unable to generate password");

  if (opt_seed || opt_pass)
    printf("MAC address: %s Timestamp: %s (%s) Seed: %s Password: %s\n", MAC_ADDR, timestamp, date_string, seed, password);

  return result;
}

