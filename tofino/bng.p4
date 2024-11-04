/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/* It can be compiled in a number of variants (profiles) with the
 * parameters specified on the command line.
 *
 * -DIPV4_HOST_SIZE=131072   -- Set the size of IPv4 host table
 * -DIPV4_LPM_SIZE=400000    -- Set the size of IPv4 LPM table
 * -DPARSER_OPT              -- Optimize the number of parser states
 * -DBYPASS_EGRESS           -- Bypass egress processing completely
 * -DONE_STAGE               -- Allow ipv4_host and ipv4_lpm to share a stage
 * -DUSE_ALPM                -- Use ALPM implementation for ipv4_lpm table
 * -DUSE_ALPM_NEW            -- Use ALPM implementation for ipv4_lpm table,
 *                              coded in a new style (as an extern)
 * -DALPM_NAME               -- Define ALPM extern separately and not inside
 *                              the table (use with -DUSE_ALPM_NEW)
 * -DALPM_PARTITIONS         -- Define the number of ALPM partitions. Default
 *                              is 2048
 */

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 *************************************************************************/

const PortId_t CPU_PORT = 64;

/* Table Sizes */
#ifndef IPV4_HOST_SIZE
  #define IPV4_HOST_SIZE 65536
#endif
#if defined(USE_ALPM) || defined(USE_ALPM_NEW)
  #ifndef IPV4_LPM_SIZE
    #define IPV4_LPM_SIZE (400 * 1024)
  #endif
  #ifndef ALPM_PARTITIONS
    #define ALPM_PARTITIONS 2048
  #endif
#else
  #ifndef IPV4_LPM_SIZE
    #define IPV4_LPM_SIZE (12 * 1024)
  #endif
#endif

#ifndef STATS_INDEX_WIDTH
  #define STATS_INDEX_WIDTH 2
  //  #define STATS_INDEX_WIDTH 15
#endif
#ifndef COUNTER_WIDTH
#  define COUNTER_WIDTH 64
#endif

#ifndef STATS_SIZE
    #define STATS_SIZE        1<<STATS_INDEX_WIDTH
#endif
typedef bit<STATS_INDEX_WIDTH> stats_index_t;

typedef bit<10> meter_index_t;

/*************************************************************************
 ************* A S S E M B L I N G   T H E   P R O G R A M ***************
 *************************************************************************/
#include "../common/types.p4"
#include "../common/headers.p4"
#include "../common/ingress.p4"
#include "../common/egress.p4"
#include "../common/package.p4"
