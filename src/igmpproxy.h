/*
**  igmpproxy - IGMP proxy based multicast router 
**  Copyright (C) 2005 Johnny Egeland <johnny@rlo.org>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**----------------------------------------------------------------------------
**
**  This software is derived work from the following software. The original
**  source code has been modified from it's original state by the author
**  of igmpproxy.
**
**  smcroute 0.92 - Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
**  - Licensed under the GNU General Public License, version 2
**  
**  mrouted 3.9-beta3 - COPYRIGHT 1989 by The Board of Trustees of 
**  Leland Stanford Junior University.
**  - Original license can be found in the Stanford.txt file.
**
*/
/**
*   igmpproxy.h - Header file for common includes.
*/

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/param.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "os.h"
#include "config.h"

#include "list.h"

#define IGMPv3_PROXY                           (1)

#define INVAILD_TIMER                          (0)

static const unsigned short endian_test_word = 0x0101;
#define IS_BIGENDIAN() (*((unsigned char *)&endian_test_word)) 

/* IGMP versions definition */
#define IGMP_V1	                                1
#define IGMP_V2	                                2
#define IGMP_V3	                                3
#define IGMP_VERSION_MIN                        IGMP_V1
#define IGMP_VERSION_MAX                        IGMP_V3
#define IGMP_VERSION_DEFAULT                    IGMP_V3

/*
 * IGMPv3-related missing definitions
 */
#ifndef IGMP_V3_MEMBERSHIP_REPORT
#  ifdef IGMP_v3_HOST_MEMBERSHIP_REPORT
#    define IGMP_V3_MEMBERSHIP_REPORT	IGMP_v3_HOST_MEMBERSHIP_REPORT
#  else
#    define IGMP_V3_MEMBERSHIP_REPORT	0x22
#  endif
#endif

/*
 * Record type in IGMPv3 
 */
#ifndef IGMP_MODE_IS_INCLUDE
#  define IGMP_MODE_IS_INCLUDE		1
#endif

#ifndef IGMP_MODE_IS_EXCLUDE
#  define IGMP_MODE_IS_EXCLUDE		2
#endif

#ifndef IGMP_CHANGE_TO_INCLUDE_MODE
#  define IGMP_CHANGE_TO_INCLUDE_MODE	3
#endif

#ifndef IGMP_CHANGE_TO_EXCLUDE_MODE
#  define IGMP_CHANGE_TO_EXCLUDE_MODE	4
#endif

#ifndef IGMP_ALLOW_NEW_SOURCES
#  define IGMP_ALLOW_NEW_SOURCES	5
#endif

#ifndef IGMP_BLOCK_OLD_SOURCES
#  define IGMP_BLOCK_OLD_SOURCES	6
#endif

#ifndef IGMP_V3_QUERY_MINLEN
#  define IGMP_V3_QUERY_MINLEN		12
#endif


/*
 * Filter mode in IGMPv3
 */
#ifndef IGMP_V3_FMODE_INCLUDE
#  define IGMP_V3_FMODE_INCLUDE		1
#endif

#ifndef IGMP_V3_FMODE_EXCLUDE
#  define IGMP_V3_FMODE_EXCLUDE		0
#endif


/**
 * struct igmpv3_grec - an IGMPv3 group record
 * @grec_type: group record type
 * @grec_auxwords: aux data len
 * @grec_nsrcs: number of sources
 * @grec_mca: multicast address
 * @grec_src: source address list
 */
#ifndef IGMP_HEADER
struct igmpv3_grec {
    uint8_t  grec_type;
    uint8_t  grec_auxwords;
    uint16_t grec_nsrcs;
    uint32_t grec_mca;
    uint32_t grec_src[0];
};
#endif

/**
 * struct igmpv3_report - an IGMPv3 report
 * @type: type, allways 0x22 for IGMPv3 report
 * @resv1: reserved, doesn't used this field in IGMPv3
 * @csum: check sum of the whole IGMP message
 * @resv2: reserved, doesn't used this field in IGMPv3
 * @ngrec: number of group records
 * @grec: group record list
 */
#ifndef IGMP_HEADER
struct igmpv3_report {
    uint8_t  type;
    uint8_t  resv1;
    uint16_t csum;
    uint16_t resv2;
    uint16_t ngrec;
    struct igmpv3_grec grec[0];
};
#endif

/**
 * struct igmpv3_query - an IGMPv3 query
 * @type: type, allways 0x11 for IGMPv3 query
 * @code: max resp code
 * @csum: check sum of the whole IGMP message
 * @group: group address
 * @misc: big endian: 
 *          resc:4, suppress:1, qrv:3
 *        little endian:
 *          qrv:3, suppress:1, resc:4
 * @qqic: querier's query interval code
 * @nsrcs: number of sources
 * @srcs: sources address list
 */
#ifndef IGMP_HEADER
struct igmpv3_query {
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;
    uint32_t group;
#if defined(BIG_ENDIAN)
    uint8_t  resv:4,
             suppress:1,
             qrv:3;
#else
    uint8_t  qrv:3,
             suppress:1,
             resv:4;
#endif		
    uint8_t  qqic;
    uint16_t nsrcs;
    uint32_t srcs[0];
};
#endif

/*
 * Limit on length of route data
 */
#define MAX_IP_PACKET_LEN	576
#define MIN_IP_HEADER_LEN	20
#define MAX_IP_HEADER_LEN	60
#define IP_HEADER_RAOPT_LEN	24

#define MAX_MC_VIFS    32     // !!! check this const in the specific includes

// Useful macros..          
#define VCMC( Vc )  (sizeof( Vc ) / sizeof( (Vc)[ 0 ] ))
#define VCEP( Vc )  (&(Vc)[ VCMC( Vc ) ])

#define     IGMPPROXY_CONFIG_FILEPATH     "/etc/igmpproxy.conf"

// Bit manipulation macros...
#define BIT_ZERO(X)      ((X) = 0)
#define BIT_SET(X,n)     ((X) |= 1 << (n))
#define BIT_CLR(X,n)     ((X) &= ~(1 << (n)))
#define BIT_TST(X,n)     ((X) & 1 << (n))


//#################################################################################
//  Globals
//#################################################################################

/*
 * External declarations for global variables and functions.
 */
#define RECV_BUF_SIZE 8192
extern char     *recv_buf;
extern char     *send_buf;

extern char     s1[];
extern char     s2[];
extern char		s3[];
extern char		s4[];



//#################################################################################
//  Lib function prototypes.
//#################################################################################

/* syslog.c
 */
extern bool Log2Stderr;           // Log to stderr instead of to syslog
extern int  LogLevel;             // Log threshold, LOG_WARNING .... LOG_DEBUG 

void my_log( int Serverity, int Errno, const char *FmtSt, ... );

/* ifvc.c
 */
#define MAX_IF         40     // max. number of interfaces recognized 

// Interface states
#define IF_STATE_DISABLED      0   // Interface should be ignored.
#define IF_STATE_UPSTREAM      1   // Interface is the upstream interface
#define IF_STATE_DOWNSTREAM    2   // Interface is a downstream interface

// Multicast default values...
#define DEFAULT_ROBUSTNESS     2
#define DEFAULT_THRESHOLD      1
#define DEFAULT_RATELIMIT      0

// Define timer constants (in seconds...)
#define INTERVAL_QUERY          125
#define INTERVAL_QUERY_RESPONSE  10
//#define INTERVAL_QUERY_RESPONSE  10

#define IGMP_OQPI		((DEFAULT_ROBUSTNESS * INTERVAL_QUERY) + INTERVAL_QUERY_RESPONSE/2)
#define IGMP_GMI		((DEFAULT_ROBUSTNESS * INTERVAL_QUERY) + INTERVAL_QUERY_RESPONSE)

#define ROUTESTATE_NOTJOINED            0   // The group corresponding to route is not joined
#define ROUTESTATE_JOINED               1   // The group corresponding to route is joined
#define ROUTESTATE_CHECK_LAST_MEMBER    2   // The router is checking for hosts

/**
 * struct source - an IGMP source record
 * @addr: source address
 * @timer: source timer
 * @fstate: indicate the forwarding state.
 *          in EXCLUDE mode, we need to maintain 2 source list,
 *                           0 means unactive state, 1 means active state.
 *          in INCLUDE mode, we just used active state.
 * @is_scheduled: is this source in the group&source specific query scheduling?
 * @query_retransmission_count: group&source specific query retransmission count
 * @gp: the source belong to the group
 * @list: source list
 */
struct source {
    struct in_addr   addr;
    int              timer;
    int              fstate;
    int              is_scheduled;
    int              query_retransmission_count;

    struct group     *gp;

    struct list_node list;
};

/**
 * struct group - an IGMP group state
 * @addr: group address
 * @timer: group timer for switch mode from EXCLUDE to INCLUDE
 * @fmode: filter mode, INCLUDE or EXCLUDE
 * @version: Used for group compatibility
 * @v1_host_timer: IGMPv1 host timer
 * @v2_host_timer: IGMPv2 host timer
 * @intrface: the group belong to the interface
 * @is_scheduled: is it in the group specific query scheduling
 * @query_retransmission_count: group specific query retransmission count
 * @query_timer: timer for periodic queries
 * @sources: sources record list head
 * @nsrcs: sources record number
 * @nscheduled_src: the number of sources in the scheduling
 * @list: group list
 */
struct group {
    struct in_addr   mcast;
    int              timer;
    int              fmode;
    int              version;
    int              v1_host_timer;
    int              v2_host_timer;

    struct IfDesc    *interface;

    int              is_scheduled;
    int              query_retransmission_count;
    int              query_timer;
    

    struct list_head sources;
    int              nsrcs;
    int              nscheduled_src; /* FIXME */

    struct list_node list;
};

/**
 * struct source_in_member - an source record in member record
 * @addr: source address
 * @list: source list
 */
struct source_in_member {
    struct in_addr   addr;

    struct list_node list;
};

/**
 * struct member - an membership record
 * @mcast: group address
 * @fmode: filter mode, INCLUDE or EXCLUDE
 * @sources: sources record list head
 * @nsrcs: sources record number in the group
 * @list: group list
 */
struct member {
    struct in_addr   mcast;
    int              fmode;
    struct list_head sources;
    int              nsrcs;

    struct list_node list;
};

/**
 * struct member_db - an membership database
 * @members: membership list head
 * @nmems: number of memberships
 */
struct member_db {
    struct list_head members;
    int              nmems;
};

struct member_db member_database;

/**
 * struct scheduled_query - scheduled group-source specific query/group specific query 
 * @mcast: group address
 * @retnum: retransmit number
 * @numsrc: number of source, , in group specific query is zero, otherwise non-zero
 * @sources: sources
 */
struct scheduled_query {
    struct in_addr   mcast;
    int              retnum;
    struct list_head list;
    int              nsrcs;
    struct in_addr   sources[0];
}; 

/**
 * struct scheduled_db - ab scheduled query database
 * @queries: scheduled queries head 
 * @nqueries: number of queries
 */
struct scheduled_db {
    struct list_head queries;
    int              nqueries;
};

struct scheduled_db query_database;


// Linked list of networks... 
struct SubnetList {
    uint32_t              subnet_addr;
    uint32_t              subnet_mask;
    struct SubnetList*  next;
};

struct IfDesc {
    char                Name[IF_NAMESIZE];
    struct in_addr      InAdr;          /* == 0 for non IP interfaces */            
    short               Flags;
    short               state;
    struct SubnetList*  allowednets;
    struct SubnetList*  allowedgroups;
    unsigned int        robustness;
    unsigned char       threshold;   /* ttl limit */
    unsigned int        ratelimit; 
    unsigned int        index;		/* VIF index */

    bool                isQuerier;      /* am I a querier ? */
    int                 queryTimer;         /* query timer (125s) */
    int                 queryResponseTimer; /* query response interval timer(10s) */
    int                 otherQuerierPresentTimer;

    struct list_head    groups;
    int                 ngps;   /* number of groups */
};

// Keeps common configuration settings 
struct Config {
    unsigned int        robustnessValue;
    unsigned int        queryInterval;
    unsigned int        queryResponseInterval;
    // Used on startup..
    unsigned int        startupQueryInterval;
    unsigned int        startupQueryCount;
    // Last member probe...
    unsigned int        lastMemberQueryInterval;
    unsigned int        lastMemberQueryCount;
    // Set if upstream leave messages should be sent instantly..
    unsigned short      fastUpstreamLeave;
};

// Defines the Index of the upstream VIF...
extern int upStreamVif;

/* ifvc.c
 */
void buildIfVc( void );
struct IfDesc *getIfByName( const char *IfName );
struct IfDesc *getIfByIx( unsigned Ix );
struct IfDesc *getIfByAddress( uint32_t Ix );
int isAdressValidForIf(struct IfDesc* intrface, uint32_t ipaddr);

/* mroute-api.c
 */
struct MRouteDesc {
    struct in_addr  OriginAdr, McAdr;
    short           InVif;
    uint8_t           TtlVc[ MAX_MC_VIFS ];
};

// IGMP socket as interface for the mrouted API
// - receives the IGMP messages
extern int MRouterFD;

int enableMRouter( void );
void disableMRouter( void );
void addVIF( struct IfDesc *Dp );
int addMRoute( struct MRouteDesc * Dp );
int delMRoute( struct MRouteDesc * Dp );
int getVifIx( struct IfDesc *IfDp );

/* config.c
 */
int loadConfig(char *configFile);
void configureVifs(void);
struct Config *getCommonConfig(void);

/* igmp.c
*/
extern uint32_t allhosts_group;
extern uint32_t allrouters_group;
#if defined(IGMPv3_PROXY)
#define	INADDR_ALLV3RTRS_GROUP	0xe0000016U /* 224.0.0.22 */ 
extern uint32_t allv3routers_group;

void 
buildIgmpv3Query(uint32_t src, uint32_t dst, /* IP src + dst */
                 int type, int code, uint32_t group, uint16_t nsrcs, uint32_t *srcs, int srsp, int qqic, int datalen);

void sendIgmpv3query(uint32_t src, uint32_t dst, uint32_t len);
#endif
void initIgmp(void);
void acceptIgmp(int);
void sendIgmp (uint32_t, uint32_t, int, int, uint32_t,int);

/* lib.c
 */
char   *fmtInAdr( char *St, struct in_addr InAdr );
char   *inetFmt(uint32_t addr, char *s);
char   *inetFmts(uint32_t addr, uint32_t mask, char *s);
uint16_t inetChksum(uint16_t *addr, int len);

/* kern.c
 */
void k_set_rcvbuf(int bufsize, int minsize);
void k_hdr_include(int hdrincl);
void k_set_ttl(int t);
void k_set_loop(int l);
void k_set_if(uint32_t ifa);
/*
void k_join(uint32_t grp, uint32_t ifa);
void k_leave(uint32_t grp, uint32_t ifa);
*/

/* udpsock.c
 */
int openUdpSocket( uint32_t PeerInAdr, uint16_t PeerPort );

/* mcgroup.c
 */
int joinMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr );
int leaveMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr );
#if defined(IGMPv3_PROXY)

void setSourceFilter(int UdpSock, struct member *mb);
int joinSpecificMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr );
int leaveSpecificMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr );
#endif


/* rttable.c
 */
void initRouteTable(void);
void clearAllRoutes(void);
int insertRoute(uint32_t group, int ifx);
int activateRoute(uint32_t group, uint32_t originAddr);
void ageActiveRoutes(void);
void setRouteLastMemberMode(uint32_t group);
int lastMemberGroupAge(uint32_t group);
#if defined(IGMPv3_PROXY)
int getMcGroupSock(void);
int updateRoute(uint32_t group);
int deleteRoute(uint32_t group);
#endif

/* request.c
 */
void acceptGroupReport(uint32_t src, uint32_t group, uint8_t type);
void acceptLeaveMessage(uint32_t src, uint32_t group);
void sendGeneralMembershipQuery(void *argument);
#if defined(IGMPv3_PROXY)
void acceptIGMPMembershipQuery(uint32_t src, uint8_t type, char *buffer, uint32_t len);
void acceptIGMPv3GroupReport(uint32_t src, uint8_t type, char *buffer);
void sendGroupSpecificMembershipQuery(void *argument);
void sendGroupSourceSpecificMembershipQuery(void *argument, int with_sflag, uint32_t nsrcs, uint32_t *srcs); 
struct group *interfaceGroupLookup(struct IfDesc *sourceVif, uint32_t groupAddr);
struct group *interfaceGroupAdd(struct IfDesc *sourceVif, uint32_t groupAddr);
struct source *groupSourceLookup(struct group *gp, uint32_t sourceAddr);
#endif


/* callout.c 
*/
typedef void (*timer_f)(void *);

void callout_init(void);
void free_all_callouts(void);
void age_callout_queue(int);
int timer_nextTimer(void);
int timer_setTimer(int, timer_f, void *);
int timer_clearTimer(int);
int timer_leftTimer(int);
#if defined(IGMPv3_PROXY)
int timer_inQueue(int);
#endif

/* confread.c
 */
#define MAX_TOKEN_LENGTH    30

int openConfigFile(char *filename);
void closeConfigFile(void);
char* nextConfigToken(void);
char* getCurrentConfigToken(void);

/* igmpsnoop.c
 */
void sw_snoop_init(void);
int get_arp_entry(uint32_t src_addr);
int bridge2ifname(void);
void IGMP_snooping_handle_join(uint32_t src_addr, uint32_t mcgroup);
void IGMP_snooping_handle_leave(uint32_t src_addr, uint32_t mcgroup);
#if MC_FPP_ENABLED
void handle_fpp_join(uint32_t src_addr, uint32_t mcgroup);
void handle_fpp_leave(uint32_t src_addr, uint32_t mcgroup);
#endif
#ifdef AGING_TIMEOUT
void do_client_aging(void);
#endif

