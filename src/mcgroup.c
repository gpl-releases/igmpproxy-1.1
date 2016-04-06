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
**  - Original license can be found in the "doc/mrouted-LINCESE" file.
**
*/
/**
*   mcgroup contains functions for joining and leaving multicast groups.
*
*/

#include "defs.h"
#include "igmpproxy.h"

#include <alloca.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>

       

/**
*   Common function for joining or leaving a MCast group.
*/
static int joinleave( int Cmd, int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr ) {
    struct ip_mreq CtlReq;
    const char *CmdSt = Cmd == 'j' ? "join" : "leave";
    
    memset(&CtlReq, 0, sizeof(CtlReq));
    CtlReq.imr_multiaddr.s_addr = mcastaddr;
    CtlReq.imr_interface.s_addr = IfDp->InAdr.s_addr;
    
    {
        my_log( LOG_NOTICE, 0, "%sMcGroup: %s on %s", CmdSt, 
            inetFmt( mcastaddr, s1 ), IfDp ? IfDp->Name : "<any>" );
    }
    
    if( setsockopt( UdpSock, IPPROTO_IP, 
          Cmd == 'j' ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, 
          (void *)&CtlReq, sizeof( CtlReq ) ) ) 
    {
        my_log( LOG_WARNING, errno, "MRT_%s_MEMBERSHIP failed", Cmd == 'j' ? "ADD" : "DROP" );
        return 1;
    }
    
    return 0;
}

/**
*   Joins the MC group with the address 'McAdr' on the interface 'IfName'. 
*   The join is bound to the UDP socket 'UdpSock', so if this socket is 
*   closed the membership is dropped.
*          
*   @return 0 if the function succeeds, 1 if parameters are wrong or the join fails
*/
int joinMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr ) {
    return joinleave( 'j', UdpSock, IfDp, mcastaddr );
}

/**
*   Leaves the MC group with the address 'McAdr' on the interface 'IfName'. 
*          
*   @return 0 if the function succeeds, 1 if parameters are wrong or the join fails
*/
int leaveMcGroup( int UdpSock, struct IfDesc *IfDp, uint32_t mcastaddr ) {
    return joinleave( 'l', UdpSock, IfDp, mcastaddr );
}

#if 0
/* Full-state filter operations.  */
struct ip_msfilter
  {
    /* IP multicast address of group.  */
    struct in_addr imsf_multiaddr;
    //uint32_t imsf_multiaddr;

    /* Local IP address of interface.  */
    struct in_addr imsf_interface;
    //uint32_t imsf_interface;

    /* Filter mode.  */
    uint32_t imsf_fmode;

    /* Number of source addresses.  */
    uint32_t imsf_numsrc;
    /* Source addresses.  */
    struct in_addr imsf_slist[1];
    //uint32_t imsf_slist[1];
  };
#endif

#define IP_MSFILTER_SIZE(numsrc) (sizeof (struct ip_msfilter) \
				  - sizeof (struct in_addr)		      \
				  + (numsrc) * sizeof (struct in_addr))

#define IP_MSFILTER 41

/*
 * Set the source list and the source filter
 * on upstream interface
 */
void setSourceFilter(int UdpSock, struct member *mb) {
    assert(mb != NULL);

    struct IfDesc *upStreamIf = NULL;
    struct source_in_member *src_in_mb = NULL;
    int nnodes = 0;
            
    upStreamIf = getIfByIx( upStreamVif );

#define	MAX_ADDRS 500
    char buffer[IP_MSFILTER_SIZE(MAX_ADDRS)];
    memset(buffer, IP_MSFILTER_SIZE(MAX_ADDRS), 0);
    struct ip_msfilter *imsfp = NULL;
    int i = 0;

    // Sanitycheck the group adress...
    if( ! IN_MULTICAST( ntohl(mb->mcast.s_addr) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group. set source filter failed.",
            inetFmt(mb->mcast.s_addr, s1));
        return;
    } else {
        my_log(LOG_WARNING, 0, "The group address is %s\tmode %s, number of source is %d",
            inetFmt(mb->mcast.s_addr, s1), mb->fmode ? "INCLUDE" : "EXCLUDE", mb->nsrcs);
    }
    
    imsfp = (struct ip_msfilter *) &buffer;
#if 1
    imsfp->imsf_multiaddr = mb->mcast;
    imsfp->imsf_interface = upStreamIf->InAdr;
#else
    imsfp->imsf_multiaddr = mb->mcast.s_addr;
    imsfp->imsf_interface = upStreamIf->InAdr.s_addr;
#endif
    imsfp->imsf_fmode  = mb->fmode;
    imsfp->imsf_numsrc = mb->nsrcs;

    nnodes = mb->nsrcs;
    list_for_each(&mb->sources, src_in_mb, list) {
        if (nnodes--) {
            if(src_in_mb) {
#if 1
                imsfp->imsf_slist[i] = src_in_mb->addr;
#else
                imsfp->imsf_slist[i] = src_in_mb->addr.s_addr;
#endif
                i++;
            }
        }
    }
    assert(i == mb->nsrcs);
    assert(mb->nsrcs <= MAX_ADDRS);

    if (setsockopt(UdpSock, IPPROTO_IP, IP_MSFILTER, imsfp, IP_MSFILTER_SIZE(mb->nsrcs)) < 0 ) {
        my_log(LOG_ERR, errno, "setsockopt IP_MSFILTER fail. nnodes %d", nnodes); 
    }

    return;
}

