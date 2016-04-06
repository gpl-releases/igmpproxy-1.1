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
*   request.c 
*
*   Functions for recieveing and processing IGMP requests.
*
*/

#include "defs.h"
#include "igmpproxy.h"

// Prototypes...
void sendGroupSpecificMemberQuery(void *argument);  

void sourceDestory(struct source *src);

void sourceTimerTimeout(void *arg);

void groupTimerTimeout(void *arg);

void otherQuerierTimerTimeout(void *arg);

void oldHostTimerTimeout(void *arg);

uint32_t decodeExpTimeCode8(uint8_t code);
uint8_t encodeExpTimeCode8(uint32_t decodedTime);

void groupTimerUpdate(struct IfDesc *sourceVif, uint32_t mcast, uint32_t val);
void sourceTimerUpdate(struct IfDesc *sourceVif, uint32_t mcast, uint32_t nsrcs, uint32_t *sources, uint32_t val);

void memberDatabaseUpdate(uint32_t mcastAddr);

void processModeIsInclude(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources);
void processModeIsExclude(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources);
void processChangeToIncludeMode(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources);
void processChangeToExcludeMode(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources);
void processAllowNewSource(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources);
void processBlockOldSource(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources);

#define LMQT 2 /* FIXME: Need to get, unit second */

    
typedef struct {
    uint32_t      group;
    uint32_t      vifAddr;
    short       started;
} GroupVifDesc;


/**
*   Handles incoming membership reports, and
*   appends them to the routing table.
*/
void acceptGroupReport(uint32_t src, uint32_t group, uint8_t type) {
    struct IfDesc  *sourceVif;

    // Sanitycheck the group adress...
    if(!IN_MULTICAST( ntohl(group) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group.",
            inetFmt(group, s1));
        return;
    }

    // Find the interface on which the report was recieved.
    sourceVif = getIfByAddress( src );
    if(sourceVif == NULL) {
        my_log(LOG_WARNING, 0, "No interfaces found for source %s",
            inetFmt(src,s1));
        return;
    }

    if(sourceVif->InAdr.s_addr == src) {
        my_log(LOG_NOTICE, 0, "The IGMP message was from myself. Ignoring.");
        return;
    }

    // We have a IF so check that it's an downstream IF.
    if(sourceVif->state == IF_STATE_DOWNSTREAM) {

        my_log(LOG_DEBUG, 0, "Should insert group %s (from: %s) to route table. Vif Ix : %d",
            inetFmt(group,s1), inetFmt(src,s2), sourceVif->index);

        // The membership report was OK... Insert it into the route table..
        //insertRoute(group, sourceVif->index);
#if 0
        // Eric, ignore ssdp/upnp
        inetFmt(group,s1);
        if( strcmp(s1, "239.255.255.250") )
            IGMP_snooping_handle_join(src, group);
#endif
#if defined(IGMPv3_PROXY)

        // Eric, ignore ssdp/upnp
        inetFmt(group,s1);
        /* if( strcmp(s1, "239.255.255.250") ) */
        /*     IGMP_snooping_handle_join(src, group); */

        /* 
         * IGMPv1/v2 report equal IGMPv3 IS_EX { NULL } 
         */

        /* Find the group, and if not present, add it to interface */
        struct group *gp = NULL;
        gp = interfaceGroupAdd(sourceVif, group);
        if(gp == NULL) {
            my_log(LOG_ERR, 0, "Can't add group %08x to interface", group);
            return;
        }

        if(type == IGMP_V1_MEMBERSHIP_REPORT) {
            /* IGMPv2 report */
            if(gp->version != IGMP_V1)
                gp->version = IGMP_V1;

            timer_clearTimer(gp->v1_host_timer);
            gp->v1_host_timer = timer_setTimer(IGMP_GMI, oldHostTimerTimeout, gp);             
        } else {
            if (gp->version == IGMP_V1) {
                my_log(LOG_ERR, 0, "Receive the IGMPv2 report when version is IGMPv1");
                return;
            }
                
            /* IGMPv2 report */
            if(gp->version == IGMP_V3)
                gp->version = IGMP_V2;

            timer_clearTimer(gp->v2_host_timer);
            gp->v2_host_timer = timer_setTimer(IGMP_GMI, oldHostTimerTimeout, gp);
        }
       
        insertRoute(group, sourceVif->index);
        
        my_log(LOG_INFO, 0, "In %s", __FUNCTION__);
        processModeIsExclude(sourceVif, gp, 0, NULL);
#else
        insertRoute(group, sourceVif->index);

	// If we don't have a whitelist we insertRoute and done
	if(sourceVif->allowedgroups == NULL)
	{
	    insertRoute(group, sourceVif->index);
	    return;
	}
	// Check if this Request is legit on this interface
	struct SubnetList *sn;
	for(sn = sourceVif->allowedgroups; sn != NULL; sn = sn->next)
	    if((group & sn->subnet_mask) == sn->subnet_addr)
	    {
        	// The membership report was OK... Insert it into the route table..
        	insertRoute(group, sourceVif->index);
		return;
	    }
#endif
	my_log(LOG_INFO, 0, "The group address %s may not be requested from this interface. Ignoring.", inetFmt(group, s1));
    } else {
        // Log the state of the interface the report was recieved on.
        my_log(LOG_INFO, 0, "Mebership report was recieved on %s. Ignoring.",
            sourceVif->state==IF_STATE_UPSTREAM?"the upstream interface":"a disabled interface");
    }

}

/**
 *   Receives and handles a group leave message.
 */
void acceptLeaveMessage(uint32_t src, uint32_t group) {
    struct IfDesc   *sourceVif;
    
    my_log(LOG_DEBUG, 0,
	    "Got leave message from %s to %s. Starting last member detection.",
	    inetFmt(src, s1), inetFmt(group, s2));

    // Sanitycheck the group adress...
    if(!IN_MULTICAST( ntohl(group) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group.",
            inetFmt(group, s1));
        return;
    }

    // Find the interface on which the report was recieved.
    sourceVif = getIfByAddress( src );
    if(sourceVif == NULL) {
        my_log(LOG_WARNING, 0, "No interfaces found for source %s",
            inetFmt(src,s1));
        return;
    }

    // We have a IF so check that it's an downstream IF.
    if(sourceVif->state == IF_STATE_DOWNSTREAM) {
#if defined(IGMPv3_PROXY)
        /* 
         * IGMP v2 leave equal IGMPv3 IS_IN { NULL } 
         */

        /* Find the group, and if not present, add it to interface */
        struct group *gp = NULL;
        gp = interfaceGroupAdd(sourceVif, group);
        if(gp == NULL) {
            my_log(LOG_ERR, 0, "Can't add group %08x to interface", group);
            return;
        }

        /*
         * Ignore this 'Leave Group' message because this
         * group has IGMPv1 hosts members.
         */
        if (gp->version == IGMP_V1) {
            my_log(LOG_ERR, 0, "Receive the IGMPv2 leave when version is IGMPv1");
            return;
        }

        /* IGMPv2 leave */
        if(gp->version == IGMP_V3)
            gp->version = IGMP_V2;

        timer_clearTimer(gp->v2_host_timer);
        gp->v2_host_timer = timer_setTimer(IGMP_GMI, oldHostTimerTimeout, gp);
        
        processModeIsInclude(sourceVif, gp, 0, NULL);
#else
        GroupVifDesc   *gvDesc;
        gvDesc = (GroupVifDesc*) malloc(sizeof(GroupVifDesc));

        // Tell the route table that we are checking for remaining members...
        setRouteLastMemberMode(group);

        // Call the group spesific membership querier...
        gvDesc->group = group;
        gvDesc->vifAddr = sourceVif->InAdr.s_addr;
        gvDesc->started = 0;

        sendGroupSpecificMemberQuery(gvDesc);
#endif
    } else {
        // just ignore the leave request...
        my_log(LOG_DEBUG, 0, "The found if for %s was not downstream. Ignoring leave request.", inetFmt(src, s1));
    }
}


/*
 * Lookup a group in the grouptable of an interface
 */
struct group *
interfaceGroupLookup(struct IfDesc *sourceVif, uint32_t groupAddr)
{
    struct group *gp = NULL;
    int flag = 0;

    my_log(LOG_INFO, 0, "Look group address %s.", __FUNCTION__); 
    interfaceGroupLog(sourceVif);

    assert(sourceVif != NULL);

    /* Search the group in the interface */
    if(sourceVif->ngps == 0)
	return NULL;

    int nnodes = sourceVif->ngps;
    list_for_each(&sourceVif->groups, gp, list) {
        if (nnodes-- > 0) {
            if(gp && gp->mcast.s_addr == groupAddr) {
                my_log(LOG_INFO, 0, "XXX: find group address %s: %s in interface %s num of group %d.", 
                    inetFmt(groupAddr, s1), inetFmt(gp->mcast.s_addr, s2), sourceVif->Name, sourceVif->ngps - nnodes);
                flag = 1;
                break;
            }
        } else {
           flag = 0;
           break;
        }
    }

    if (flag)
        return gp;
    else
        return NULL;
}

/*
 * Create a group record, if fail, return NULL
 */
struct group *
groupCreate(uint32_t groupAddr)
{
    struct group *gp = NULL;

    // Sanitycheck the group adress...
    if( ! IN_MULTICAST( ntohl(groupAddr) )) {
        my_log(LOG_WARNING, 0, "The group address %s(%s) is not a valid Multicast group. group create failed.",
            inetFmt(groupAddr, s1), inetFmt(ntohl(groupAddr), s2));
        return NULL;
    }
    
    if ((gp = malloc(sizeof(*gp))) != NULL) {
        gp->mcast.s_addr               = groupAddr;
        gp->timer                      = INVAILD_TIMER;        /* Maybe need to chanage */
        gp->fmode                      = IGMP_V3_FMODE_INCLUDE; /* Default is INCLUDE{NUL} mode */
        gp->version                    = IGMP_V3;
        gp->v1_host_timer              = INVAILD_TIMER;
        gp->v2_host_timer              = INVAILD_TIMER;
        gp->interface                  = NULL;
        gp->is_scheduled               = 0;
        gp->query_retransmission_count = 0;
        gp->query_timer                = INVAILD_TIMER;
        gp->nsrcs                      = 0;
        gp->nscheduled_src             = 0;

        list_head_init(&gp->sources);
    } else {
        my_log(LOG_ERR, 0, "Creat new group error.");
    }
    
    return gp;	
}


/*
 * Destory a group record
 */
void groupDestory(struct group *gp)
{
    assert(gp != NULL);

    struct source *src = NULL;
    struct source *nxt = NULL;

    /* Remove the group from interface */
    my_log(LOG_DEBUG, 0, "XXX: Destory group %s : num of group %d", inetFmt(gp->mcast.s_addr, s1), gp->interface->ngps);
    list_del(&gp->list);
    if(gp->interface->ngps > 0)
        gp->interface->ngps--;

    interfaceGroupLog(gp->interface);

    /* Clean the timers */
    timer_clearTimer(gp->v1_host_timer);
    timer_clearTimer(gp->v2_host_timer);
    timer_clearTimer(gp->timer);

    /* XXX: Do we need to free the sources? */
    int nnodes = gp->nsrcs;
    list_for_each_safe(&gp->sources, src, nxt, list) {
        if (nnodes-- > 0) {
            sourceDestory(src);
        } else {
            break;
        }
    }

    free(gp);
    gp = NULL;
}

/*
 * Add a group to the set of groups of an interface, if fail, return NULL
 */
struct group *
interfaceGroupAdd(struct IfDesc *sourceVif, uint32_t groupAddr)
{
    assert(sourceVif != NULL);

    struct group *gp = NULL;

    // Sanitycheck the group adress...
    if( ! IN_MULTICAST( ntohl(groupAddr) )) {
        my_log(LOG_INFO, 0, "The group address %s is not a valid Multicast group. interface group add failed.",
            inetFmt(groupAddr, s1));
        return 0;
    }

    /* Return the group if it's already present */
    if((gp = interfaceGroupLookup(sourceVif, groupAddr)) != NULL) {

        my_log(LOG_INFO, 0, "----------- Find group address %s in interface %s interface number group %d.",
            inetFmt(groupAddr, s1), sourceVif->Name, sourceVif->ngps); 
        interfaceGroupLog(sourceVif);

        return gp;
    }

    if((gp = groupCreate(groupAddr)) != NULL) {
        list_add(&sourceVif->groups, &gp->list); /* Add group to interface */
        sourceVif->ngps++;

        gp->interface = sourceVif;

        my_log(LOG_INFO, 0, "************** Add group address %s to interface %s number group %d. Line %d",
            inetFmt(groupAddr, s1), sourceVif->Name, sourceVif->ngps, __LINE__);
        interfaceGroupLog(sourceVif);
    }

    return gp;
}

/*
 * Lookup a source in the group
 */
struct source *
groupSourceLookup(struct group *gp, uint32_t sourceAddr)
{
    struct source *src = NULL;
    int nnodes = gp->nsrcs;
    int flag = 0;
   
    /* Search the source in the group */
    list_for_each(&gp->sources, src, list) {
        if (nnodes-- > 0) {
            if(src && src->addr.s_addr == sourceAddr) {
                flag = 1;
                break;
            }
        } else {
            flag = 0;
            break;
        }
    }

    if (flag)
        return src;
    else
        return NULL;
}

/*
 * Create a source, if fail, return NULL
 */
struct source *
sourceCreate(uint32_t sourceAddr)
{
    struct source* src = NULL;
    
    if ((src = malloc(sizeof(*src))) != NULL) {
        src->addr.s_addr                = sourceAddr;
        src->timer                      = INVAILD_TIMER; /* Maybe need to chanage */
        src->fstate                     = 1;             /* Default is forward mode */
        src->is_scheduled               = 0;
        src->query_retransmission_count = 0;
        src->gp                         = NULL;

        my_log(LOG_INFO, 0, "Creat source %s.", inetFmt(sourceAddr, s1));
    } else {
        my_log(LOG_ERR, 0, "Creat new source error.");
    }
    
    return src;	
}

/*
 * Destory a source
 */
void sourceDestory(struct source *src)
{
    assert(src != NULL);    
    if(!src)
        return;

    /* Remove from the group */
    list_del(&src->list);
    src->gp->nsrcs--;

    /* Clean ther source timer */
    timer_clearTimer(src->timer);

    free(src);
    src= NULL;
}

/*
 * Add a source to the set of sources of an group, if fail, return NULL
 */
struct source *
groupSourceAdd(struct group *gp, uint32_t sourceAddr)
{
    assert(gp != NULL);

    struct source *src = NULL;

    /* Return the source if it's already present */
    if((src = groupSourceLookup(gp, sourceAddr)) != NULL)
        return src;

    if((src = sourceCreate(sourceAddr)) != NULL) {
        list_add(&gp->sources, &src->list); /* Add source to group */
        gp->nsrcs++;

        src->gp = gp;  
    }

    return src; 
}

/*
 * Handle a is_in{A} report for a group 
 * the report have only one source
 */
void
processModeIsInclude(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources) {
    struct source *src = NULL;
    
    assert(gp != NULL);
    assert(sourceVif != NULL);

    switch (gp->fmode) {
    case IGMP_V3_FMODE_INCLUDE:
    case IGMP_V3_FMODE_EXCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         * INCLUDE (A)    IS_IN (B)     INCLUDE (A+B)            (B)=GMI 
         * EXCLUDE (X,Y)  IS_IN (A)     EXCLUDE (X+A,Y-A)        (A)=GMI          
         */
        for(int i = 0; i < numsrc; i++) {
           src = groupSourceAdd(gp, sources[i]);
           
           if(src) {
               /* Update the source state */
               timer_clearTimer(src->timer);
               src->timer    = INVAILD_TIMER;
               src->timer    = timer_setTimer(IGMP_GMI, sourceTimerTimeout, src);
               src->fstate   = 1;
            } else {
                my_log(LOG_ERR, 0, "add filter source fail.");
            }
        }
        break;

    default:
        my_log(LOG_ERR, 0, "I don't think we can arrive there.");
        break;
    }

    /* XXX: Update the membership/router info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    memberDatabaseUpdate(gp->mcast.s_addr);    
}

/*
 * Handle a is_ex{A} report for a group 
 * the report have only one source
 */
void
processModeIsExclude(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources) {
    struct source *src = NULL;
    struct source *nxt = NULL;
    int nnodes = 0;
    int flag = 0;
    
    assert(gp != NULL);
    assert(sourceVif != NULL);

    interfaceGroupLog(sourceVif);

    switch (gp->fmode) {
    case IGMP_V3_FMODE_INCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         * INCLUDE (A)    IS_EX (B)     EXCLUDE (A*B,B-A)        (B-A)=0
         *                                                        Delete (A-B)
         *                                                        Group Timer=GMI        
         */
        gp->fmode = IGMP_V3_FMODE_EXCLUDE; /* Change the group mode */

        /* Delete (A-B) */
        nnodes = gp->nsrcs;
        list_for_each_safe(&gp->sources, src, nxt, list) {
            if(nnodes-- > 0) {
                int i;
                flag = 0;
                for(i = 0; i < numsrc; i++) {
                    if(src && src->addr.s_addr == sources[i]) {/* (A * B) */
                        flag = 1;
                        break;
                    }
                }

                /* We don't find it, delete it */
                if(!flag)
                    sourceDestory(src);
	    } else {
                break;
            }
        }

        for(int i = 0; i < numsrc; i++) {
            src = groupSourceLookup(gp, sources[i]);
            if(src) {
                /* (B) in the (A) */
                src->fstate = 1; /* FIXME: We don't need to update fstate */
            } else {
                /* (B) not in the (A), add it to unactive list */
                if((src = sourceCreate(sources[i])) != NULL) {
                    list_add(&gp->sources, &src->list); /* Add source to group */
                    gp->nsrcs++;

                    src->fstate = 0; /* Unactive this source */

                    src->gp = gp;  
                }
            }
        }

        /* Update the group timer */
        timer_clearTimer(gp->timer);
        gp->timer = INVAILD_TIMER;
        gp->timer = timer_setTimer(IGMP_GMI, groupTimerTimeout, gp);
                
        break;

    case IGMP_V3_FMODE_EXCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         * EXCLUDE (X,Y)  IS_EX (A)     EXCLUDE (A-Y,Y*A)        (A-X-Y)=GMI
         *                                                        Delete (X-A)
         *                                                        Delete (Y-A)
         *                                                        Group Timer=GMI    
         */

        /* Delete (X-A) and (Y-A) */
        nnodes = gp->nsrcs;
        list_for_each_safe(&gp->sources, src, nxt, list) {
            if(nnodes-- > 0) {
                int i;
                flag = 0;
                for(i = 0; i< numsrc; i++) {
                    if(src && src->addr.s_addr == sources[i]) {
                        flag = 1;
                        break;
                    } 
                }

                /* We don't find it, delete it */
                if(!flag)
                    sourceDestory(src);
             } else {
                 break;
             }
        }

        /* Get (A-Y) */
        for(int i = 0; i < numsrc; i++) {
           src = groupSourceLookup(gp, sources[i]);
           
           if(!src) {
                if((src = sourceCreate(sources[i]))) {
                    list_add(&gp->sources, &src->list); /* Add source to group */
                    gp->nsrcs++;

                    src->gp = gp;  
                }
                src->fstate = 1; /* Active this source */

                /* Update the source timer */
                /* (A-X-Y) = GMI */
                timer_clearTimer(src->timer);
                src->timer = INVAILD_TIMER;
                src->timer = timer_setTimer(IGMP_GMI, sourceTimerTimeout, src);
            }
        }

        /* Update the group timer */
        timer_clearTimer(gp->timer);
        gp->timer = INVAILD_TIMER;
        gp->timer = timer_setTimer(IGMP_GMI, groupTimerTimeout, gp);
        break;

    default:
        my_log(LOG_ERR, 0, "I don't think we can arrive there.");
        break;
    }

    /* XXX: Update the membership/router info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    interfaceGroupLog(sourceVif);
    memberDatabaseUpdate(gp->mcast.s_addr); 
}

/*
 * Handle to_in{ } report for a group 
 */
void
processChangeToIncludeMode(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources) {
    struct source *src = NULL;
    int nsource = 0;
    int nnodes = 0;
    int flag = 0;
    uint32_t *srcs = NULL;
    
    assert(gp != NULL);
    assert(sourceVif != NULL);

    /* In IGMPv1 group compatibility mode, ignored TO_IN{} */
    if(gp->version == IGMP_V1)
        return;    

    switch (gp->fmode) {
    case IGMP_V3_FMODE_INCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         * INCLUDE (A)    TO_IN (B)    INCLUDE (A+B)           (B)=GMI
         *                                                      Send Q(G,A-B)       
         */
        for(int i = 0; i < numsrc; i++) {
           src = groupSourceAdd(gp, sources[i]);
           
           if(src) {
               /* Update the source state */
               timer_clearTimer(src->timer);
               src->timer    = INVAILD_TIMER;
               src->timer    = timer_setTimer(IGMP_GMI, sourceTimerTimeout, src);
               src->fstate   = 1;
            } else {
                my_log(LOG_ERR, 0, "add filter source fail.");
            }
        }

        /* Send Q(G, A-B) */
        srcs = malloc(gp->nsrcs * sizeof(uint32_t));
        if(!srcs) {
            my_log(LOG_ERR, 0, "Can't malloc %d size uint32_t", gp->nsrcs);
        }
        
        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if(nnodes-- > 0) {
                int i;
                flag = 0;
                for(i = 0; i< numsrc; i++) {
                    if(src && src->addr.s_addr == sources[i]) {
                        flag = 1;
                        break;
                    }
                }
                
                /* We don't find it */
                if(!flag) {
                    srcs[nsource] = src->addr.s_addr;
                    nsource++;
            
                    if(!src->is_scheduled) {
                        src->is_scheduled = 1; /* We will send Q(G, S) */
                        gp->nscheduled_src++;
                    }
                }
            } else {
                break;
            }
        }
        
        if(nsource != 0) {
            sendGroupSourceSpecificMembershipQuery(gp, 0, nsource, srcs);
        }
        free(srcs);        

        break;

    case IGMP_V3_FMODE_EXCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         * EXCLUDE (X,Y)  TO_IN (A)    EXCLUDE (X+A,Y-A)       (A)=GMI
         *                                                      Send Q(G,X-A)
         *                                                      Send Q(G)
         */
        for(int i = 0; i < numsrc; i++) {
           src = groupSourceAdd(gp, sources[i]);

           if (src) {
               /* Update the source state */
               src->fstate   = 1;
               timer_clearTimer(src->timer);
               src->timer = INVAILD_TIMER;
               src->timer    = timer_setTimer(IGMP_GMI, sourceTimerTimeout, src);
           } else {
               my_log(LOG_ERR, 0, "add filter source fail");
           }
        }

        /* 
         *    Send Q(G, X-A)
         *    Send Q(G) 
         */
        srcs = malloc(gp->nsrcs * sizeof(uint32_t));
        if(!srcs) {
            my_log(LOG_ERR, 0, "Can't malloc %d size uint32_t", gp->nsrcs);
        }

        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if(nnodes-- > 0) {
                if(src && src->fstate == 1) {
                    int i;
                    flag = 0;
                    for(i = 0; i< numsrc; i++) {
                        if(src->addr.s_addr == sources[i]) {
                            flag = 1;
                            break;
                        }
                    }
                    
                    if(!flag) {
                        srcs[nsource] = src->addr.s_addr;
                        nsource++;

                        if(!src->is_scheduled) {
                            src->is_scheduled = 1; /* We will send Q(G, S) */
                            gp->nscheduled_src++;
                        }
                    }
                }
            } else {
                break;
            }
        }
        
        if(nsource != 0) {
            sendGroupSourceSpecificMembershipQuery(gp, 0, nsource, srcs);
        }
        free(srcs);

        if(!gp->is_scheduled)
            gp->is_scheduled = 1;

        sendGroupSpecificMemberQuery(gp);
        
        break;

    default:
        my_log(LOG_ERR, 0, "I don't think we can arrive there.");
        break;
    }

    /* XXX: Update the membership/router info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    memberDatabaseUpdate(gp->mcast.s_addr);
}

/*
 * Handle to_ex{ } report for a group 
 */
void
processChangeToExcludeMode(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources) {
    struct source *src = NULL;
    struct source *nxt = NULL;
    int  nsource = 0;
    int  nnodes = 0;
    int  flag = 0;
    uint32_t *srcs = NULL;    

    assert(gp != NULL);
    assert(sourceVif != NULL);

    /*
     * XXX: Ignore the source list in the CHANGE_TO_EXCLUDE_MODE
     * messages when in IGMPv1, IGMPv2 compatibility mode.
     */
    if(gp->version != IGMP_V3) {
        numsrc = 0;
        /* XXX: Don't modified *sources */
    }

    switch (gp->fmode) {
    case IGMP_V3_FMODE_INCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         *  INCLUDE (A)    TO_EX (B)    EXCLUDE (A*B,B-A)       (B-A)=0
         *                                                      Delete (A-B)
         *                                                      Send Q(G,A*B)
         *                                                      Group Timer=GMI   
         */
        gp->fmode = IGMP_V3_FMODE_EXCLUDE; /* Change the group mode */
        
        srcs = malloc(numsrc * sizeof(uint32_t));
        if(!srcs) {
            my_log(LOG_ERR, 0, "Can't malloc %d size uint32_t", numsrc);
        }
       
        /* Delete (A-B) */
        nnodes = gp->nsrcs;
        list_for_each_safe(&gp->sources, src, nxt, list) {
            if(nnodes-- > 0) {
                int i;
                flag = 0;
                for(i = 0; i< numsrc; i++) {
                    if(src && src->addr.s_addr == sources[i]) {
                        srcs[nsource] = sources[i];
                        nsource++;

                        if(!src->is_scheduled) {
                            src->is_scheduled = 1;
                            gp->nscheduled_src++;
                        }
                        flag = 1;
                        break;
                    }
                }

                /* We don't find it, delete it */
                if(!flag)
                    sourceDestory(src);
            } else {
                break;
            }
        }

        for(int i = 0; i < numsrc; i++) {
            src = groupSourceLookup(gp, sources[i]);
            if(src) {
                /* (B) in the (A) */
                src->fstate = 1; /* FIXME: We don't need to update fstate */
            } else {
                /* (B) not in the (A), add it to unactive list */
                if((src = sourceCreate(sources[i]))) {
                    list_add(&gp->sources, &src->list); /* Add source to group */
                    gp->nsrcs++;

                    src->fstate = 0; /* Unactive this source */
                    src->gp = gp;  
                }
            }
        }

        /* Update the group timer */
        timer_clearTimer(gp->timer);
        gp->timer = INVAILD_TIMER;
        gp->timer = timer_setTimer(IGMP_GMI, groupTimerTimeout, gp);
        
        /* TODO: Send Q(G, A*B)*/
        if(nsource != 0) {
            sendGroupSourceSpecificMembershipQuery(gp, 0, nsource, srcs);
        }
        free(srcs);
        
        break;

    case IGMP_V3_FMODE_EXCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         *  EXCLUDE (X,Y)  TO_EX (A)    EXCLUDE (A-Y,Y*A)       (A-X-Y)=Group Timer
         *                                                      Delete (X-A)
         *                                                      Delete (Y-A)
         *                                                      Send Q(G,A-Y)
         *                                                      Group Timer=GMI
         */

        /* Delete (X-A) and (Y-A)*/
        nnodes = gp->nsrcs;
        list_for_each_safe(&gp->sources, src, nxt, list) {
            if(nnodes-- > 0) {
                int i;
                flag = 0;
                for(i = 0; i< numsrc; i++) {
                    if(src && src->addr.s_addr == sources[i]) {
                        flag = 1;
                        break;
                    }
                }

                /* We don't find it, delete it */
                if(!flag)
                    sourceDestory(src);
            } else {
                break;
            }
        }

        for(int i = 0; i < numsrc; i++) {
           src = groupSourceLookup(gp, sources[i]);
           
           if(!src) {
                if((src = sourceCreate(sources[i]))) {
                    list_add(&gp->sources, &src->list); /* Add source to group */
                    gp->nsrcs++;

                    src->gp = gp;  
             
                    src->fstate = 1; /* Active this source */

                    /* Update the source timer */
                    timer_clearTimer(src->timer);
                    src->timer = INVAILD_TIMER;
                    src->timer = timer_setTimer(timer_leftTimer(gp->timer), sourceTimerTimeout, src);
                }
            }
        }

        /* Update the group timer */
        timer_clearTimer(gp->timer);
        gp->timer = INVAILD_TIMER;
        gp->timer = timer_setTimer(IGMP_GMI, groupTimerTimeout, gp);

        /* Send Q(G, A-Y) */
        srcs = malloc(gp->nsrcs * sizeof(uint32_t));
        if(!srcs) {
            my_log(LOG_ERR, 0, "Can't malloc %d size uint32_t", gp->nsrcs);
        }
        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if(nnodes-- > 0) {
                if(src && src->fstate == 1) {
                    srcs[nsource] = src->addr.s_addr;
                    nsource++;
                    if(!src->is_scheduled) {
                        src->is_scheduled = 1;
                        gp->nscheduled_src++;
                    }
                }
            } else {
                break;
            }
        }
        
        if(nsource != 0) {
            sendGroupSourceSpecificMembershipQuery(gp, 0, nsource, srcs);
        }
        free(srcs);        

        break;

    default:
        my_log(LOG_ERR, 0, "I don't think we can arrive there.");
        break;
    }

    /* XXX: Update the membership/router info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    memberDatabaseUpdate(gp->mcast.s_addr);
}

/*
 * Handle a allow report for a group 
 */
void
processAllowNewSource(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources) {
    struct source *src = NULL;
    
    assert(gp != NULL);
    assert(sourceVif != NULL);

    switch (gp->fmode) {
    case IGMP_V3_FMODE_INCLUDE:
    case IGMP_V3_FMODE_EXCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         * INCLUDE (A)    ALLOW (B)    INCLUDE (A+B)           (B)=GMI
         * EXCLUDE (X,Y)  ALLOW (A)    EXCLUDE (X+A,Y-A)       (A)=GMI     
         */
        for(int i = 0; i < numsrc; i++) {
           src = groupSourceAdd(gp, sources[i]);
           
           if (src) {
               /* Update the source state */
               timer_clearTimer(src->timer);
               src->timer    = INVAILD_TIMER;
               src->timer    = timer_setTimer(IGMP_GMI, sourceTimerTimeout, src);
               src->fstate   = 1;
           } else {
               my_log(LOG_ERR, 0, "add filter source fail.");
           }
        }
        break;

    default:
        my_log(LOG_ERR, 0, "I don't think we can arrive there.");
        break;
    }

    /* XXX: Update the membership/router info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    memberDatabaseUpdate(gp->mcast.s_addr);
}

/*
 * Handle a block report for a group 
 */
void
processBlockOldSource(struct IfDesc *sourceVif, struct group *gp, int numsrc, uint32_t *sources) {
    struct source *src = NULL;

    int nsource = 0;
    int nnodes = 0;
    //uint32_t *source = NULL;
    uint32_t *srcs = NULL;
    
    /* In IGMPv1/IGMPv2 group compatibility mode, ignored BLOCK */
    if(gp->version != IGMP_V3)
        return;    

/*
    source = malloc(nsource * sizeof(uint32_t));
    if(!source) {
        my_log(LOG_ERR, 0, "Malloc sources fail.\n");
        return;
    }    
*/
    assert(gp != NULL);
    assert(sourceVif != NULL);

    switch (gp->fmode) {
    case IGMP_V3_FMODE_INCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         * INCLUDE (A)    BLOCK (B)    INCLUDE (A)             Send Q(G,A*B) 
         */
        
        /* Send Q(G, A*B) */
        srcs = malloc(numsrc * sizeof(uint32_t));
        if(!srcs) {
            my_log(LOG_ERR, 0, "Can't malloc %d size uint32_t", numsrc);
        }
        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if (nnodes-- > 0) {
                for(int i= 0; i<numsrc; i++) {
                    if(src && src->addr.s_addr == sources[i]) {
                        srcs[nsource] = sources[i];
                        nsource++;
                    
                        if(!src->is_scheduled) {
                            src->is_scheduled = 1;
                            gp->nscheduled_src++;
                        }     
                    }
                }
            } else {
                break;
            }
        }

        if(nsource != 0) {
            sendGroupSourceSpecificMembershipQuery(gp, 0, nsource, srcs);
        }
        free(srcs);

        break;

    case IGMP_V3_FMODE_EXCLUDE:
        /*
         * Router State   Report Rec'd New Router State        Actions
         *  ------------   ------------ ----------------        -------
         *  EXCLUDE (X,Y)  BLOCK (A)    EXCLUDE (X+(A-Y),Y)     (A-X-Y)=Group Timer
         *                                                      Send Q(G,A-Y)
         */
        srcs = malloc(numsrc * sizeof(uint32_t));
        if(!srcs) {
            my_log(LOG_ERR, 0, "Can't malloc %d size uint32_t", numsrc);
        }
        for(int i = 0; i < numsrc; i++) {
            src = groupSourceLookup(gp, sources[i]);
            if(!src) {
                if((src = sourceCreate(sources[i]))) {
                    list_add(&gp->sources, &src->list); /* Add source to group */
                    gp->nsrcs++;

                    src->gp = gp;  
                }
                src->fstate = 1; /* Active this source */

                /* Update the source timer */
                timer_clearTimer(src->timer);
                src->timer = INVAILD_TIMER;
                src->timer = timer_setTimer(timer_leftTimer(gp->timer), sourceTimerTimeout, src);                    
            }

            if(src->fstate == 1) {
                if(!src->is_scheduled) {
                    src->is_scheduled = 1;
                    gp->nscheduled_src++;
                }
                
                srcs[nsource] = src->addr.s_addr;
                nsource++;
            }
        }

        /* Send Q(G, A-Y) */
        if(nsource != 0) {
            sendGroupSourceSpecificMembershipQuery(gp, 0, nsource, srcs);
        }
        free(srcs);

        break;

    default:
        my_log(LOG_ERR, 0, "I don't think we can arrive there.");
        break;
    }

    /* XXX: Update the membership/router info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    memberDatabaseUpdate(gp->mcast.s_addr);
}

/*
 *   Handles incoming IGMP membership query
 */
void acceptIGMPMembershipQuery(uint32_t src, uint8_t type, char *buffer, uint32_t len)
{
    struct IfDesc   *sourceVif = NULL;
    struct igmp     *igmp = NULL;
    uint32_t message_version;
    uint32_t mcast = 0; /* The group address in the query */

    /* Find the interface on which the report was recieved. */
    sourceVif = getIfByAddress( src );
    if(sourceVif == NULL) {
        my_log(LOG_WARNING, 0, "No interfaces found for source %s",
                inetFmt(src,s1));
        return;
    }

    if(sourceVif->InAdr.s_addr == src) {
        my_log(LOG_NOTICE, 0, "The IGMP message was from myself. Ignoring.");
        return;
    }

    /* We have a IF so check that it's an downstream IF. */
    if(sourceVif->state == IF_STATE_DOWNSTREAM) {

	/*
	 * The IGMP version of a Membership Query message is:
	 * - IGMPv1 Query: length = 8 AND Max Resp Code field is zero
	 * - IGMPv2 Query: length = 8 AND Max Resp Code field is non-zero
	 * - IGMPv3 Query: length >= 12
	 */
        igmp = (struct igmp *)buffer;
        mcast = igmp->igmp_group.s_addr;
        if(igmp->igmp_code == 0 && len == IGMP_MINLEN) {
            /* Receive IGMPv1 query */
            message_version = IGMP_V1;
            my_log(LOG_NOTICE, 0, "The IGMP message was IGMPv1 Query, but the interface is IGMPv3 mode. Ignoring.");
            return;
        } else if (igmp->igmp_code != 0 && len == IGMP_MINLEN) {
            /* Receive IGMPv2 query */
            message_version = IGMP_V2;
            my_log(LOG_NOTICE, 0, "The IGMP message was IGMPv2 Query, but the interface is IGMPv3 mode. Ignoring.");
            return;
        } else if (len >= IGMP_V3_QUERY_MINLEN) {
            /* Receive IGMPv3 query */
            message_version = IGMP_V3;

        } else {
            /* The others. */
            my_log(LOG_ERR, 0, "Can't handle the IGMP query type. Ignoring.");
            return;
       }
       
       /* Compare this querier address with my address. */
       if(src < sourceVif->InAdr.s_addr) {
           /* 
            * Eventually a new querier 
            */

           /* Disable query timer */
           timer_clearTimer(sourceVif->queryTimer);
           sourceVif->queryTimer = INVAILD_TIMER;

           sourceVif->isQuerier = false;

           /* Register other querier present timer */
           sourceVif->otherQuerierPresentTimer = timer_setTimer(IGMP_OQPI, otherQuerierTimerTimeout, sourceVif);
        }   

        if(message_version == IGMP_V3) {
            struct igmpv3_query *ih3 = (struct igmpv3_query *)buffer;

            uint8_t sflag  = ih3->suppress;
            uint8_t qrv    = ih3->qrv;
            uint32_t qqic  = decodeExpTimeCode8(ih3->qqic);
            uint16_t nsrcs = ntohs(ih3->nsrcs);

            if(IGMP_V3_QUERY_MINLEN + nsrcs * sizeof(uint32_t) > len) {
                my_log(LOG_ERR, 0, "The IGMPv3 query is short. Ignoring.");
                return;
            }

            /* Receive general query, do nothing */
            if(mcast == 0 && nsrcs == 0)
                return;
            
            /* 
             * XXX: 
             *   1. Update the querier's robustness variable (qrv)
             *   2. Update the querier's query internal code (qqic)  
             */
            
            if(!sflag) {
                if(mcast != 0 && nsrcs == 0) {
                    /* Receive group spesific query, Q(G) = LMQT */
                    groupTimerUpdate(sourceVif, mcast, LMQT);                       

                } else if (mcast != 0 && nsrcs != 0) {
                    /* Receive group and source spesific query, Q(G, A) = LMQT */
                    sourceTimerUpdate(sourceVif, mcast, nsrcs, ih3->srcs, LMQT);

                }
            }
        } /* End of message_version == IGMP_V3 */
    } else {
        my_log(LOG_ERR, 0, "Receive IGMP query in no-Downstream. Ignoring.");
        return;
    }   
}

void groupTimerUpdate(struct IfDesc *sourceVif, uint32_t mcast, uint32_t val)
{
    struct group *gp = interfaceGroupLookup(sourceVif, mcast);
    if(gp != NULL) {
        timer_clearTimer(gp->timer);
        gp->timer = timer_setTimer(val, groupTimerTimeout, gp);
    }
}

void sourceTimerUpdate(struct IfDesc *sourceVif, uint32_t mcast, uint32_t nsrcs, uint32_t *sources, uint32_t val)
{
    struct group *gp = interfaceGroupLookup(sourceVif, mcast);
    if(gp != NULL) {
        uint32_t i;
        uint32_t source = 0;

        for(i=0; i< nsrcs; i++) {
            source = sources[i];
            struct source *src = groupSourceLookup(gp, source);
            if(src != NULL) {
                timer_clearTimer(src->timer);
                src->timer = timer_setTimer(val, sourceTimerTimeout, src);
            }
        }
    }
}

uint32_t decodeExpTimeCode8(uint8_t code)
{
    uint32_t decodedTime = 0;

    /*
     * From RFC 3376 Section 4.1.1/4.1.7
     *
     * If Code < 128, Time = Code
     *
     * If Code >= 128, Code represents a floating-point value as follows:
     *
     *     0 1 2 3 4 5 6 7
     *    +-+-+-+-+-+-+-+-+
     *    |1| exp | mant  |
     *    +-+-+-+-+-+-+-+-+
     *
     * Time = (mant | 0x10) << (exp + 3)
     */
    if (code < 128) {
	decodedTime = code;
    } else {
	uint8_t mant =  code & 0xf;
	uint8_t exp = (code >> 4) & 0x7;
	decodedTime = (mant | 0x10) << (exp + 3);
    }

    return decodedTime;
}

uint8_t encodeExpTimeCode8(uint32_t decodedTime)
{
    uint8_t code = 0;

    /*
     * From RFC 3376 Section 4.1.1/4.1.7
     *
     * If Code < 128, Time = Code
     *
     * If Code >= 128, Code represents a floating-point value as follows:
     *
     *     0 1 2 3 4 5 6 7
     *    +-+-+-+-+-+-+-+-+
     *    |1| exp | mant  |
     *    +-+-+-+-+-+-+-+-+
     *
     * Time = (mant | 0x10) << (exp + 3)
     */
    if (decodedTime < 128) {
	code = decodedTime;
    } else {
	uint8_t mant = 0;
	uint8_t exp = 0;

	/* Calculate the "mant" and the "exp" */
	while ((decodedTime >> (exp + 3)) > 0x1f) {
	    exp++;
	}
	mant = (decodedTime >> (exp + 3)) & 0xf;

	code = 0x80 | (exp << 4) | mant;
    }

    return code;
}

/**
*   Handles incoming IGMPv3 membership reports, and
*   appends them to the routing table.
*/
void acceptIGMPv3GroupReport(uint32_t src, uint8_t type, char *buffer) {
    struct IfDesc   *sourceVif = NULL;

    struct igmpv3_report *report = NULL;
    struct igmpv3_grec *record = NULL;
    uint16_t numOfGroup; /* number of group in the IGMPv3 report */
    uint16_t numOfSource;/* number of source in the record */
    uint16_t auxLen;
    uint16_t Idx;
    uint32_t group;
    char *tmp = NULL;
    struct group *gp = NULL;

    // Find the interface on which the report was recieved.
    sourceVif = getIfByAddress( src );
    if(sourceVif == NULL) {
        my_log(LOG_WARNING, 0, "No interfaces found for source %s",
                inetFmt(src,s1));
        return;
    }

    if(sourceVif->InAdr.s_addr == src) {
        my_log(LOG_NOTICE, 0, "The IGMP message was from myself. Ignoring.");
        return;
    }
    
    report = (struct igmpv3_report *) buffer;

    numOfGroup = ntohs(report->ngrec);

    tmp = (char *)report->grec;

    // We have a IF so check that it's an downstream IF.
    if(sourceVif->state == IF_STATE_DOWNSTREAM) {
    
        for(Idx=0; Idx < numOfGroup; Idx++) {
            record = (struct igmpv3_grec *)tmp;          
 
            // Sanitycheck the group adress...
            group = record->grec_mca;
            if(!IN_MULTICAST( ntohl(group) )) {
                my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group.",
                    inetFmt(group, s1));
                return;
            } else {
                my_log(LOG_INFO, 0, "The group address is %s.",
                    inetFmt(group, s1));
            }

            // Find the group, and if not present, add it to interface
            gp = NULL;
            gp = interfaceGroupAdd(sourceVif, group);
            if(gp == NULL) {
                my_log(LOG_ERR, 0, "Can't add group %08x to interface", group);
                return;
            } else {
                my_log(LOG_DEBUG, 0, "Find the group. %s / 0x%08x", __FUNCTION__, gp->mcast.s_addr);
            }

            // Eric, ignore ssdp/upnp
            inetFmt(group,s1);
            /* if( strcmp(s1, "239.255.255.250") ) */
            /*     IGMP_snooping_handle_join(src, group); */

            /* XXX: need to move to before add group to interface? */
            if (gp->version != IGMP_V3) {
                my_log(LOG_WARNING, 0, "Receive the IGMPv3 report when version isn't IGMPv3");
                return;
            }

            uint8_t type = record->grec_type; /* record type */
            numOfSource = ntohs(record->grec_nsrcs);

            switch(type) {
            case IGMP_MODE_IS_INCLUDE:
                my_log(LOG_INFO, 0, "In %s processModeIsInclude", __FUNCTION__);
                processModeIsInclude(sourceVif, gp, numOfSource, record->grec_src);
                break;
 
            case IGMP_MODE_IS_EXCLUDE:
                my_log(LOG_INFO, 0, "In %s processModeIsExclude", __FUNCTION__);
                processModeIsExclude(sourceVif, gp, numOfSource, record->grec_src);
                break;

            case IGMP_CHANGE_TO_INCLUDE_MODE:
                my_log(LOG_INFO, 0, "In %s processChangeToIncludeMode", __FUNCTION__);
                processChangeToIncludeMode(sourceVif, gp, numOfSource, record->grec_src);
                break;

            case IGMP_CHANGE_TO_EXCLUDE_MODE:
                my_log(LOG_INFO, 0, "In %s processChangeToExcludeMode", __FUNCTION__);
                processChangeToIncludeMode(sourceVif, gp, numOfSource, record->grec_src);
                break;

            case IGMP_ALLOW_NEW_SOURCES:
                my_log(LOG_INFO, 0, "In %s processAllowNewSource", __FUNCTION__);
                processAllowNewSource(sourceVif, gp, numOfSource, record->grec_src);
                break;

            case IGMP_BLOCK_OLD_SOURCES:
                my_log(LOG_INFO, 0, "In %s processBlockOldSource", __FUNCTION__);
                processBlockOldSource(sourceVif, gp, numOfSource, record->grec_src);
                break;
            
            default:
		my_log(LOG_ERR, 0, "The record type %02x can't handle.", type);
                break;
            }
            
            auxLen = ntohs (record->grec_auxwords);

            /* Skip the auxiliary data */
            tmp +=(sizeof(struct igmpv3_grec) + numOfSource * sizeof(uint32_t) + auxLen);

#if 0
            my_log(LOG_DEBUG, 0, "Should insert group %s (from: %s) to route table. Vif Ix : %d",
                inetFmt(group,s1), inetFmt(src,s2), sourceVif->index);

	    // If we don't have a whitelist we insertRoute and done
	    if(sourceVif->allowedgroups == NULL)
	    {
	        insertRoute(group, sourceVif->index);
	        return;
	    }
	    // Check if this Request is legit on this interface
	    struct SubnetList *sn;
	    for(sn = sourceVif->allowedgroups; sn != NULL; sn = sn->next)
	        if((group & sn->subnet_mask) == sn->subnet_addr)
	        {
        	    // The membership report was OK... Insert it into the route table..
        	    insertRoute(group, sourceVif->index);
		    return;
	        }
	    my_log(LOG_INFO, 0, "The group address %s may not be requested from this interface. Ignoring.", inetFmt(group, s1));
#endif
        }
    } else {
        // Log the state of the interface the report was recieved on.
        my_log(LOG_INFO, 0, "Mebership report was recieved on %s. Ignoring.",
            sourceVif->state==IF_STATE_UPSTREAM?"the upstream interface":"a disabled interface");
    }
}

void scheduledRetransmissionQuery(void *argument) {
    assert(argument != NULL);

    struct group *gp = (struct group *)argument;
    struct source *src = NULL;
    struct  Config  *conf = getCommonConfig();
    int do_send_group_query = 0;
    uint32_t *sources_with_sflag = NULL;
    uint32_t *sources_without_sflag = NULL;
    uint32_t nwith_sflag = 0;
    uint32_t nwithout_sflag = 0;
    int nnodes = 0;

    if(gp->is_scheduled == 1 && gp->query_retransmission_count != 0) {
        /* XXX: Send group spesific query */
        sendGroupSpecificMemberQuery(gp);
        
        do_send_group_query = 1;
        gp->query_retransmission_count--;

        if(gp->query_retransmission_count == 0)
            gp->is_scheduled = 0; /* group spesific retransmission finished */
    }

    if(gp->nscheduled_src != 0) {
        if(!do_send_group_query) {
            sources_with_sflag = malloc(gp->nscheduled_src * sizeof(uint32_t));
            if(!sources_with_sflag) {
                my_log(LOG_ERR, 0, "Malloc sources_with_sflag fail");
                return;
            }   
        }

        sources_without_sflag = malloc(gp->nscheduled_src * sizeof(uint32_t));
        if(!sources_without_sflag) {
            my_log(LOG_ERR, 0, "Malloc sources_without_sflag fail");
            return;
        }        

        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if (nnodes-- > 0) {
                if(src && src->is_scheduled && src->query_retransmission_count !=0) {
                    if(timer_leftTimer(src->timer) <= LMQT) {
                        sources_without_sflag[nwithout_sflag] = src->addr.s_addr;
                        nwithout_sflag++;
                    } else if (timer_leftTimer(src->timer) > LMQT && !do_send_group_query) {
                        sources_with_sflag[nwith_sflag] = src->addr.s_addr;
                        nwith_sflag++;
                    }
                    
                    src->query_retransmission_count--;
                    if(src->query_retransmission_count == 0) {
                        src->is_scheduled = 0; /* retransmission finished */
                    
                        gp->nscheduled_src--;
                    }
                }
            } else {
                break;
            }
        }

        if(!nwithout_sflag) {
            /* XXX: Send group&source spesific query without sflag */
            sendGroupSourceSpecificMembershipQuery(gp, 0, nwithout_sflag, sources_without_sflag);
        }
        free(sources_without_sflag);
        sources_without_sflag = NULL;      
 
        if(!nwith_sflag) {
            /* XXX: Send group&source spesific query with sflag */
            sendGroupSourceSpecificMembershipQuery(gp, 1, nwith_sflag, sources_with_sflag);
        }
        free(sources_with_sflag);
        sources_with_sflag = NULL;
    }

    if((gp->query_retransmission_count != 0) || gp->nscheduled_src != 0)
        gp->query_timer = timer_setTimer(conf->lastMemberQueryInterval, scheduledRetransmissionQuery, gp);
}

/**
 *   XXX:
 *   Sends a group-source specific member query and schedule
 *   the retransmission query.
 */
void sendGroupSourceSpecificMembershipQuery(void *argument, int with_sflag, uint32_t nsrcs, uint32_t *sources) {
    assert(argument != NULL);

    struct group *gp = (struct group *)argument;
    struct source *src = NULL;
    struct  Config  *conf = getCommonConfig();

    struct IfDesc *Dp = gp->interface;
    int nnodes = 0;

    /*
     * Only the Querier should originate Query messages
     */
    if(!Dp->isQuerier)
        return;

    nnodes = gp->nsrcs;
    list_for_each(&gp->sources, src, list) {
        if (nnodes-- > 0) {
            /* Lower the source timer with LMQT */
            if(src && src->is_scheduled == 1 && src->query_retransmission_count == 0) {
                if(timer_leftTimer(src->timer) > LMQT) {
                    timer_clearTimer(src->timer);
                    src->timer = timer_setTimer(LMQT, sourceTimerTimeout, src);
                }
            
                src->query_retransmission_count = conf->lastMemberQueryCount - 1;
            }
        } else {
            break;
        }
    }
    
    /* 
     * FIXME: Send group&source specific query
     *      Ugly interface, need to redesign :( 
     */
    buildIgmpv3Query(Dp->InAdr.s_addr, gp->mcast.s_addr,
                         IGMP_MEMBERSHIP_QUERY,
                         //conf->lastMemberQueryInterval * IGMP_TIMER_SCALE,
                         conf->lastMemberQueryInterval,
                         gp->mcast.s_addr,
                         nsrcs,
                         sources,
                         0,
                         conf->queryInterval,
                         0);

    sendIgmpv3query(Dp->InAdr.s_addr, gp->mcast.s_addr, IP_HEADER_RAOPT_LEN + IGMP_V3_QUERY_MINLEN + nsrcs * sizeof(uint32_t));
    my_log(LOG_INFO, 0, "Send group source specific query.");

    /* Schedule group&source specific query */
    if(!(timer_inQueue(gp->query_timer))) {
        gp->query_timer = timer_setTimer(conf->lastMemberQueryInterval, scheduledRetransmissionQuery, gp);
    }
}


/**
*   Sends a group specific query until and schedule
*   the retransmission query.
*/
void sendGroupSpecificMemberQuery(void *argument) {
    struct  Config  *conf = getCommonConfig();

#if !defined(IGMPv3_PROXY)
    // Cast argument to correct type...
    GroupVifDesc   *gvDesc = (GroupVifDesc*) argument;

    if(gvDesc->started) {
        // If aging returns false, we don't do any further action...
        if(!lastMemberGroupAge(gvDesc->group)) {
            return;
        }
    } else {
        gvDesc->started = 1;
    }

    // Send a group specific membership query...
    sendIgmp(gvDesc->vifAddr, gvDesc->group, 
             IGMP_MEMBERSHIP_QUERY,
             conf->lastMemberQueryInterval * IGMP_TIMER_SCALE, 
             gvDesc->group, 0);

    my_log(LOG_DEBUG, 0, "Sent membership query from %s to %s. Delay: %d",
        inetFmt(gvDesc->vifAddr,s1), inetFmt(gvDesc->group,s2),
        conf->lastMemberQueryInterval);

    // Set timeout for next round...
    timer_setTimer(conf->lastMemberQueryInterval, sendGroupSpecificMemberQuery, gvDesc);
#else
    assert(argument != NULL);

    struct group *gp = (struct group *)argument;
    struct IfDesc *Dp = gp->interface;

    /*
     * Only the Querier should originate Query messages
     */
    if(!Dp->isQuerier)
        return;

    /* Lower the group timer with LMQT */
    if(gp->is_scheduled == 1 && gp->query_retransmission_count == 0) {
        if(timer_leftTimer(gp->timer) > LMQT) {
            timer_clearTimer(gp->timer);
            gp->timer = timer_setTimer(LMQT, groupTimerTimeout, gp);
        }

        gp->query_retransmission_count = conf->lastMemberQueryCount - 1;
    }

    /* Send group specific query */
    /* FIXME: Ugly, need to redesign the interface */
    buildIgmpv3Query(Dp->InAdr.s_addr, gp->mcast.s_addr,
                         IGMP_MEMBERSHIP_QUERY,
                         //conf->lastMemberQueryInterval * IGMP_TIMER_SCALE,
                         conf->lastMemberQueryInterval,
                         gp->mcast.s_addr,
                         0,
                         NULL,
                         0,
                         conf->queryInterval,
                         0);

    sendIgmpv3query(Dp->InAdr.s_addr, gp->mcast.s_addr, IP_HEADER_RAOPT_LEN + IGMP_V3_QUERY_MINLEN);
    my_log(LOG_INFO, 0, "Send group specific query.");

    /* Schedule retransmission group query */
    if(!(timer_inQueue(gp->query_timer))) {
        gp->query_timer = timer_setTimer(conf->lastMemberQueryInterval, scheduledRetransmissionQuery, gp);
    }
    
#endif
}


/**
*   Sends a general membership query on downstream VIFs
*/
void sendGeneralMembershipQuery(void *arg) {
    struct  Config  *conf = getCommonConfig();
    struct  IfDesc  *Dp = (struct IfDesc *)arg;
    


    if ( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) ) {
        if(Dp->state == IF_STATE_DOWNSTREAM && Dp->isQuerier) {
#if !defined(IGMPv3_PROXY)
            // Send the membership query...
            sendIgmp(Dp->InAdr.s_addr, allhosts_group, 
                         IGMP_MEMBERSHIP_QUERY,
                         conf->queryResponseInterval * IGMP_TIMER_SCALE, 0, 0);
#else
           /*
            * Only the Querier should originate Query messages
            */
            if(!Dp->isQuerier)
                return;
         
            buildIgmpv3Query(Dp->InAdr.s_addr, allhosts_group,
                         IGMP_MEMBERSHIP_QUERY,
                         conf->queryResponseInterval * IGMP_TIMER_SCALE,
                         0, /* Group address is 0.0.0.0 */
                         0, /* number of source is zero */
                         NULL,
                         0,
                         conf->queryInterval,
                         0);

            sendIgmpv3query(Dp->InAdr.s_addr, allhosts_group, IP_HEADER_RAOPT_LEN + IGMP_V3_QUERY_MINLEN);
                
            // FIXME: TODO
            // Install timer for next general query...
            if(conf->startupQueryCount>0) {
                // Use quick timer...
                Dp->queryTimer = timer_setTimer(conf->startupQueryInterval, sendGeneralMembershipQuery, Dp);
                // Decrease startup counter...
                conf->startupQueryCount--;
            } 
            else {
                // Use slow timer...
                Dp->queryTimer = timer_setTimer(conf->queryInterval, sendGeneralMembershipQuery, Dp);
            }
           
           my_log(LOG_INFO, 0, "Send general query.");
           interfaceGroupLog(Dp);
  
           // FIXME:
           //Dp->queryResponseTimer = timer_setTimer(conf->queryResponseInterval, ageActiveRoutes, NULL);
#if 0
           // Do aging for each client
           do_client_aging();
#endif
#endif
            my_log(LOG_DEBUG, 0,
			"Sent membership query from %s to %s. Delay: %d",
			inetFmt(Dp->InAdr.s_addr,s1),
			inetFmt(allhosts_group,s2),
			conf->queryResponseInterval);
            }
        }

    // Install timer for aging active routes.
    // TODO

#if !defined(IGMPv3_PROXY)
    timer_setTimer(conf->queryResponseInterval, ageActiveRoutes, NULL);

    // Install timer for next general query...
    if(conf->startupQueryCount>0) {
        // Use quick timer...
        timer_setTimer(conf->startupQueryInterval, sendGeneralMembershipQuery, NULL);
        // Decrease startup counter...
        conf->startupQueryCount--;
    } 
    else {
        // Use slow timer...
        timer_setTimer(conf->queryInterval, sendGeneralMembershipQuery, NULL);
    }
#endif
}

/**
 * The previous querier has expired. I will become the querier.
 **/
void otherQuerierTimerTimeout(void *arg) {
    
    assert(arg != NULL);

    struct  IfDesc  *Dp = (struct IfDesc *)arg;
    struct  Config  *conf = getCommonConfig();

    Dp->otherQuerierPresentTimer = INVAILD_TIMER;
    Dp->isQuerier = true;

    Dp->queryTimer = timer_setTimer(conf->queryInterval, sendGeneralMembershipQuery, Dp);    
}

/**
 * The old host timer has expired. I will change the group compatibility mode.
 **/
void oldHostTimerTimeout(void *arg) {
    assert(arg != NULL);
    
    struct group *gp = (struct group *)arg;

    if(gp->version == IGMP_V2)
        gp->version = IGMP_V3;
 
    if(gp->version == IGMP_V1) {
        if(timer_inQueue(gp->v2_host_timer))
            gp->version = IGMP_V2;
        else
            gp->version = IGMP_V3;
    }
}

/**
 * The group timer time out.
 **/
void groupTimerTimeout(void *arg)
{
    assert(arg != NULL);

    struct group *gp = (struct group *)arg;
    struct source *src = NULL;
    struct source *nxt = NULL;
    uint32_t groupAddr = gp->mcast.s_addr;
    int nnodes = 0;

    /* When mode is INCLUDE, do nothing */
    if(gp->fmode == IGMP_V3_FMODE_INCLUDE)
        return;

    if(gp->fmode == IGMP_V3_FMODE_EXCLUDE) {
        
        /* Clear the unactive sources */
        nnodes = gp->nsrcs;
        list_for_each_safe(&gp->sources, src, nxt, list) {
            if (nnodes-- > 0) {
                if(src && src->fstate == 0) {
                    sourceDestory(src);
                }
            } else {
               break;
            }
        }

        if(list_empty(&gp->sources)) {
            my_log(LOG_INFO, 0, "EXCLUDE source is NUL %s", __FUNCTION__);
            groupDestory(gp);
        } else {
            gp->fmode = IGMP_V3_FMODE_INCLUDE; /* Change the group mode */
        }
    }
    
    /* TODD: Update membership/routing table info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    memberDatabaseUpdate(groupAddr);
}

/**
 * The source timer time out.
 **/
void sourceTimerTimeout(void *arg)
{
    assert(arg != NULL);

    struct source *src = (struct source *)arg;
    struct group  *gp  = src->gp;
    uint32_t groupAddr = gp->mcast.s_addr;

    if(gp->fmode == IGMP_V3_FMODE_INCLUDE) {
        sourceDestory(src);

        if(list_empty(&gp->sources)) {
            my_log(LOG_INFO, 0, "INCLUDE source is NUL %s", __FUNCTION__);
            groupDestory(gp);
        }
    }

    if(gp->fmode == IGMP_V3_FMODE_EXCLUDE) {
        /* Move the source to unactive state */
        src->fstate = 0;
        timer_clearTimer(src->timer);
        src->timer  = INVAILD_TIMER;
    }

    /* TODD: Update membership/routing table info */
    my_log(LOG_INFO, 0, "Update database in %s", __FUNCTION__);
    memberDatabaseUpdate(groupAddr);
}

/**
 * Initialize the membership database
 */
void memberDatabaseInit(void)
{
    list_head_init(&member_database.members);
    member_database.nmems = 0;
}

/**
 * Look up the source in the member, if don't find it, return NULL  
 */
struct source_in_member *memberSourceLookup(struct member *mb, uint32_t srcAddr)
{
    assert(mb != NULL);
    struct source_in_member *src_in_mb = NULL;
    
    int nnodes = 0;
    int flag = 0;

    nnodes = mb->nsrcs;
    list_for_each(&mb->sources, src_in_mb, list) {
        if (nnodes-- > 0) {
            if (src_in_mb && src_in_mb->addr.s_addr == srcAddr) {
                flag = 1;
                break;
            }
        } else {
            break;
        }
    }

    if (flag)
        return src_in_mb;
    else
        return NULL;    
}

/**
 * Add source to member, if fail, return NULL
 */
struct source_in_member *memberSourceAdd(struct member *mb, uint32_t srcAddr)
{
    assert(mb != NULL);
    struct source_in_member *src_in_mb = NULL;

    src_in_mb = memberSourceLookup(mb, srcAddr);
    if (src_in_mb == NULL) {
    
        src_in_mb = malloc(sizeof(struct source_in_member));
        if(!src_in_mb) {
            my_log(LOG_ERR, 0, "create source in the member fail");
            return NULL; /* XXX: Maybe we need free some thing ? */
        }

        src_in_mb->addr.s_addr = srcAddr;

        list_add(&mb->sources, &src_in_mb->list);
        mb->nsrcs++;
    }

    return src_in_mb;
}

void memberSourceDel(struct member *mb, uint32_t srcAddr)
{
    assert(mb != NULL);
    if(!mb)
        return;

    int nnodes = 0;

    struct source_in_member *src_in_mb = NULL;
    struct source_in_member *nxt = NULL;
    
    nnodes = mb->nsrcs;
    list_for_each_safe(&mb->sources, src_in_mb, nxt, list) {
        if (nnodes-- > 0) { 
            if(src_in_mb && src_in_mb->addr.s_addr == srcAddr) {
                list_del(&src_in_mb->list);
                mb->nsrcs--;

                free(src_in_mb);
                
                break;
            }
        } else {
            break;
        }
    }
}

/**
 * Create a member, if fail, return NULL.
 **/
struct member *memberCreate(uint32_t mcastAddr)
{
    // Sanitycheck the group adress...
    if( ! IN_MULTICAST( ntohl(mcastAddr) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group. member create failed.",
            inetFmt(mcastAddr, s1));
        return 0;
    }

    //struct source *src = NULL;
    struct member *mb = NULL;
    mb = malloc(sizeof(struct member));
    if(!mb) {
        my_log(LOG_ERR, 0, "create member fail");
        return NULL;
    }

    mb->mcast.s_addr = mcastAddr;
    mb->fmode        = IGMP_V3_FMODE_INCLUDE; /* XXX: Default INCLUDE{NUL} */

    list_head_init(&mb->sources);
    mb->nsrcs        = 0;

/*
    list_for_each(&gp->sources, src, list) {
        if(gp->fmode == IGMP_V3_FMODE_INCLUDE) {
            memberSourceAdd(mb, src->addr_s_addr);
        } else if(gp->fmode == IGMP_V3_FMODE_EXCLUDE && src->fmode == 0) {
            memberSourceAdd(mb, src->addr_s_addr);
        }
    }
*/
    return mb;
}

void memberAdd(struct member *mb)
{
    assert(mb != NULL);
    
    list_add(&member_database.members, &mb->list);
    member_database.nmems++;
}

void memberDestory(struct member *mb)
{
    assert(mb != NULL);
    struct source_in_member *src_in_mb = NULL;
    struct source_in_member *nxt = NULL;
    int nnodes = 0;

    list_del(&mb->list);
    member_database.nmems--;

    nnodes = mb->nsrcs;
    list_for_each_safe(&mb->sources, src_in_mb, nxt, list) {
        if(nnodes-- > 0) {
            if(src_in_mb) {
                memberSourceDel(mb, src_in_mb->addr.s_addr);
            }
        } else {
            break;
        }
    }

    free(mb);
}

/**
 * Merge the group information to member.
 */ 
void memberDatabaseMerge(struct member *mb, struct group *gp)
{
    assert(mb != NULL);
    assert(gp != NULL);

    memberDatabaseLog();

    struct source *src = NULL;
    struct source_in_member *src_in_mb = NULL;
    struct source_in_member *nxt = NULL;
    int nnodes = 0;
    int nnodes_2nd = 0;
    int flag = 0;

    /* 
     * merge the member state from all interface
     *    RFC 3376 $3.2 
     *    RFC 4605 $4.1
     */ 

    /*
     * Database{mb}  Group{gp}     Action(mb) 
     * INCLUDE {A}   INCLUDE {B}   INCLUDE{A + B}
     */
    if(gp->fmode == IGMP_V3_FMODE_INCLUDE && mb->fmode == IGMP_V3_FMODE_INCLUDE) {
        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if (nnodes-- > 0) {
                nnodes_2nd = mb->nsrcs;
                flag = 0;
                list_for_each(&mb->sources, src_in_mb, list) {
                    if (nnodes_2nd-- > 0) {
                        if(src_in_mb && src->addr.s_addr == src_in_mb->addr.s_addr) {
                            flag = 1;
                            break;
                        }
                    } else {
                        flag = 0;
                        break;
                    }
                }
                
                /* Add the new source to member */
                if (!flag)
                    memberSourceAdd(mb, src->addr.s_addr);
            } else {
                break;
            }
        }
    }

    /*
     * Database{mb}  Group{gp}     Action(mb) 
     * INCLUDE {A}   EXCLUDE {B}   EXCLUDE{B - A}
     */
    if(gp->fmode == IGMP_V3_FMODE_EXCLUDE && mb->fmode == IGMP_V3_FMODE_INCLUDE) {
        mb->fmode = IGMP_V3_FMODE_EXCLUDE; /* Change mode, from INCLUDE -> EXCLUDE */
        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if ((nnodes-- > 0) && src && src->fstate == 0) {
                nnodes_2nd = mb->nsrcs;
                flag = 0;
                list_for_each_safe(&mb->sources, src_in_mb, nxt, list) {
                    if (nnodes_2nd-- > 0) {
                        if(src_in_mb && src->addr.s_addr == src_in_mb->addr.s_addr) {
                            memberSourceDel(mb, src_in_mb->addr.s_addr);
                            flag = 1;
                            break;
                        }
                    } else {
                        break;
                    }
                }
                      
                /* Add the new source to member */
                if (!flag)
                    memberSourceAdd(mb, src->addr.s_addr);
            } else {
                break;
            }
        }
    }

    /*
     * Database{mb}  Group{gp}     Action(mb) 
     * EXCLUDE {A}   INCLUDE {B}   EXCLUDE{A - B}
     */
    if(gp->fmode == IGMP_V3_FMODE_INCLUDE && mb->fmode == IGMP_V3_FMODE_EXCLUDE) {
        nnodes = gp->nsrcs;
        list_for_each(&gp->sources, src, list) {
            if(nnodes-- > 0) {
                nnodes_2nd = mb->nsrcs;
                list_for_each_safe(&mb->sources, src_in_mb, nxt, list) {
                    if (nnodes_2nd-- > 0) {
                        if(src_in_mb && src->addr.s_addr == src_in_mb->addr.s_addr) {
                            memberSourceDel(mb, src_in_mb->addr.s_addr);
                            break;
                        }
                    } else {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    /*
     * Database{mb}  Group{gp}     Action(mb) 
     * EXCLUDE {A}   EXCLUDE {B}   EXCLUDE{A * B}
     */
    if(gp->fmode == IGMP_V3_FMODE_EXCLUDE && mb->fmode == IGMP_V3_FMODE_EXCLUDE) {
        nnodes = mb->nsrcs;
        list_for_each_safe(&mb->sources, src_in_mb, nxt, list) {
            if (nnodes-- > 0) {
                nnodes_2nd = gp->nsrcs;
                flag = 0;
                list_for_each(&gp->sources, src, list) {
                    if (nnodes_2nd-- > 0) {
                        if(src && src->addr.s_addr == src_in_mb->addr.s_addr) {
                            flag = 1;
                            break;
                        }
                    } else {
                        break;
                    }
                }
              
                if(!flag)
                    memberSourceDel(mb, src_in_mb->addr.s_addr);
            } else {
                break;
            }
        }
    }

    memberDatabaseLog();
}

struct member *memberLookup(uint32_t mcastAddr)
{
    struct member *mb = NULL;
    int flag = 0;

    // Sanitycheck the group adress...
    if( ! IN_MULTICAST( ntohl(mcastAddr) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group. member look up failed.",
            inetFmt(mcastAddr, s1));
        return NULL;
    }

    if(!member_database.nmems)
        return NULL;

    int nnodes = member_database.nmems;

    list_for_each(&member_database.members, mb, list) {
        if (nnodes-- > 0) {
            if(mb && mb->mcast.s_addr == mcastAddr) {
                flag = 1;
                break;
            }
        } else {
            flag = 0;
            break;
        }
    }

    if (flag)
        return mb;
    else
        return NULL;
}

/**
 * Update members database
 */
void memberDatabaseUpdate(uint32_t mcastAddr)
{
    // Sanitycheck the group adress...
    if( ! IN_MULTICAST( ntohl(mcastAddr) )) {
        my_log(LOG_WARNING, 0, "The group address %s is not a valid Multicast group. member database update failed.",
            inetFmt(mcastAddr, s1));
        return;
    } else {
        my_log(LOG_WARNING, 0, "Update group %s to database", inetFmt(mcastAddr, s1));
    }

    struct member *mb = NULL;
    uint32_t       group = mcastAddr;
    struct group *merge_gp = NULL;
    struct IfDesc *upstrIf = NULL;
    uint32_t insertRouteFlag = 0;
    int flag = 0;
    
    // Get the upstream VIF...
    upstrIf = getIfByIx( upStreamVif );

    mb = memberLookup(group);
    if(!mb) {
        mb = memberCreate(group);
        if (mb)
            memberAdd(mb);

        /* XXX:
         *     1). join the group in the upstream ?
         *     2). add new pending routing entry 
         */
        insertRouteFlag = 1;
    } 

    /* Loop through all interface about this group and merge it to database */
    {
        unsigned Ix;
        struct IfDesc *Dp;

        for ( Ix = 0; (Dp = getIfByIx(Ix)); Ix++ ) {
            if ( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) && (Dp->state == IF_STATE_DOWNSTREAM) ) {
                merge_gp = interfaceGroupLookup(Dp, group);
                if(merge_gp) {
                    memberDatabaseMerge(mb, merge_gp);
                    flag = 1; /* Find this group in one interface */
                    
                    /* Insert routing entry, can't to decide the VIF until get Upcall message */
                    if((insertRouteFlag && findRoute(group) == NULL)) {
                        insertRoute(group, Dp->index); /* XXX: Create the route entry and send join message in upstream */
                        //insertRouteFlag = 0;
                    } 
                }    
            }
        }
    }

    //updateRoute(group);

    assert(mb != NULL);

    /* XXX: When group is INCLUDE{NUL} or no interface join this group, delete it */
    if((mb->fmode == IGMP_V3_FMODE_INCLUDE && !mb->nsrcs) || flag == 0) {
        deleteRoute(group); /* Send Leave message and prune the routing */

        memberDestory(mb);
    } else {
        /* XXX: Set source filtering in the upstream interface */
        setSourceFilter(getMcGroupSock(), mb);
 
        updateRoute(group);
    }   
}

/**
 * Initialize the scheduling query database
 */
/*
void queryDatabaseInit()
{
    list_head_init(&query_db.queries);
    query_db.nqueries = 0;
}
*/

/*
void queryEntryAdd(struct *gp)
{
    if(gp->is_scheduled == 1) {
        
        gp->is_scheduled = 0; // Clean the group-specific query scheduled

    } else {
        
    }
}
*/
void memberDatabaseLog()
{
    int nnodes = member_database.nmems;
    int nnodes_2nd = 0;
    
    struct member *mb = NULL;
    struct source_in_member *src_in_mb = NULL;

    my_log(LOG_INFO, 0, "\n-Member database--------------------------------------");       
    list_for_each(&member_database.members, mb, list) {
        if (nnodes-- > 0) {
            my_log(LOG_INFO, 0, "Group %s\tFilter Mode %s\tNum of Src %d",  inetFmt(mb->mcast.s_addr, s1), (mb->fmode ? "INCLUDE" : "EXCLUDE"), mb->nsrcs);
            nnodes_2nd = mb->nsrcs;
            list_for_each (&mb->sources, src_in_mb, list) {
                if (nnodes_2nd-- > 0) {
                    my_log(LOG_INFO, 0, "\t\t\t\t\t Source %s", inetFmt(src_in_mb->addr.s_addr, s1));
                } else {
                    break;
                }
            }
        } else {
            break;
        }
    }
    my_log(LOG_INFO, 0, "-------------------------------------------------------");       
}

void interfaceGroupLog(struct IfDesc *sourceVif)
{
    struct group *gp = NULL;
    int flag = 0;

    my_log(LOG_INFO, 0, "++++++++ Interface info %s.", __FUNCTION__); 

    assert(sourceVif != NULL);

    int nnodes = sourceVif->ngps;
    list_for_each(&sourceVif->groups, gp, list) {
        if (nnodes-- > 0) {
            my_log(LOG_INFO, 0, "group address %s, index %d", 
                inetFmt(gp->mcast.s_addr, s2), sourceVif->ngps - nnodes);
        } else {
            break;
        }
    } 
    my_log(LOG_INFO, 0, "++++++++ Interface info %s.", __FUNCTION__); 
}
