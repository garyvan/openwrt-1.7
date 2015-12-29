/***********************license start***************                              
* Copyright (c) 2003-2013  Cavium Inc. (support@cavium.com). All rights           
* reserved.                                                                       
*                                                                                 
*                                                                                 
* Redistribution and use in source and binary forms, with or without              
* modification, are permitted provided that the following conditions are          
* met:                                                                            
                                                                                  
*   * Redistributions of source code must retain the above copyright              
*     notice, this list of conditions and the following disclaimer.               
*                                                                                 
*   * Redistributions in binary form must reproduce the above                     
*     copyright notice, this list of conditions and the following                 
*     disclaimer in the documentation and/or other materials provided             
*     with the distribution.                                                      
*                                                                                 
*   * Neither the name of Cavium Inc. nor the names of                            
*     its contributors may be used to endorse or promote products                 
*     derived from this software without specific prior written                   
*     permission.                                                                 
                                                                                  
* This Software, including technical data, may be subject to U.S. export  control 
* laws, including the U.S. Export Administration Act and its  associated          
* regulations, and may be subject to export or import  regulations in other       
* countries.                                                                      
                                                                                  
* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"        
* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR       
* WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO   
* THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY REPRESENTATION OR  
* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF     
* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
***********************license end**************************************/         


/**
 * @file
 *
 * SE/SEUM:
 * Reference application to showcase HFA as XML file parser. 
 * The following lists the operational aspects of this
 * application.
 * - Multicore - NO(runs on single core)
 * - Type of API - Synchronous OO API
 * - Cluster resources - Managed by HFA API.
 * - Graph count - 1
 * - Graph to cluster map - one graph on all clusters
 * - Nature of ctx - Private to the core
 * - Clusters for load - all by default. Configurable using cmdline option
 * - Clusters for search - 0 by default. Configurable, but limited to 1 cluster
 * - Buffer Payload - XML File only
 * - PCAP - Not Supported
 * - Cross Packet Search - Enabled
 * - FSAVEBUF - Supported. Application checks ppoflags set by HFA HW, 
 *              if FSAVEBUF sets in ppoflags then the application provides
                back buffer of savelen + current buffer to the search otherwise 
                it will provide current chunk buffer to the search
 */
#include <cvm-hfa-graph.h>
#include <cvm-hfa-cluster.h>
#include <cvm-hfa-search.h>
#include <cvm-hfa.h>
#include <pcap.h>
#include <app-utils.h>

/* @cond APPINTERNAL */
typedef struct xml_match{
    int  soff;
    int  eoff;
    int  mno;
    struct xml_match *prev;
    struct xml_match *next;
}xml_match_t;

CVMX_SHARED options_t           options;
CVMX_SHARED hfa_dev_t           hfa_dev;
CVMX_SHARED hfa_graph_t         graph;

hfautils_payload_attr_t         pattr;
hfa_searchctx_t                 ctx;    
hfa_searchparams_t              param;    
hfa_size_t                      rsize=0;
void                            *graph_data = NULL;
int                             iovlen_0_n = 0; 
void                            *rptr = NULL;
hfa_searchctx_t                 *psctx = NULL;
int                             stage = -1;
hfa_iovec_t                     *input = NULL;
int                             savelen = 0, boffset = 0;
xml_match_t                     *start_node = NULL;
xml_match_t                     *last_node = NULL;

void matchcb(int, int, int, int, void *);
hfa_return_t  parse_xml_matches();

/* @endcond APPINTERNAL */
typedef enum {
    OPTIONS_INIT = 1,
    DEV_INIT = 2,
    GRAPH_INIT = 3,
    CTX_INIT  = 4,
    INPUT_INIT = 5,
    PKTBUF_INIT  
}error_stage_t;

/**
 * Cleanup allocated memory for match list 
 */
static inline void 
cleanup_matchlist() 
{
    xml_match_t     *matchnode = start_node;

    while(matchnode != NULL) {
        hfautils_memoryfree(matchnode, sizeof(xml_match_t), 
                                    (hfa_searchctx_t *)NULL);
        matchnode = matchnode->next;
    }
}
/** 
 * Application cleanup will be done by this routine 
 */
static inline void 
cleanup(int iovlen_0_n) 
{
    int     i = 0;

    switch(stage) {
        case PKTBUF_INIT:
            for(i = 0; i < iovlen_0_n; i++) {
                /* Cleanup allocated memory for payload buffer */
                hfautils_memoryfree(input[i].ptr, input[i].len, 
                                    (hfa_searchctx_t *)NULL);
            }
        case INPUT_INIT:
            hfautils_memoryfree(input,sizeof(hfa_iovec_t) * (iovlen_0_n+1), 
                                        (hfa_searchctx_t *)(psctx));
        case CTX_INIT:
            hfautils_memoryfree(rptr, rsize, (hfa_searchctx_t *)(psctx));
            hfa_dev_searchctx_cleanup (&hfa_dev, &ctx);
        case GRAPH_INIT:
            if(!HFA_GET_GRAPHATTR((&graph), memonly)){ 
                hfa_graph_cacheunload (&graph);
            }
            hfa_dev_graph_cleanup(&hfa_dev, &graph);
        case DEV_INIT:
            hfa_dev_cleanup (&hfa_dev);   
        case OPTIONS_INIT:
            hfautils_cleanup_payload_attributes(&pattr, &options);
            hfautils_memoryfree(graph_data, options.graphsize,
                                    (hfa_searchctx_t *) NULL);
        default:
            hfautils_reset_octeon();
            break;
    }
}
/**
 * Initialize search context 
 */ 
static inline hfa_return_t 
initialize_ctx(void)
{
    /*initialize search context object */
    if(HFA_SUCCESS != hfa_dev_searchctx_init (&hfa_dev, &ctx)){
        ERR("SearchCtx Init Failure\n");
        return HFA_FAILURE;
    }
    /*bind graph to the context */
    if(HFA_SUCCESS != hfa_searchctx_setgraph (&ctx, &graph)){
        ERR("Searchctx_setgraph Failure\n");
        return HFA_FAILURE;
    }
    /*set flags for search*/
    hfa_searchctx_setflags (&ctx, options.pfflags);

    psctx = &ctx; 
    if(NULL == (rptr = 
                hfautils_memoryalloc(rsize, 128, (hfa_searchctx_t *)(psctx)))){
        ERR("Rptr allocation failure\n");
        goto ctx_cleanup;
    }
    return HFA_SUCCESS;
ctx_cleanup:
    hfa_dev_searchctx_cleanup (&hfa_dev, &ctx);
    return HFA_FAILURE;
} 
/**
 * Load graph into HFA memory and cache
 */
static inline hfa_return_t 
graph_load(void) 
{
    /*initialize graph object*/
    if(HFA_SUCCESS != hfa_dev_graph_init (&hfa_dev, &graph)){
        ERR("hfa_dev_graph_init() failure\n");
        return HFA_FAILURE;
    }
    /* set cluster on which this graph will be loaded*/
    if(HFA_SUCCESS != hfa_graph_setcluster (&graph, options.graph_clmsk)){
        ERR("hfa_graph_setcluster() failure\n");
        return HFA_FAILURE;
    }
    /* load graph to HFA memory*/
    if(HFA_SUCCESS != hfautils_download_graph(&graph, graph_data, 
                options.graphsize, GRAPHCHUNK, 0)){
        ERR("hfautils_download_graph() failure\n");
        return HFA_FAILURE;
    }
    /* load graph to cache, if it is a cacheable graph */
    if(!HFA_GET_GRAPHATTR((&graph), memonly)){ 
        if( HFA_SUCCESS != hfa_graph_cacheload (&graph)){
            ERR("Graph Cacheload failure\n");
            hfa_dev_graph_cleanup(&hfa_dev, &graph);
            return HFA_FAILURE;
        }
    }
    /* Get savelen for cross packet matching */
    hfa_graph_getsavelen(&graph, &savelen);
    if(savelen <= 0)
        savelen = options.payloadsize;
    LOG("Graph download, Cache download completed\n");
    return HFA_SUCCESS;
}
/** 
 * Process command line options and read graph. 
 */
static inline hfa_return_t 
process_options (int argc, char **argv) 
{
    hfautils_options_init(&options);
    options.verbose=1;
    options.pfflags &= ~HFA_SEARCHCTX_FNOCROSS;
    if(HFA_SUCCESS != hfautils_parse_arguments(argc, argv, &options)){
        return (HFA_FAILURE);
    }
    if(options.pcap){
        ERR("PCAP file not supported\n");
        return HFA_FAILURE;
    }       
    /* Read graph */
    if(HFA_SUCCESS != hfautils_read_file(options.graph, 
                        &graph_data, options.graphsize)){
        ERR ("Error in reading graph\n");
        return (HFA_FAILURE);
    }
    memset(&pattr, 0, sizeof(hfautils_payload_attr_t));
    /* Initialize attributes for parsing the payload file */
    if(HFA_SUCCESS != hfautils_init_payload_attributes (&pattr, &options)){
        ERR ("Failure in hfautils_init_payload_attributes\n");
        goto gfree;
    }
    rsize=MAXRBUFSIZE;
    HFA_ALIGNED(rsize,128);
    
    return HFA_SUCCESS;
gfree:
    hfautils_memoryfree(graph_data, options.graphsize,
                                (hfa_searchctx_t *) NULL);
    return HFA_FAILURE;
}
int 
main (int argc, char **argv)
{ 
    uint32_t                    tot_iov_datalen = 0;
    hfa_ppoflags_t              ppoflags = 0;
    uint32_t                    reason = 0;
    uint64_t                    *pmatches = NULL;
    uint64_t                    nmatches=0;
    int                         i = 0;
    hfa_pdboff_t                pdboffset = 0;
    hfa_iovec_t                 *input_tmp = NULL;
    int64_t                     psize = 0;
    void                        *payload = NULL;
     
    cvmx_user_app_init ();
    hfautils_register_signalhandler();
    if (cvmx_is_init_core ()) {

        /* Process command line options, read graph */ 
        if(HFA_SUCCESS != process_options(argc, argv)) {
            ERR("failure in process_options\n");
            goto m_cleanup;
        }
        /*initialize HFA device and device driver*/
        if(HFA_SUCCESS != hfa_dev_init(&hfa_dev)){
            ERR("hfa_dev_init failed \n");
            stage = OPTIONS_INIT;
            goto m_cleanup;
        }
        /* Initialize graph object and load graph */
        if(HFA_SUCCESS != graph_load()) {
            ERR("Failure in graph_load\n");
            stage = DEV_INIT;
            goto m_cleanup;
        }
        /* Initialize search context */
        if(HFA_SUCCESS != initialize_ctx()) {
            ERR("Failure in initialize_ctx\n");
            stage = GRAPH_INIT;
            goto m_cleanup;
        }
        
        if (NULL == (input = hfautils_memoryalloc(sizeof(hfa_iovec_t), 8, 
                        (hfa_searchctx_t *)(psctx)))){
            ERR ("unable to alloc iovec entries for payload");
            stage = CTX_INIT;
            goto m_cleanup;
        }
        memset (&param, 0, sizeof (hfa_searchparams_t));
        param.clusterno = options.cluster;
        boffset=0;
        iovlen_0_n = 0;
        /* Parse through NORMAL payload and process search  */     
        while(!gzeof(pattr.gzf)) {
            /* Get a pcacket buffer from NORMAL payload file */
            if(HFA_SUCCESS != hfautils_parse_payload(&pattr, &options)){
                if(gzeof(pattr.gzf))
                    break;
                ERR("Failure in hfautils_parse_payload\n");
                stage = INPUT_INIT;
                goto m_cleanup;
            }
            psize = pattr.psize;
            payload = pattr.payload;
            /* This while loop is for RFULL case, if RFULL occures it will 
             * keep sending the data till all data consumed in a packet 
             * by HFA engine */
            while(psize > 0) {
                input[iovlen_0_n].ptr = payload;
                input[iovlen_0_n].len = psize;
                tot_iov_datalen += options.chunksize;
                iovlen_0_n++;
                /*set input parameters to search*/
                hfa_searchparam_set_inputiovec_0_n (&param, input, 
                                                   iovlen_0_n, 1);

                /*set output parameters to search */
                hfa_searchparam_set_output(&param, rptr, rsize);
                
                /*set matchcb to report matches */
                hfa_searchparam_set_matchcb(&param, matchcb, NULL);

                /* Perform search using search context and search parameters.
                 * This call will block till instruction completes in HFA
                 */
                if(HFA_SUCCESS != hfa_searchctx_search (&ctx, &param)){
                    ERR("hfa_searchctx_search() failure\n");
                    stage = PKTBUF_INIT;
                    goto m_cleanup;
                }
                /*Get the search reason from hardware*/
                hfa_searchparam_get_hwsearch_reason(&param, &reason);

                if (reason != HFA_REASON_DDONE &&
                        reason != HFA_REASON_RFULL){
                    ERR("GRAPH WALK FAILED, REASON CODE: 0x%x\n", reason);
                    stage = PKTBUF_INIT;
                    goto m_cleanup;
                }
                /*Get the pdboffset from hardware*/
                hfa_searchparam_get_hwsearch_pdboff (&param, &pdboffset);
                DBG("pdboffset = %lu\n", pdboffset);

                /* Post process the results from HFA and record found matches*/
                if(HFA_SUCCESS != 
                        hfa_searchctx_getmatches (&ctx, &param, &pmatches)){
                    ERR ("searchctx getmatches failure()\n");
                    stage = PKTBUF_INIT;
                    goto m_cleanup;
                }
                /*matches points to match buffer allocated by post processing*/
                hfautils_print_matches (&ctx, pmatches, &nmatches, boffset, 
                                         options.verbose);
                boffset += pdboffset;
                psize -= pdboffset;
                payload += pdboffset;
                /*Get ppoflags 
                 *If FSAVEBUF set in ppoflags then the application has to provide
                 *back buffer of savelen + current buffer to the search otherwise 
                 *it has to provide current chunk buffer to the serach*/ 
                hfa_searchparam_get_ppoflags (&param, &ppoflags);
                if(HFA_ISBITMSKCLR(ppoflags, HFA_PP_OFLAGS_FSAVEBUF)){
                    iovlen_0_n = 0;
                }
                else if (boffset < tot_iov_datalen-input[iovlen_0_n-1].len)
                {
                    /*
                     * HFA engine did not consume all the input data in this
                     * instruction.So erase the last iovec. It will be refilled
                     * in the next iteration of the loop with adjusted
                     * input payload(based pdboffset...which is accounted for
                     * above).
                     */
                    iovlen_0_n--;
                    /* Cleanup allocated memory for payload buffer */
                    hfautils_memoryfree(input[iovlen_0_n].ptr, 
                        input[iovlen_0_n].len, (hfa_searchctx_t *)NULL);
                    tot_iov_datalen -= options.chunksize;
                }
                else if ((tot_iov_datalen - input[iovlen_0_n-1].len) < savelen)
                {
                    /* Savelen is how much back buffer memory must be preserved 
                     * when using cross-packet matching. Allocates memory for 
                     * iovecs till back buffer + current buffer fit in 
                     * the iovecs 
                     */
                    if (NULL == (input_tmp = 
                        hfautils_memoryalloc(sizeof(hfa_iovec_t)*(iovlen_0_n+1),
                                         8, (hfa_searchctx_t *)(psctx)))){
                        ERR ("unable to alloc iovec entries for payload");
                        stage = PKTBUF_INIT;
                        goto m_cleanup;
                    }
                    for (i = iovlen_0_n-1; i >=0; i--) {
                        input_tmp[i].ptr = input[i].ptr; 
                        input_tmp[i].len = input[i].len; 
                    }
                    hfautils_memoryfree(input,sizeof(hfa_iovec_t)*iovlen_0_n, 
                                                    (hfa_searchctx_t *)(psctx));
                    input = input_tmp;
                }
                else 
                {
                    /* If allocated iovecs are enough to store back buffer + 
                     * current buffer then adjust the buffer ptrs */ 
                    iovlen_0_n--;
                    /* Cleanup allocated memory for payload buffer */
                    hfautils_memoryfree(input[0].ptr, input[0].len, 
                                            (hfa_searchctx_t *)NULL);
                    for(i = 0; i < iovlen_0_n; i++) {
                        input[i].ptr = input[i+1].ptr;
                        input[i].len = input[i+1].len;
                    }
                }
            }
        }
        stage = PKTBUF_INIT;
        parse_xml_matches();
m_cleanup:
        cleanup(iovlen_0_n);
    }
    return 0;
}

void 
matchcb(int patno, int mno, int soff, int eoff, void *arg)
{
    char            buf[128];
    xml_match_t     *matchnode = NULL;

    if (soff == CVM_HFA_INVAL)
        snprintf (buf, sizeof buf, "INV");
    else {
        soff += boffset;
        snprintf (buf, sizeof buf, "%d", soff);
    }
    eoff += boffset;
    
    /*Allocate node*/
    if(NULL == (matchnode = hfautils_memoryalloc(sizeof(xml_match_t), 8,
                    (hfa_searchctx_t *)NULL))){
        ERR("Failure in allocating search node\n");
        return;
    }
    memset(matchnode, 0, sizeof(xml_match_t));

    matchnode->soff = soff;
    matchnode->eoff = eoff;
    matchnode->mno = mno;
        
    if(start_node == NULL) {
        start_node = last_node = matchnode;
        matchnode->next = matchnode->prev = NULL;
    }
    else {
        last_node->next = matchnode;
        matchnode->prev = last_node;
        last_node = matchnode;
        matchnode->next = NULL;
    }
    DBG ("found pattern %d(%d) match at [%s..%d]\n", patno, mno, buf, eoff);
}
/** Swap two nodes */
void 
swap(xml_match_t *n1, xml_match_t *n2) {

    xml_match_t     temp;

    temp.soff = n2->soff;
    temp.eoff = n2->eoff;
    temp.mno = n2->mno;
    n2->soff = n1->soff;
    n2->eoff = n1->eoff;
    n2->mno =  n1->mno;
    n1->soff = temp.soff;
    n1->eoff = temp.eoff;
    n1->mno = temp.mno;
}

void 
quicksort_list(xml_match_t *left, xml_match_t *right)
{
    xml_match_t *start;
    xml_match_t *current; 

    /* If the left and right pointers are the same, then return */
    if (left == right) return;

    /* Set the Start and the Current item pointers */
    start = left;
    current = start->next;

    /* Loop forever (well until we get to the right) */
    while (1)
    {
        /* If the start item is less then the right */
        if (start->soff < current->soff)
        {
            swap(start, current);
        }   

        /* Check if we have reached the right end */
        if (current == right) break;

        /* Move to the next item in the list */
        current = current->next;
    }

    /* Swap the First and Current items */
    swap(left, current);

    /* Save this Current item */
    xml_match_t *oldcurrent = current;

    /* Check if we need to sort the left hand size of the Current point */
    current = current->prev;
    if (current != NULL)
    {
        if ((left->prev != current) && (current->next != left))
            quicksort_list(left, current);
    }

    /* Check if we need to sort the right hand size of the Current point */
    current = oldcurrent;
    current = current->next;
    if (current != NULL)
    {
        if ((current->prev != right) && (right->next != current))
            quicksort_list(current, right);
    }
}
/** Parse xml matches */
hfa_return_t 
parse_xml_matches() 
{
    xml_match_t             *matchnode = NULL;
    int                     soff, eoff, mno;
    int                     len, i, csoff;
    int                     slen, sidx, eidx;
    int                     printflag = 0;
    
    /* Perform quicksort based on start offset of each match */
    quicksort_list(start_node, last_node);
   
    /* Iterate through linked list and print matches 
     * based on mno of a match 
     * */ 
    matchnode = start_node; 
    while(matchnode != NULL) {
        soff = matchnode->soff;
        eoff = matchnode->eoff;
        mno = matchnode->mno;
        len = eoff-soff+1;
        printflag = 0;
        sidx = soff/options.chunksize;
        eidx = eoff/options.chunksize;
        csoff = soff - (sidx * options.chunksize);
        if(sidx == eidx) 
            slen = len;
        else {
            slen = options.chunksize-csoff;
        }
        if(mno != 0) {
            for(i = sidx; i <= eidx; i++) {
                if(hfautils_strnstr((char *)(input[i].ptr)+csoff, "<", slen)) {
                    printflag = 1;
                    break;
                }
                len -= slen;
                if(len < options.chunksize) 
                    slen = len; 
                else 
                    slen = options.chunksize;
                csoff = 0;
            }
            if(printflag) {
                matchnode = matchnode->next;
                continue;
            }
            len = eoff-soff+1;
            csoff = soff - (sidx * options.chunksize);
            if(sidx == eidx) 
                slen = len;
            else 
                slen = options.chunksize-csoff;

            printf("\n");
            if(mno == 1) 
                printf("\n");
            else 
                printf("\t");

            /* Print match string */ 
            for(i = sidx; i <= eidx; i++) {
                printf("%.*s", slen, (char *)input[i].ptr+csoff);
                len -= slen;
                if(len < options.chunksize) 
                    slen = len; 
                else 
                    slen = options.chunksize;
                csoff = 0;
            }
        }
        /* Move to next node */
        matchnode = matchnode->next;
    }
    printf("\n");
    /* Cleanup memory allocated for matchlist */
    cleanup_matchlist();

    return HFA_SUCCESS;
}
                                                                                                             
