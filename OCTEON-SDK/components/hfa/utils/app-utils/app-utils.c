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
 *  @file
 *  Common utility functions for applications
 */
#include <app-utils.h>
#include <pcap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define swap32(x)   \
(((x<<24)&0xff000000)|((x>>24)&0xff)|((x<<8)&0xff0000)|((x>>8)&0xff00))
#else
#define swap32(x)   (x)
#endif
#ifdef KERNEL
extern void gz_fsinit(void *nm_blk_addr, void *(*memfs_alloc_rtn)
                     (size_t, gfp_t), void (*memfs_free_rtn)(const void *));
#else 
extern void gz_fsinit(void *nm_blk_addr, void *(*memfs_alloc_rtn)
                     (size_t), void (*memfs_free_rtn)(const void *));
#endif

#ifndef __linux__
extern unsigned long long gz_get_size(gzFile file);
#endif
#ifdef KERNEL
#include <linux/interrupt.h>
#endif

CVMX_SHARED cvmx_fau_reg_64_t   faubase;

/**
 * Read file data from a gzip-stream(compressed or uncompressed).
 
 * @param   gzf     gzip file stream
 * @param   buf     buffer into which file data read is returned
 * @param   size    size of buffer
 *
 * @return  number of bytes read
 */          
hfa_size_t 
fd_read (gzFile gzf, void *buf, hfa_size_t size) 
{
    hfa_size_t totsize = 0, blocksize, items;
    
    while (!gzeof(gzf))
    {
        blocksize = (size - totsize) < BLK_SIZE ? (size - totsize) : BLK_SIZE;
        items = gzread(gzf, buf + totsize, blocksize);
        if (items != blocksize)
        {
            return items;
        }
        else if (blocksize == 0)
            break;
        else
            totsize += blocksize;
    }
    return totsize;
}

#ifdef KERNEL

void            (*tasklet_callbackptr)(unsigned long);
struct tasklet_struct  *task[MAX_CORES];
/**
 * Return size of uncompressed file.
 * 
 * @param   filename    name of file(compressed or uncompressed)  
 * @param   psize       *psize contains size of file
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */

hfa_return_t 
hfautils_file_size(char *filename, hfa_size_t *psize)
{
    struct file     *file;
    gzFile gzf = NULL;
    int size;
    static int fs = 0;
    mm_segment_t    old_fs; 
    loff_t          csize;

    if(fs == 0)
    {
        fs++;
        /* It should be vmalloc but due to the limitation of 
         * vmalloc in tasklets using kmalloc. */
        gz_fsinit(NULL,kmalloc,kfree);
    }
    if(filename && psize){

        *psize=0;

        old_fs = get_fs();
        set_fs(KERNEL_DS);

        file = filp_open(filename, O_RDONLY, 0);
        if (!IS_ERR(file)) {
            csize = vfs_llseek(file, 0, SEEK_END);
            vfs_llseek(file, 0, SEEK_SET);
        } else {
            set_fs(old_fs);
            ERR ("unable to open file %s \n", filename);
            return HFA_FAILURE;
        }
        if ((gzf = gzopen (filename, "rb")) == NULL) {
            filp_close(file, NULL);
            set_fs(old_fs);
            ERR ("unable to open file: %s\n", filename);
            return HFA_FAILURE;
        }
        if(!gzdirect(gzf))
        {
            vfs_llseek(file, csize - 4, SEEK_SET);
            vfs_read(file,(void *)&size,4,&file->f_pos);
            *psize = (hfa_size_t)swap32(size);
        }
        else
           *psize = csize;

        filp_close(file, NULL);
        gzclose(gzf);
        set_fs(old_fs);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Read payload data from a file to a buffer(compressed or uncompressed).
 *
 * @param   filename   file from which data to be read
 * @param   data       buffer into which data read will be returned
 * @param   size       size of data to be read 
 * @param   pos        file position 
 
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_read_payload(char *filename, void **data, hfa_size_t *pos, 
                                            task_attr_t *t_attr)
{
    struct file     *file = NULL;
    mm_segment_t    old_fs; 
    hfa_size_t      size = 0;
     
    if(!(filename && data && t_attr))
        return HFA_FAILURE;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    file = filp_open(filename, O_RDONLY, 0);
    if(IS_ERR(file)) {
        ERR ("unable to open file: %s\n", filename);
        goto restore_fs;
    }
    size = vfs_llseek(file, 0, SEEK_END);
    vfs_llseek(file, 0, SEEK_SET);
    *data = hfautils_vmmemoryalloc(size, (hfa_searchctx_t *)NULL);
    if (*data  == NULL) {
        ERR ("unable to allocate %lu bytes file %s \n", size, filename);
        goto fclose;
    }
    if(vfs_read(file, *data, size, (loff_t *)pos) != size) { 
        ERR ("unable to read file %s \n", filename);
        goto data_free;
    }
    t_attr->size = size; 
    t_attr->data = *data; 
    filp_close(file, NULL); 
    set_fs(old_fs);
    
    return HFA_SUCCESS;
data_free:
    hfautils_memoryfree(*data, size, (hfa_searchctx_t *)NULL);
fclose:
    filp_close(file, NULL); 
restore_fs: 
    set_fs(old_fs);

    return HFA_FAILURE;
}
/**
 * Read data from a file to a buffer(compressed or uncompressed).
 *
 * @param   filename   file from which data to be read
 * @param   data       buffer into which data read will be returned
 * @param   size       size of data to be read 
 * @param   pos        file position 
 * @param   isgraph    argument to know the file is a graph file or not 
 
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_read_file(char *filename, void **data, hfa_size_t size,
                                    hfa_size_t *pos, int isgraph)
{
    gzFile gzf = NULL;
    mm_segment_t    old_fs; 
    
    if(!(filename && data && pos && size))
        return HFA_FAILURE;

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    if ((gzf = gzopen (filename, "rb")) == NULL) {
        set_fs(old_fs);
        ERR ("unable to open file: %s\n", filename);
        return HFA_FAILURE;
    }
    if(isgraph) 
          *data = hfautils_vmmemoryalloc(size, (hfa_searchctx_t *)NULL);
    else 
          *data = hfautils_memoryalloc(size, 128, (hfa_searchctx_t *)NULL);
       
    if (*data  == NULL) {
        gzclose(gzf);
        set_fs(old_fs);
        ERR ("unable to allocate %lu bytes file %s \n", size, filename);
        return HFA_FAILURE;
    }
    if (fd_read (gzf, *data, size) != size) {
        if(isgraph)
            hfautils_vmmemoryfree(*data, size, (hfa_searchctx_t *)NULL);
        else 
            hfautils_memoryfree(*data, size, (hfa_searchctx_t *)NULL);
        gzclose(gzf);
        set_fs(old_fs);
        ERR ("unable to read file %s \n", filename);
        return HFA_FAILURE;
    }
    *pos = gztell(gzf);
    gzclose(gzf);
    set_fs(old_fs);
    return HFA_SUCCESS;
}
/**
 * Validate chunk size given through command line.
 *
 * @param   chunksize     pointer to chunk size 
 * @param   payloadsize   size of payload file
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_validate_chunksize(uint32_t *chunksize,uint32_t payloadsize)
{
    if(payloadsize < *chunksize){
        *chunksize = payloadsize;
    }
    if(!(*chunksize)){
        ERR("chunksize is zero\n");
        return HFA_FAILURE;
    }
    if(*chunksize > HFA_SEARCH_MAX_GM_LEN){
        *chunksize = HFA_SEARCH_MAX_GM_LEN;
    }
    return HFA_SUCCESS;
}  
#else  /*Endof #ifdef KERNEL, Start of #ifndef KERNEL*/
/**
 * Return size of a file(compressed or uncompressed).
 * 
 * @param   filename   name of file  
 * @param   pbufsize   *pbufsize contains size of file
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfautils_file_size(char *filename, hfa_size_t *pbufsize)
{
#ifdef __linux__
    gzFile gzf = NULL;hfa_size_t csize = 0;
    int size = 0;
    FILE *fd = NULL;
    
    if ((fd = fopen (filename, "rb")) == NULL) {
        ERR ("unable to open file: %s\n", filename);
        return HFA_FAILURE;
    }
    fseek (fd, 0, SEEK_END);
    csize = ftell(fd);

    if ((gzf = gzopen (filename, "rb")) == NULL) {
        ERR ("unable to open file: %s\n", filename);
        return HFA_FAILURE;
    }
    if(!gzdirect(gzf))
    {
        fseek(fd, csize - 4, SEEK_SET);
        fread(&size,4,1,fd);
        *pbufsize = (hfa_size_t)swap32(size);
    }
    else
       *pbufsize = csize;
    fclose(fd);
    gzclose(gzf);
    return HFA_SUCCESS;
#else 
    gzFile gzf = NULL;
    if ((gzf = gzopen (filename, "rb")) == NULL) {
        ERR ("unable to open file: %s\n", filename);
        return HFA_FAILURE;
    }

    *pbufsize = (hfa_size_t)gz_get_size(gzf);
    gzclose(gzf);
    return HFA_SUCCESS;
#endif /* ifdef __linux__ */  
}
/**
 * Read data from a file to a buffer(compressed or uncompressed).
 *
 * @param   filename   file from which data to be read
 * @param   ppbuf      buffer into which data read will be returned
 * @param   bufsize    size of data to be read 
 * 
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfautils_read_file (char *filename, void **ppbuf, hfa_size_t bufsize)
{
    gzFile gzf = NULL;
    hfa_size_t  size = 0;
    
    if ((gzf = gzopen (filename, "rb")) == NULL) {
        ERR ("unable to open file: %s\n", filename);
       return -1;
    }
    if ((*ppbuf = 
        hfautils_memoryalloc(bufsize, 128, (hfa_searchctx_t *)NULL))== NULL) {
        ERR ("unable to allocate temp buffer (%lu) for file:%s\n",
                                                bufsize, filename);
        goto rf_free_close;
    }
    if ((size = fd_read (gzf, *ppbuf, bufsize)) != bufsize) {
        ERR ("unable to read file %s\n", filename);
        goto rf_free_buf;
    }
    gzclose(gzf);
    dprintf("Filename %s, Bufptr %p, Sz %lu\n",filename, *ppbuf, bufsize);
    return(0);

rf_free_buf:
    hfa_bootmem_free(*ppbuf, bufsize);
rf_free_close:
    gzclose(gzf);
    return(-1);
}
/**
 * Signal handler to ignore CTRL-C.
 *
 * @param   sig  signal
 */
void hfa_sigint_handler(int sig) {
    
    if (cvmx_is_init_core ()) {
        printf("\nIgnoring CTRL-C");
    }
}
/**
 * Register signal handler for SIGINT(CTRL-C).
 */
void hfautils_register_signalhandler()
{
#ifdef __linux__
    signal(SIGINT, hfa_sigint_handler);
#endif
}
/**
 *  Perform a soft reset of Octeon  
 */
void hfautils_reset_octeon()
{
#ifndef __linux__
    cvmx_reset_octeon(); 
#endif
}
/** This function locates the first occurrence of the null-terminated
 *  string s2 in the string s1, where not more than len characters are 
 *  searched.
 */
char *hfautils_strnstr(const char *s1, const char *s2, uint64_t len)
{   
    uint64_t l2;

    l2 = strlen(s2);
    if (!l2)
        return (char *)s1;
    while (len >= l2) {
        len--; 
        if (!memcmp(s1, s2, l2))
            return (char *)s1;
        s1++;
    }       
    return NULL;
}                
/**
 * Initialize command line arguments.
 *
 * @param  poptions  pointer to structure of options  
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_options_init (options_t *poptions)
{
    if(poptions) {
        poptions->verbose=0;
        strncpy(poptions->graph, "graph", strlen("graph"));
        strncpy(poptions->payload, "payload", strlen("payload"));
        poptions->graphsize = 0;
        poptions->payloadsize = 0;
        poptions->chunksize = 65535;
        poptions->cluster = 0;
        poptions->israndom = 0;
        poptions->graph_clmsk = hfa_get_max_clmsk();
        poptions->nsearchctx = 0;
        poptions->nsearch = 0;
        poptions->nflows = 0;
        poptions->npkts = 0;
        poptions->pfflags = HFA_SEARCHCTX_FDEFAULTFLAGS;
        poptions->pcap = 0;
        poptions->networkpayload=0;
        strncpy(poptions->fs, "files", strlen("files"));
        poptions->ngraphs=0;

        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/* no namedblock support in simulator */
#ifndef HFA_SIM
/**
 * initialize the tar for gzip.
 *  
 * @param   fs  tar file
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */

static inline hfa_return_t 
hfautils_fsinit (char *fs)
{
  const cvmx_bootmem_named_block_desc_t *nb;
  nb = cvmx_bootmem_find_named_block(fs);
  if (!nb)
  {
    ERR("unable to find the named block %s\n",fs);
    return HFA_FAILURE;
  }
  if(!nb->base_addr)
  {
    ERR("base_addr of named block is NULL\n");
    return HFA_FAILURE;
  }
  gz_fsinit(cvmx_phys_to_ptr(nb->base_addr),malloc,(void(*)(const void *))free);
  return HFA_SUCCESS;
}
#endif
/**
 * Parse command line arguments.
 *
 * @param   argc      argc from the application
 * @param   argv      argv from the application
 * @param   poptions  pointer to structure of options
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */ 
hfa_return_t
hfautils_parse_arguments(int argc, char **argv, options_t *poptions)
{
    char choice;
    int opt;
    int matchacross, singlematch;
     
    struct option optlist[] = {
                                  { "graph", 1, NULL, 0 },
                                  { "payload", 1, NULL, 1 },
                                  /* option 2 */
                                  /* option 3 */
                                  { "chunksize", 1, NULL, 4},
                                  { "cluster", 1, NULL, 5},
                                  { "nctx", 1, NULL, 6},
                                  { "clmsk", 1, NULL, 7},
                                  { "matchacross", 1, NULL, 8},
                                  { "singlematch", 1, NULL, 9},
                                  { "pcap", 1, NULL, 10},
                                  { "network", 1, NULL, 11},
                                  { "nflows", 1, NULL, 12},
                                  { "npkts", 1, NULL, 13},
                                  { "verbose", 1, NULL, 14},
                                  { "fs", 1, NULL, 15},
                                  { "ngraphs", 1, NULL, 16},
                                  { NULL, 0, NULL, 0 }
                              };
    while (1) {
        choice = getopt_long_only (argc, (char **) argv, "", optlist,
                &opt);
        if (choice == -1)
            break;
        if (choice == '?')
            ERR ("unknown option\n");
        switch (choice) {
        case 0:
            if(strlen(optarg) >= MAX_NAME_LENGTH) {
               ERR("Graph name length exceeding limit %d\n", MAX_NAME_LENGTH); 
               return HFA_FAILURE;
            }
            strncpy(poptions->graph, optarg, strlen(optarg));
            poptions->graph[strlen(optarg)] = '\0';
            break;
        case 1:
            if(strlen(optarg) >= MAX_NAME_LENGTH) {
               ERR("Payload name length exceeding limit %d\n", MAX_NAME_LENGTH); 
               return HFA_FAILURE;
            }
            strncpy(poptions->payload, optarg, strlen(optarg));
            poptions->payload[strlen(optarg)] = '\0';
            break;
        case 2:
            poptions->graphsize = strtoul (optarg, NULL, 0);
            break;
        case 3:
            poptions->payloadsize = strtoul (optarg, NULL, 0);
            break;
        case 4:
            poptions->chunksize = strtoul (optarg, NULL, 0);
            break;
        case 5:
            poptions->cluster = atoi (optarg);
            break;
        case 6:
            if(poptions->nsearchctx)
                poptions->nsearchctx = strtoul (optarg, NULL, 0);
            break;
        case 7:
            poptions->graph_clmsk= atoi(optarg);
            break;
        case 8:
            matchacross = strtoul (optarg, NULL, 0);
            if(matchacross)
                poptions->pfflags &= ~HFA_SEARCHCTX_FNOCROSS;
            else 
                poptions->pfflags |= HFA_SEARCHCTX_FNOCROSS;
            break;
        case 9:
            singlematch = strtoul (optarg, NULL, 0);
            if(singlematch)
                poptions->pfflags |= HFA_SEARCHCTX_FSINGLEMATCH;
            else
                poptions->pfflags &= ~HFA_SEARCHCTX_FSINGLEMATCH;
            break;
        case 10:
            poptions->pcap = strtoul (optarg, NULL, 0);
            break;
        case 11:
            poptions->networkpayload= strtoul (optarg, NULL, 0);
            break;
        case 12:
            if(poptions->nflows)
                poptions->nflows = strtoul (optarg, NULL, 0);
            break;
        case 13:
            if(poptions->npkts)
                poptions->npkts = strtoul (optarg, NULL, 0);
        break;
        case 14:
            poptions->verbose= strtoul (optarg, NULL, 0);
        break;
        case 15:
            if(strlen(optarg) >= MAX_NAME_LENGTH) {
               ERR("fs name length exceeding limit %d\n", MAX_NAME_LENGTH); 
               return HFA_FAILURE;
            }
            strncpy(poptions->fs, optarg, strlen(optarg));
            poptions->fs[strlen(optarg)] = '\0';
            break;
        case 16:
            poptions->ngraphs = strtoul (optarg, NULL, 0);
            break;
        default:
            return (HFA_FAILURE);
        }
    }
    /*Validate Input Arguments*/
    
    /* If poptions->cluster = -1(HFA_ANY_CLUSTER_SEARCH - HW Load Balancing) 
     * then api will provide clmsk for search instruction(HW will choose anyone 
     * available cluster based on load in the clmsk).
     */
    if(poptions->cluster < (-1) || (poptions->cluster >= hfa_get_max_clusters())){
        ERR("Invalid cluster number provided: %d\n", poptions->cluster);
        return (HFA_FAILURE);
    }
    if(poptions->graph_clmsk > hfa_get_max_clmsk()){
        ERR("Invalid Graph Cluster Mask: 0x%x\n", poptions->graph_clmsk);
        return (HFA_FAILURE);
    }
    if(poptions->pcap && poptions->networkpayload){
        LOG("Warning: Network option disabled when PCAP option provided\n");
        poptions->networkpayload =0;
    }
#ifndef __linux__
    /* initialize the tar for gzip */
    if(HFA_SUCCESS != hfautils_fsinit(poptions->fs)){
        ERR("unable to find the tar file(graph + payload)\n");
        return HFA_FAILURE;
    }
#else
    /* initialize the memory allocation functions for gzip */
    gz_fsinit(NULL,malloc,(void(*)(const void *))free);
#endif
    if(!poptions->ngraphs)
    {
        DBG("Getting graph file: \"%s\" size: ", poptions->graph);
        if(HFA_SUCCESS != hfautils_file_size(poptions->graph,
                                         &(poptions->graphsize))){
            ERR("unable to extract graph size\n");
            return HFA_FAILURE;
        }
        dprintf("0x%lx\n", poptions->graphsize);
    }
    if(!poptions->networkpayload) {
        DBG("Getting payload file: \"%s\" size: ", poptions->payload);
        if(HFA_SUCCESS != hfautils_file_size(poptions->payload,
                                             &(poptions->payloadsize))){
            ERR("unable to extract payload size\n");
            return HFA_FAILURE;
        }
        dprintf("0x%lx\n", poptions->payloadsize);

        if(poptions->chunksize > poptions->payloadsize){
            poptions->chunksize = poptions->payloadsize;
        }
         if(!poptions->chunksize){
            ERR("chunksize is zero\n");
            return HFA_FAILURE;
        }
        if(poptions->chunksize > HFA_SEARCH_MAX_GM_LEN){
            poptions->chunksize = HFA_SEARCH_MAX_GM_LEN;
        }
    }
    /*Print Options*/
    hfa_log("\n");
    LOG("%-25s: %-10s\n", "Graph", poptions->graph);
    LOG("%-25s: %-10s\n", "Payload", poptions->payload);
    LOG("%-25s: %-10lu\n", "Graphsize", poptions->graphsize);
    LOG("%-25s: %-10lu\n", "Payloadsize", poptions->payloadsize);
    LOG("%-25s: %-10lu\n", "Chunksize", poptions->chunksize);
    if((hfa_get_max_clusters() -1) && (poptions->israndom)){
        LOG("%-25s: %s\n", "Cluster", "RoundRobin");
    } else {
        LOG("%-25s: %d%s\n", "Cluster", poptions->cluster,
            (poptions->cluster==-1)?"(HWLoadBalancing)":"");
    }
    LOG("%-25s: 0x%-10x\n", "Graph_ClMsk", poptions->graph_clmsk);
    if(poptions->nsearchctx){
            LOG("%-25s: %-10lu\n", "No. of SearchCtx", poptions->nsearchctx);
    } 
    if(poptions->nflows){
            LOG("%-25s: %-10lu\n", "No. of Flows", poptions->nflows);
    }
    if((poptions->npkts) && !(poptions->networkpayload)){
        LOG("%-25s: %-10lu\n", "No. of Local Pkts", poptions->npkts);
    }
    LOG("%-25s: %-10s\n", "CrossPktMatch Search", 
           (HFA_ISBITMSKSET(poptions->pfflags, HFA_SEARCHCTX_FNOCROSS)? 
           "Disable": "Enable"));
    LOG("%-25s: %-10s\n", "Singlematch Search", 
       (HFA_ISBITMSKSET(poptions->pfflags, HFA_SEARCHCTX_FSINGLEMATCH)? 
       "Enable": "Disable"));
    if(poptions->networkpayload){
        LOG("%-25s: %-10s\n", "Payload Src", "Network");
    } else {
        if(poptions->pcap){
            LOG("%-25s: %-10s\n", "Payload Src", "PCAP Payload file");
        } else {
            LOG("%-25s: %-10s\n", "Payload Src", "Payload file");
        }
    }
    hfa_log("\n");

    return (HFA_SUCCESS);
}
#endif /*End of  #ifdef KERNEL*/
/**
 * Initialize the attributes needed for parsing the payload file.
 *
 * @param   pattr           pointer to payload attributes
 * @param   poptions        pointer to structure of options
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_init_payload_attributes(hfautils_payload_attr_t *pattr, 
                                 options_t *poptions)
{
    void            *phdr = NULL;
    int             hdrsize = sizeof(pcap_file_header_t);
#ifdef KERNEL
    char            absolutePath[321];
#endif
     
    if(!(poptions->payload))
        return HFA_FAILURE;

#ifdef KERNEL
    pattr->old_fs = get_fs();
    set_fs(KERNEL_DS);
    
    if(in_softirq()) {
        /* If it is a tasklet, pass pointer to payload */
        if ((pattr->gzf = gzopen (pattr->path, "rb")) == NULL) {
            ERR ("unable to open file: %s\n", poptions->payload);
            goto restore_fs;
        }
    }
    else {
        sprintf(absolutePath, "%s/%s", pattr->path, poptions->payload);
        /* Open given payload file */
        if ((pattr->gzf = gzopen (absolutePath, "rb")) == NULL) {
            ERR ("unable to open file: %s\n", poptions->payload);
            goto restore_fs;
        }
    }
#else 
    if ((pattr->gzf = gzopen (poptions->payload, "rb")) == NULL) {
        ERR ("unable to open file: %s\n", poptions->payload);
        goto restore_fs;
    }
#endif
    if(poptions->pcap) {
        phdr = hfautils_memoryalloc(hdrsize, 8, (hfa_searchctx_t *)NULL);
        if (phdr == NULL) {
            ERR ("unable to allocate %d bytes for phdr \n", hdrsize);
            goto fd_close;
        }
        /* Read pcap header from PCAP file for initialization */
        if (fd_read (pattr->gzf, phdr, hdrsize) != hdrsize) {
            ERR ("unable to read file %s \n", poptions->payload);
            goto phdr_free;
        }
        /* Parse pcap header and gives snaplen if it is a PCAP file */
        if(HFA_SUCCESS != (pcap_file_init (phdr, pattr))){
            ERR ("pcap file init error\n");
            goto phdr_free;
        }
    }
    return HFA_SUCCESS;
phdr_free:
    hfautils_memoryfree(phdr, hdrsize, (hfa_searchctx_t *)NULL);
fd_close:
    gzclose(pattr->gzf);
restore_fs:
#ifdef KERNEL
    set_fs(pattr->old_fs);
#endif
    return HFA_FAILURE;
}
/**
 * This routine is counter part of hfautils_init_payload_attributes().
 *
 * @param   pattr           pointer to payload attributes
 * @param   poptions        Pointer to option data structure
 */
void 
hfautils_cleanup_payload_attributes(hfautils_payload_attr_t *pattr, 
                                              options_t *poptions)
{
    if(poptions->pcap) {
        if(pattr->phdr) {
            hfautils_memoryfree(pattr->phdr, sizeof(pcap_file_header_t), 
                                       (hfa_searchctx_t *)NULL);
        }
    }
    if(pattr->gzf)
        gzclose(pattr->gzf);
#ifdef KERNEL
    set_fs(pattr->old_fs);
#endif
}
/**
 * This routine reads data of chunksize/a packet from given payload(Normal/PCAP)
 * file and returns data buffer.
 *
 * @param   pattr           pointer to payload attributes
 * @param   poptions        pointer to cmd line options
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_parse_payload(hfautils_payload_attr_t *pattr, 
                       options_t *poptions)
{
    void        *data = NULL;
    int         size = 0, unread_data_len = 0; 
    uint32_t    buf;

    pattr->payload = NULL;
    pattr->psize = 0;
    if(poptions->pcap) {
        /*Parse pcap file for actual payload in a packet*/
        if(HFA_SUCCESS != pcap_parse_file(pattr)) {
            LOG("Failure in pcap_parse_file\n");
            return HFA_FAILURE;
        }
        if(pattr->psize == 0)
            return HFA_FAILURE;
        data = hfautils_memoryalloc(pattr->psize, 128, (hfa_searchctx_t *)NULL);
        if (data == NULL) {
            ERR ("unable to allocate %u bytes for packet\n", pattr->psize);
            return HFA_FAILURE;
        }
        /* Read actual payload in a packet to a buffer from PCAP file */
        if (fd_read (pattr->gzf, data, pattr->psize) != pattr->psize) {
            ERR ("unable to read payload file \n");
            hfautils_memoryfree(data, pattr->psize, (hfa_searchctx_t *)NULL);
            return HFA_FAILURE;
        }
        if(pattr->remain)
            gzseek(pattr->gzf, pattr->remain, SEEK_CUR);
        DBG("Read size = %lu\n", gztell(pattr->gzf));
    }else {
        unread_data_len = poptions->payloadsize - gztell(pattr->gzf);
        if(!unread_data_len) {    
            fd_read(pattr->gzf, &buf, 2);
            return HFA_FAILURE;
        }
        size = (unread_data_len < poptions->chunksize)? unread_data_len: 
                                                    poptions->chunksize;
        pattr->psize = size;
        data = hfautils_memoryalloc(size, 128, (hfa_searchctx_t *)NULL);
        if (data == NULL) {
            ERR ("unable to allocate %d bytes for payload\n", size);
            return HFA_FAILURE;
        }
        /* Read data of given size to a buffer from Payload(Normal) file */
        if (fd_read (pattr->gzf, data, size) != size) {
            ERR ("unable to read payload file\n");
            hfautils_memoryfree(data, size, (hfa_searchctx_t *)NULL);
            return HFA_FAILURE;
        }
    }
    /* Returns data buffer */
    pattr->payload = data;
    return HFA_SUCCESS;
}
/* no named block support in simulator */
#ifndef HFA_SIM
/** 
 * Return size of named block.
 *
 * @param   namedblock  pointer to named block
 * @param   psize       size of namedblock
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_getnb_size (char *namedblock, hfa_size_t *psize)
{
    const cvmx_bootmem_named_block_desc_t *nb = NULL;
    if(namedblock){
        nb = hfa_bootmem_find_named_block(namedblock);
        if(nb){
            *psize=nb->size;
            return (HFA_SUCCESS);
        }
    } 
    return (HFA_FAILURE);
}
/**
 * Return base address of named block.
 *
 * @param  namedblock  pointer to named block
 * @param  ppbuf       pointer to base address of named block
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfautils_read_nb(char *namedblock, void **ppbuf)
{

    const cvmx_bootmem_named_block_desc_t *nb = NULL;
    nb = hfa_bootmem_find_named_block(namedblock);
    if(nb){
        *ppbuf = cvmx_phys_to_ptr(nb->base_addr);
        if(*ppbuf){
            return (HFA_SUCCESS);
        }
    } else {
        ERR("Failure in finding \"%s\" named block\n", namedblock);
    }
    return(HFA_FAILURE);
}
#endif
/**
 * Parse graph into chunks and load graph to HFA memory.
 *
 * @param   pgraph    pointer to graph on which ctx will work 
 * @param   gbuf      pointer to graph buffer
 * @param   gsize     size of graph
 * @param   chunk     chunksize 
 * @param   isasync   option to use async api's or sync api's 
 * 
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_download_graph (hfa_graph_t *pgraph, void *gbuf, hfa_size_t gsize,
                         int chunk, hfa_bool_t isasync)
{
    hfa_size_t  pos=0, chunksize=GRAPHCHUNK, cs=0;
    hfa_size_t  gs = gsize;
    uint32_t    status=0; 

    if(chunk <= 0){
        ERR("wrong chunk length : %d\n", chunk);
        return HFA_FAILURE;
    }
    if(chunk > 0 && chunk < chunksize){
        chunksize = chunk;
    }
    DBG("pgraph: %p, gbuf: %p, gsize: %lu, chunk: %d, async: %d\n",
             pgraph, gbuf, gs, chunksize, isasync);
    
    if(pgraph && gbuf && gs){
        do {
            cs= (gs > chunksize) ? chunksize: gs;

            if(isasync){
                if(HFA_SUCCESS != 
                       hfa_graph_memload_data_async(pgraph, gbuf+pos, cs)){
                    ERR("hfa_graph_memload_data_async error\n");
                    return HFA_FAILURE;
                }
                do {
                    if(HFA_SUCCESS != hfa_graph_getstatus(pgraph, &status)){
                        ERR("hfa_graph_getstatus error\n");
                        return HFA_FAILURE;
                    }
                }while(CVM_HFA_EAGAIN == status);
            } else {
              if(HFA_SUCCESS != 
                    hfa_graph_memload_data(pgraph, gbuf+pos, cs)){
                  ERR("hfa_graph_memload_data error\n");
                  return HFA_FAILURE;
                }
            }
            gs -= cs;
            pos += cs;
        }while(gs >0);
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Initialize performance counters.
 *
 * @param   pstats   pointer to structure of performance statistics
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_init_perf_cntrs(hfautils_fau_perfcntrs_t *pstats)
{
    if(pstats){
        faubase = CVMX_FAU_REG_AVAIL_BASE;
        /**In packets*/
        pstats->in = faubase;
        faubase += 8;
        /**Out  packets*/
        pstats->out = faubase;
        faubase += 8;
        pstats->pend_wqe = faubase;
        faubase += 8;
        pstats->adsuccess = faubase;
        faubase += 8;
        pstats->adretry = faubase;
        faubase += 8;
        pstats->dropped = faubase;
        faubase += 8;
        pstats->sdsuccess = faubase;
        faubase += 8;
        pstats->pdsuccess = faubase;
        faubase += 8;
        pstats->adfail = faubase;
        faubase += 8;
        pstats->sdfail = faubase;
        faubase += 8;
        pstats->pdfail = faubase;
        faubase += 8;
        pstats->pdretry = faubase;
        faubase += 8;
        pstats->sdretry = faubase;
        faubase += 8;
        pstats->nmatches = faubase;
        faubase += 8;
        pstats->tot_bytes = faubase;
        faubase += 8;
        return HFA_SUCCESS;
    }
    return HFA_FAILURE;
}
/**
 * Print pattern matches via match buffer and cleanup all matches.
 *
 * @param  psctx      pointer to search context
 * @param  pmatches   pointer to match buffer
 * @param  nmatches   number of matches 
 * @param  boffset    offset of payload
 * @param  verbose    verbose option to print more data
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_print_matches(hfa_searchctx_t *psctx, uint64_t *pmatches, 
                 hfa_size_t *nmatches, int boffset, int verbose)
{
    char            buf[128];
    int             i, j, soff, eoff, len;
    uint64_t        *ptr;
    hfa_meta_t      meta;
    hfa_match_t     match;
    hfa_cap_t       cap;
    hfa_return_t    retval = HFA_SUCCESS;

    if ((uint64_t *)pmatches != NULL) {
        ptr = (uint64_t *)pmatches;
        len = 0;
        meta.u64 =  hfa_match_get(psctx, &ptr, &len);
        if (meta.s.allocerr){
            ERR ("not enough memory to report all matches\n");
            retval = HFA_FAILURE;
        } else {
            for (i = 0; i < meta.s.nmatch; ++i) {
                match.u64 = hfa_match_get(psctx, &ptr, &len);
                for (j = 0; j < match.s.ncap; ++j) {
                    cap.u64 = hfa_match_get(psctx, &ptr, &len);
                    if (cap.s.soff == CVM_HFA_INVAL)
                        snprintf (buf, sizeof buf, "N/A");
                    else {
                        soff=boffset+cap.s.soff;
                        snprintf (buf, sizeof buf, "%d", soff);
                    }
                    eoff = boffset + cap.s.eoff;
                    if(verbose){
                     LOG ("pattern %d(%d) match "
                          "at [%s..%d]\n", match.s.patno, cap.s.no, buf, eoff);
                    }
                }
                (*nmatches)++;
            }
        }
        hfa_matches_cleanup(&((psctx->savedctx).state), pmatches);
    }
    return (retval);
}
/**
 * Match callback to count number of matches.
 * This callback is registered using hfa_searchparam_set_matchcb().
 *
 * @param   patno   pattern number
 * @param   mno     match number with in pattern (for captured groups)
 * @param   soff    start offset
 * @param   eoff    end offset
 * @param   arg     callback argument
 */
void 
hfautils_matchcb(int patno, int mno, int soff, int eoff, void *arg)
{
/* no fau registers support in simulator */
#ifndef HFA_SIM
    hfautils_fau_perfcntrs_t *pstats = NULL;

    pstats = (hfautils_fau_perfcntrs_t *)arg;
    if(pstats){
        HFAUTILS_FAU_INCBY((*pstats), nmatches, 1);
    }
#endif
}
/**
 * Initialize the interfaces to receive network traffic.
 *
 *@param    hfa_prt_cfg      pointer to port configuration structure
 *
 *@return   HFA_SUCCESS 
 */
hfa_return_t
hfautils_initinterfaces (hfa_prt_cfg_t *hfa_prt_cfg)
{
/* no network packets support for simulator */
#ifndef HFA_SIM
    int                         port, interface, imode, num_interfaces;
    cvmx_pip_prt_tagx_t         tag_config;
    int                         pkind;
    
    LOG("Initializing Interfaces for HFA-Apps\n");   
    num_interfaces = cvmx_helper_get_number_of_interfaces();
#ifndef KERNEL
    /* Initialize the PIP, IPD, and PKO hardware to support
    * simple priority based queues for the ethernet ports.
    */
    if (cvmx_helper_initialize_packet_io_global ())
        ERR ("unable to initialize packet io\n");
#endif
    /* Setup Random Early Drop to automatically begin 
     * dropping packets when there are less than 128 
     * packet buffers.
     */
    cvmx_helper_setup_red (256,128);
    for (interface = 0; interface < num_interfaces; interface++){ 
        int                             num_ports;
        
        imode = cvmx_helper_interface_get_mode (interface);

        num_ports = cvmx_helper_ports_on_interface (interface);
        switch(imode){
            case CVMX_HELPER_INTERFACE_MODE_SGMII:
            case CVMX_HELPER_INTERFACE_MODE_QSGMII:
            case CVMX_HELPER_INTERFACE_MODE_XAUI:
            for (port = 0; port < num_ports; port++){
                /*Group Configuration*/
                if(octeon_has_feature(OCTEON_FEATURE_PKND)){
		            pkind = cvmx_helper_get_pknd(interface, port);
                } else {
	    	        pkind = cvmx_helper_get_ipd_port(interface, port);
                }
                tag_config.u64=  cvmx_read_csr(CVMX_PIP_PRT_TAGX(pkind));
                /* Sets ipv4 includes src address in tuple tag hash */
                tag_config.s.ip4_src_flag = 1;
                /* Sets IPv4 includes dst address in tuple tag hash */
                tag_config.s.ip4_dst_flag = 1;
                /* Sets IPv4 includes protocol in tuple tag hash */
                tag_config.s.ip4_pctl_flag = 1;
                /* Sets IPv4 includes TCP/UDP src port in tuple tag hash */
                tag_config.s.ip4_sprt_flag = 1;
                /* Sets IPv4 includes TCP/UDP dst port in tuple tag hash */
                tag_config.s.ip4_dprt_flag = 1;
                if(hfa_prt_cfg->isgrpset) {
                   /* Specifies the grp to use for the work. PIP will
                    * set this group to all incoming packets */
                   tag_config.s.grp = hfa_prt_cfg->wqegrp;
                }
                if(hfa_prt_cfg->grptag) {
                /* Configure PIP_PRT_TAG register to compute the work-queue 
                * entry group from tag bits.
                * If grptag is 1. Enables the use of the least-significant
                * bits of the work-queue entry Tag field to determine the 
                * work-queue entry group.
                * 
                * wqe group = (WORD2[Tag<5:0>] AND ~(GRPTAGMASK)) + GRPTAGBASE
                * GRPTAGMASK specifies which of the least-significant bits of
                * the wqe Tag field to exclude from the computation.
                *
                */
                    tag_config.s.grptag = 1;
                /* 4 Bits of the GRPTAGMASK */
                    tag_config.s.grptagmask = hfa_prt_cfg->tagmask_lsb;
                /* Most significant 2 Bits of the GRPTAGMASK */
                    tag_config.s.grptagmask_msb = hfa_prt_cfg->tagmask_msb;
                /* Offset to use to compute the work-queue entry group 
                 * from tag bits.
                 */
                    tag_config.s.grptagbase = 0x0;
                    tag_config.s.grptagbase_msb = 0x0;
                }
                if(hfa_prt_cfg->istagtypeset) {
                    /* tag_type for each incoming packet.(ORDERED, ATOMIC or NULL) */ 
                    tag_config.s.ip4_tag_type = hfa_prt_cfg->tag_type;
                }
                cvmx_write_csr(CVMX_PIP_PRT_TAGX(pkind), tag_config.u64);
                hfa_os_sync();
            }
            break;
            default:
            break;
        }
    }
#endif
    return HFA_SUCCESS;
}
/**
 * Initialize WQE, IBUF and PKO fpa pools.
 *
 * @param   ibuf_pool_cnt    number of ibuf pools to be create 
 * @param   wqe_pool_cnt     number of wqe pools to be create
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfautils_initialize_wqepool(uint64_t ibuf_pool_cnt, uint64_t wqe_pool_cnt)
{
/* no wqe,ibuf and fpa pools support in simulator */
#if !(defined KERNEL) && !(defined HFA_SIM)
    hfa_size_t    nbuffers;
    int           pko=0, ibuf=0, wqe=0;
    int           pko_pool_cnt = 0;
    int           pool = 0;
    
    /*create FPA_WQE_POOL and FPA_IBUF_POOL*/
    for(pool = 0; pool < 8; pool++){ 
        nbuffers = cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (pool));

        switch(pool){
            case OCTEON_IBUFPOOL:
                if(nbuffers){
                    ibuf_pool_cnt = nbuffers;
                    ibuf=0;
                } else {
                    ibuf = ibuf_pool_cnt;
                }
            break;

            case CVMX_FPA_WQE_POOL:
                if(nbuffers){
                    wqe_pool_cnt= nbuffers;
                    wqe=0;
                } else {
                    wqe = wqe_pool_cnt;
                }

            break;

            case CVMX_FPA_OUTPUT_BUFFER_POOL:
                if(nbuffers){
                    pko_pool_cnt = nbuffers;
                    pko=0;
                } else {
                    pko = CVMX_PKO_MAX_OUTPUT_QUEUES * 32;
                    pko_pool_cnt = pko;
                }
            break;

            default:
                /*Do nothing*/
            break;

        }
    }
    if (cvmx_helper_initialize_fpa (ibuf, wqe, pko, 0, 0)){
        ERR ("unable to initialize wqe and pko pools\n");
        return HFA_FAILURE; 
    }
    LOG("OCTEON_IBUFPOOL configured with %lu buffers\n", ibuf_pool_cnt);
    LOG("WQE POOL configured with %lu buffers\n", wqe_pool_cnt);
    LOG("PKO pool configured with %d buffers\n", pko_pool_cnt);

    if (octeon_has_feature(OCTEON_FEATURE_CN68XX_WQE) && 
            (!cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (8)))) 
        cvmx_helper_initialize_sso(wqe_pool_cnt);
#endif
    return HFA_SUCCESS;
}
/**
 * Create local packets for pcap/normal payload.
 * 
 * @param   wqe_attr           pointer to structure of attributes  
 * @param   poptions           pointer to cmd line options
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
static inline hfa_return_t
hfautils_create_pktwqe(pktwqe_attr_t *wqe_attr, options_t *poptions)
{
    cvmx_wqe_t              *wqe = NULL;
    uint8_t                 *buf = NULL;
    uint64_t                npkts = 0, nitrns = 0;
    uint64_t                i = 0, pktcnt = 0;
    hfautils_payload_attr_t *pattr = NULL;
     
    if(wqe_attr){
        pattr = (hfautils_payload_attr_t *)(wqe_attr->pattr);
        if(pattr){
            /* Calculate possible number of packets from payload file */
            if(poptions->pcap) {
                if(pattr->phdr == NULL) {
                    ERR("PCAP HDR must be initialized\n");
                    return HFA_FAILURE;
                }
                if(pattr->phdr->snaplen < (OCTEON_IBUFPOOL_SIZE)){
                    ERR("OCTEON_IBUFPOOL_SZ < pcap->snaplen: %d\n", 
                        pattr->phdr->snaplen);
                    return HFA_FAILURE;
                }
                /* Get valid number of packets from pcap file */
                if(HFA_SUCCESS != pcap_count_vpackets(pattr, &npkts)) {
                    ERR("Failure in pcap_count_vpackets\n");
                    return HFA_FAILURE;
                }
            }else {
                poptions->chunksize = OCTEON_IBUFPOOL_SIZE;
                npkts = (poptions->payloadsize/poptions->chunksize);
                if(poptions->payloadsize % poptions->chunksize)
                    npkts += 1;
            }
            if (npkts == 0)
            {
                ERR ("payload file doesnt have valid packets");
                return HFA_FAILURE;
            }
            if(wqe_attr->npkts <= npkts){
                nitrns = 1;
            }
            else { 
                nitrns = (wqe_attr->npkts/npkts); 
                if(wqe_attr->npkts % npkts)
                    nitrns += 1;
            }
            /* Number of local packets configurable using cmdline option(npkts) 
             * Create local packets equal to npkts */
            for(i = 0; i < nitrns; i++){
                while(!gzeof(pattr->gzf)){
                    /* Get a packet buffer and packet size */
                    if(HFA_SUCCESS != hfautils_parse_payload(pattr, poptions)){
                        if(gzeof(pattr->gzf))
                            continue;
                    }
                    assert (pattr->psize!= 0);
                    assert (pattr->payload != NULL);
                    wqe = cvmx_fpa_alloc(CVMX_FPA_WQE_POOL);
                    assert (wqe != NULL);
                    buf = cvmx_fpa_alloc(OCTEON_IBUFPOOL);
                    assert (buf != NULL);
                    memset(buf, 0, OCTEON_IBUFPOOL_SIZE);
                    /* Copy packet data into IBUF pool memory*/ 
                    memcpy(buf, pattr->payload, pattr->psize);
                    /* Cleanup allocated memory for reading a packet */
                    hfautils_memoryfree(pattr->payload, pattr->psize, 
                                        (hfa_searchctx_t *) NULL);
                    memset(wqe, 0, sizeof(cvmx_wqe_t));
                    cvmx_wqe_set_len(wqe, pattr->psize);
                    wqe->packet_ptr.s.addr = cvmx_ptr_to_phys(buf);
                    wqe->packet_ptr.s.size = pattr->psize;
                    wqe->word2.s.bufs = 1;
                    /* Submit WQE to the SSO */
                    cvmx_pow_work_submit(wqe, wqe_attr->tag, wqe_attr->tt, 
                                         wqe_attr->qos, wqe_attr->grp); 
                    pktcnt++;
                    if(wqe_attr->npkts == pktcnt)
                        break;
                }
                if(poptions->pcap)
                    gzseek(pattr->gzf, sizeof(pcap_file_header_t), SEEK_SET);
                else 
                    gzseek(pattr->gzf, 0, SEEK_SET);
            }
            return HFA_SUCCESS;
        }
    }
    return HFA_FAILURE;
}
/**
 * Create local packets for pcap/normal payload.
 *
 * 
 * @param   wqe_attr           pointer to structure of attributes  
 * @param   poptions           pointer to cmd line options
 *
 * @return  HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_create_localpkts (pktwqe_attr_t *wqe_attr, options_t *poptions)
{
    unsigned long nwqe=0, npkts;

    if(NULL == wqe_attr){
        return HFA_FAILURE;
    }
    nwqe = cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(CVMX_FPA_WQE_POOL)); 
    npkts = cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(OCTEON_IBUFPOOL));      
    if(!nwqe || !npkts){
        ERR("[%lu, %lu]: Pools are empty for local pkts\n", nwqe, npkts);
        return HFA_FAILURE;
    }
    if(wqe_attr->npkts > nwqe || wqe_attr->npkts > npkts){
        ERR("[%lu, %lu]: Pools are not enough for local pkts\n", nwqe, npkts);
        return HFA_FAILURE;
    }
    return(hfautils_create_pktwqe(wqe_attr, poptions));
}
/* no network packets support for simulator */
#ifndef HFA_SIM
/**
 * Send packet data out via network interface(PKO).
 * 
 * @param   wqe    pointer to packet wqe 
 */
void 
hfautils_send_pkt(cvmx_wqe_t *wqe)
{
    cvmx_pko_command_word0_t    pko_command;
    cvmx_buf_ptr_t              packet_ptr;
    uint64_t                    port;
    int                         queue;

    port = cvmx_wqe_get_port (wqe);
    queue = cvmx_pko_get_base_queue (port);
    cvmx_pko_send_packet_prepare (port, queue, CVMX_PKO_LOCK_ATOMIC_TAG);
    pko_command.u64 = 0;
    if (wqe->word2.s.bufs == 0) {
        pko_command.s.total_bytes = cvmx_wqe_get_len (wqe);
        pko_command.s.segs = 1;
        packet_ptr.u64 = 0;
        packet_ptr.s.pool = CVMX_FPA_WQE_POOL;
        packet_ptr.s.size = CVMX_FPA_WQE_POOL_SIZE;
        packet_ptr.s.addr = cvmx_ptr_to_phys (wqe->packet_data);
        if (cvmx_likely (!wqe->word2.s.not_IP)) {
            if (wqe->word2.s.is_v6)
                packet_ptr.s.addr += 2;
            else
                packet_ptr.s.addr += 6;
        }
    }
    else {
        pko_command.s.total_bytes = cvmx_wqe_get_len (wqe);
        pko_command.s.segs = wqe->word2.s.bufs;
        packet_ptr = wqe->packet_ptr;
        cvmx_fpa_free (wqe, CVMX_FPA_WQE_POOL, 0);
    }
    if (cvmx_pko_send_packet_finish (port, queue, pko_command, packet_ptr,
                CVMX_PKO_LOCK_ATOMIC_TAG))
        hfa_dbg("failed to send packet\n");
    cvmx_pow_tag_sw_null ();
}
/**
 * Print performance statistics.
 *
 * @param  p            pointer to structure of performance statistics
 * @param  start_port   start port
 * @param  nports       number of ports 
 * @param  verbose      verbose to print more stats
 * @param  cb           callback argument
 */
void
hfautils_printstats (hfautils_fau_perfcntrs_t *p, int start_port,
                     int nports, int verbose, hfautils_printcb_t cb)
{
    static uint64_t             prev = 0;
    uint64_t                    diff;
    uint64_t                    hz= cvmx_sysinfo_get()->cpu_clock_hz;

    if(p){
        diff = cvmx_get_cycle () - prev;
        if (diff > (hz)) {
            prev = __hfautils_printstats(p, start_port, nports, verbose);
            if(cb && verbose){
                (*cb)();
            }
       }
    }
}
/**
 * Print all fpa pools statistics
 */
void hfautils_print_fpapools_stats (void){

    hfa_log ("%s:\n%lu, %lu, %lu, %lu, %lu, %lu, "
            "%lu %lu\n", "pools",
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (0)),
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (1)),
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (2)),
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (3)),
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (4)),
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (5)),
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (6)),
        (unsigned long) cvmx_read_csr (CVMX_FPA_QUEX_AVAILABLE (7)));
}
#endif

#ifdef KERNEL
/**
 * Schedule a tasklet.
 *
 * @param  taskptr  pointer to tasklet structure
 *
 */
int schedule_tasklet(void *taskptr)
{
    struct tasklet_struct  *task = NULL;
    void **pptr = (void **) taskptr;

    *pptr = (void *)
            hfautils_memoryalloc(sizeof(struct tasklet_struct), 8, 
                                            (hfa_searchctx_t *)NULL);
    if(*pptr){
        task = (struct tasklet_struct *) *pptr;
        tasklet_init(task,tasklet_callbackptr,(unsigned long)NULL);
        tasklet_schedule(task);
    } 
    return 0;
}
/** Validate Tasklets Coremask and Threads Coremask.
 *
 * @param    pcmsk_attr     pointer to coremask attributes
 *
 * @return   HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t
hfautils_validate_threads_and_tasklets_coremask(coremask_attr_t *pcmsk_attr) 
{
    cvmx_coremask_clear_all(&pcmsk_attr->tasks_coremask);
    cvmx_coremask_set_core(&pcmsk_attr->tasks_coremask, 0);
    
    cvmx_coremask_clear_all(&pcmsk_attr->threads_coremask);
    cvmx_coremask_set_core(&pcmsk_attr->threads_coremask, 0);
    
    cvmx_coremask_set64(&pcmsk_attr->tasks_coremask, pcmsk_attr->tasks_mask);
    cvmx_coremask_set64(&pcmsk_attr->threads_coremask,pcmsk_attr->threads_mask);
    
    if(cvmx_coremask_intersects(&pcmsk_attr->tasks_coremask, 
                               &pcmsk_attr->threads_coremask)){
        ERR("threads_mask and tasks_mask should be mutually exclusive\n");
        return HFA_FAILURE;
    }
    if(!cvmx_coremask_is_subset(&cvmx_sysinfo_get()->core_mask, 
                                &pcmsk_attr->tasks_coremask) || 
      !cvmx_coremask_is_subset(&cvmx_sysinfo_get()->core_mask,
                               &pcmsk_attr->threads_coremask)) 
    {
        ERR("task_mask or threads_mask contains cores not in the coremask\n");
        return HFA_FAILURE;
    }
    pcmsk_attr->task_cores = 
    cvmx_coremask_get_core_count(&pcmsk_attr->tasks_coremask);
    
    pcmsk_attr->thread_cores = 
    cvmx_coremask_get_core_count(&pcmsk_attr->threads_coremask);

    return HFA_SUCCESS;
}

/**
 * Launch all threads and tasklets.
 *
 * @param    thread_callback    pointer to thread callback function
 * @param    tasklet_callback   pointer to tasklet callback function
 * @param    pcmsk_attr         pointer to coremask attributes
 * @param    path               absolute path of payload file
 *
 * @return   HFA_SUCCESS/HFA_FAILURE
 */
hfa_return_t 
hfautils_launch_thread_and_tasklet(int (*thread_callback)(void *),
                                  void (*tasklet_callback)(unsigned long), 
                                  coremask_attr_t *pcmsk_attr, char *path)
{
    struct task_struct          *thread[MAX_CORES] = {NULL};
    struct task_struct          *task_thread[MAX_CORES] = {NULL};
    int                         i = 0, j = 0;
    
    tasklet_callbackptr = tasklet_callback;
    
    LOG("tasklet cores: %d thread cores : %d\n", pcmsk_attr->task_cores, 
                                            pcmsk_attr->thread_cores);
    /* Schedule Threads and Tasklets */
    for(i=0,j=0; j < pcmsk_attr->task_cores; i++)
    {
        if(cvmx_coremask_is_core_set(&pcmsk_attr->tasks_coremask, i)){
            task_thread[j] = kthread_create(schedule_tasklet, (void *)&(task[i]),
                                                            "tasklet_thread");
            if(!IS_ERR(task_thread[j]))
            {
                kthread_bind(task_thread[j],i);
                j++;
            }
            else { 
                ERR("kthread_create for schedule tasklet failed\n");
                return HFA_FAILURE;
            }
        }
    }
    j--;
    while(j>=0)
    {
        if(task_thread[j])
            wake_up_process(task_thread[j]);
        j--;
    }
    for(i=0,j=0; j < pcmsk_attr->thread_cores; i++)
    {
        if(cvmx_coremask_is_core_set(&pcmsk_attr->threads_coremask, i)){
            thread[j] = kthread_create(thread_callback,(void *)path,"thread");
            if(!IS_ERR(thread[j]))
            {
                kthread_bind(thread[j],i);
                j++;
            }
            else { 
                ERR("thread creation failed\n");
                return HFA_FAILURE;
            }
        }
    }
    j--;
    while(j>=0)
    {
        if(thread[j])
            wake_up_process(thread[j]);
        j--;
    }
    return HFA_SUCCESS;
}
/**
 * Kill all tasklets 
 */
void hfautils_kill_tasklets(coremask_attr_t *pcmsk_attr)
{
    int i = 0, j = 0;
    
    for(i=0,j=0; j < pcmsk_attr->task_cores; i++)
    {
        if(cvmx_coremask_is_core_set(&pcmsk_attr->tasks_coremask, i)&&task[i]) {
            tasklet_kill(task[i]);
            hfautils_memoryfree(task[i], sizeof(struct tasklet_struct), 
                                            (hfa_searchctx_t *)NULL);
            j++;
        }
    }
}
#endif
