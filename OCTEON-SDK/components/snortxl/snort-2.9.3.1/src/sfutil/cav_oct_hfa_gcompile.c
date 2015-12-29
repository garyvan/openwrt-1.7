 	 	/***********************license start***************                              
* Copyright (c) 2008-2015 Cavium Inc. All rights reserved.
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


#include "fpcreate.h"
#include <cav_oct_hfa.h>
#include <sfportobject.h>
#include <snort.h>

int create_graphs = 0;
int merge_graphs = 1;
extern SnortConfig *snort_conf;
extern int max_hfa_len;
extern int min_hfa_len;
MDATA *global_meta_data[12];   // Meta data for the 12 different types of port tables.
GMDATA *global_graph_meta_data; // Meta data for the graphs that are being generated, similar to MDATA.
GMDATA *pm_type_list[PM_TYPE__MAX]={NULL};  // List to hold different pm_list graphs of TCP Port Table.
#ifdef CAV_OCT_HFA_GCOMPILE
#define CVMX_SHARED
#endif
extern CVMX_SHARED unsigned int sf_cmask;
MG_DATA mg_list[12]={{0}};

typedef struct _mpse_struct {

    int    method;
    void * obj;
    int    verbose;
    uint64_t bcnt;
    char   inc_global_counter;

} MPSE;


#define ERROR printf
//#define DUMP_MDATA
//#define STATIC_CACHE

#ifdef CAV_OCT_HFA_GCOMPILE
#include <sha1x86.h>

char graphpath[100]="./snortRuleDir/graphs/";
char pfpath[100] = "./snortRuleDir/patterns/";
char hfa_cmd_pool[100] = "./snortRuleDir/patterns/hfa_cmd_pool.sh";

#define dbgprintf(level, x...) if (level <= LOG_LEVEL) printf(x)
#define dbginfo(x...) dbgprintf(LINFO, x)
#define dbgl1(x...) dbgprintf(LVERBOSE, x)
#define dbgl2(x...) dbgprintf(LNOISY, x)
#define LNOISY 3
#define LINFO 1
#define LVERBOSE 2
#define LOG_LEVEL LINFO  /* Modify for more verbose output */

void * cavOctHfaNew
    (
     void (*sn_pat_free)(void *p),
     void (*sn_option_tree_free)(void **p),
     void (*sn_neg_list_free)(void **p)
    )
{
    CAV_OCT_HFA_MPSE *cohm = NULL;
    static int cnt = 0;
    char buf[100];

    dbgl1("cavOctHfaNew: entered\n");

    cohm = (CAV_OCT_HFA_MPSE *)SnortAlloc(sizeof(*cohm));
    memset(cohm, 0, sizeof(*cohm));
    cohm->sn_pat_free = sn_pat_free;
    cohm->sn_option_tree_free = sn_option_tree_free;
    cohm->sn_neg_list_free = sn_neg_list_free;
    cohm->meta_data = (MDATA *)SnortAlloc(sizeof(MDATA)); 
    memset(cohm->meta_data,0,sizeof(MDATA));
    cohm->meta_data->min_len = 1000;
    
    if(!cnt)
    {
        cnt++;
        if(create_graphs==1)
        {
            snprintf(buf, sizeof(buf)-1, "rm -rf %s",graphpath);
            system(buf);
        }
        snprintf(buf, sizeof(buf)-1, "mkdir -p %s",graphpath);
        system(buf);
        snprintf(buf, sizeof(buf)-1, "mkdir -p %s",pfpath);
        system(buf);
        snprintf(buf, sizeof(buf)-1, "rm -rf %s*",pfpath);
        system(buf);
    }
    dbgl1("cavOctHfaNew: returned %p\n", cohm);
    return (void *)cohm;
}

int cavOctHfaAddPattern
(
 CAV_OCT_HFA_MPSE *cohm,
 unsigned char *pattern,
 int pat_len,
 unsigned int sn_no_case,
 unsigned int sn_negative,
 void *sn_pat_data,
 int sn_pat_id
 )
{
    CAV_OCT_HFA_PATTERN *pat;
    int i, offset = 0;
    dbgl2("cavOctHfaAddPattern: entered (cohm: %p)\n", cohm);
    if (cohm == NULL)
        return -1;

    dbgl2("cavOctHfaAddPattern: pattern_count %d, pattern_array_len %d \n", 
            cohm->pattern_count, cohm->pattern_array_len);
    if (cohm->pattern_count >= cohm->pattern_array_len)
    {
        int array_len = cohm->pattern_count + PATTERN_ARRAY_ALLOC_SIZE;
        pat = SnortAlloc(array_len*sizeof(*pat));
        memset(pat, 0, array_len*sizeof(*pat));
        memcpy(pat, cohm->pattern_array, cohm->pattern_count*sizeof(*pat));
        if (cohm->pattern_array)
            free(cohm->pattern_array);
        cohm->pattern_array = pat;
        cohm->pattern_array_len = array_len;
        dbgl2("cavOctHfaAddPattern: pattern_array %p[%d] \n", 
                cohm->pattern_array, cohm->pattern_array_len);
    }

    dbgl2("cavOctHfaAddPattern: sn_pattern %p of len %d \n", pattern, pat_len);
    pat = &cohm->pattern_array[cohm->pattern_count];
    pat->sn_pattern = (unsigned char *)SnortAlloc(pat_len);     /*pat->sn_pattern should be clean while deleting*/
    if (pat->sn_pattern == NULL)
        return -1;
    memcpy(pat->sn_pattern, pattern, pat_len);
    /* record each octet in the form "\xhh" to suit our pattern compiler */
    pat->pattern_len = pat_len*4;
    pat->sn_no_case = sn_no_case;
    pat->sn_negative = sn_negative;
    if (pat->sn_no_case)
        pat->pattern_len += 3; /* for {i} pattern prefix */
    if (pat->sn_negative)
        pat->pattern_len += 0; 
    pat->hex_pattern = (unsigned char *)SnortAlloc(pat->pattern_len+1); /* pat->hex_pattern should be clean while deleting */
    if (pat->hex_pattern == NULL)
        return -1;
    if (pat->sn_no_case)
        offset += sprintf((char *)pat->hex_pattern+offset, "{i}"); 
    //if (pat->sn_negative)
    //    offset += sprintf((char *)pat->hex_pattern+offset, ""); 
    for(i = 0; i < pat_len; i++)
        offset += sprintf((char *)pat->hex_pattern+offset, "\\x%02x", pattern[i]); 
    pat->sn_pat_id = sn_pat_id;
    pat->sn_pat_data = sn_pat_data;
    pat->patternId = cohm->pattern_count++;
    dbgl2("cavOctHfaAddPattern: pattern[%d]' of len %d: '%s'\n", 
            cohm->pattern_count - 1, pat->pattern_len, pat->hex_pattern);

    dbgl2("cavOctHfaAddPattern: returned\n");
    if(sn_no_case)
        cohm->meta_data->ncase++;
    if(cohm->meta_data->min_len > pat_len)
        cohm->meta_data->min_len = pat_len;
    if(cohm->meta_data->max_len < pat_len)
        cohm->meta_data->max_len = pat_len;
    if(pat_len < MAX_SHORT_LENGTH)
        cohm->meta_data->nshort++;
    cohm->meta_data->tot_len += pat_len;
    return 0;
}

int cavOctHfaGetPatternCount(CAV_OCT_HFA_MPSE *cohm)
{
    if (cohm == NULL)
        return 0;

    dbgl1("cavOctHfaGetPatternCount: %d\n", cohm->pattern_count);
    return cohm->pattern_count;
}

int cavOctHfaCompile
(
 CAV_OCT_HFA_MPSE *cohm,
 int (*sn_build_tree)(void *id, void **existing_tree),
 int (*sn_neg_list_func)(void *id, void **list)
 )
{
    char * pattern_list;
    int ret,i,pfile = 0;
    int graph_data_len = 0;
    FILE * fp = NULL;
    char pfname[100];
    static int gcnt = 0;
    static int gsize = 0;
    SHA1Context sha;
    int err;

    dbgl1("cavOctHfaCompile: entered\n");
    if (cohm == NULL)
        return -1;

    cohm->meta_data->npat = cohm->pattern_count;
    cohm->meta_data->next = NULL;
    cohm->meta_data->gcount = 0;
    dbgl1("cavOctHfaCompile: gcnt = %d, gsize = %d\n", gcnt, gsize);
    cohm->sn_build_tree = sn_build_tree;
    cohm->sn_neg_list_func = sn_neg_list_func;

    /* create iovec with all patterns */
    for (i = 0; i < cohm->pattern_count; i++)
    {
        CAV_OCT_HFA_PATTERN *pat = &cohm->pattern_array[i];
        graph_data_len += pat->pattern_len+1;
    }
    dbgl1("cavOctHfaCompile: pattern_array[%d] of total len %d bytes\n", 
            cohm->pattern_count, graph_data_len);
    pattern_list = SnortAlloc(graph_data_len);
    if (pattern_list == NULL)
    {
        FatalError("pattern_list = SnortAlloc(%d) failed\n", graph_data_len);
    }
    graph_data_len = 0;
    unsigned char md[20];
    memset(md,0,40);
    int pattern_length = 0, offset = 0;
    char *pattern_str;
    for (i = 0; i < cohm->pattern_count; i++)
    {
        CAV_OCT_HFA_PATTERN * pat = &cohm->pattern_array[i];
        pattern_length += pat->pattern_len/4;
    }
    pattern_str = (char*)SnortAlloc(sizeof(char)*pattern_length);
    memset(pattern_str,0,pattern_length);

    for (i = 0; i < cohm->pattern_count; i++)
    {
        CAV_OCT_HFA_PATTERN * pat = &cohm->pattern_array[i];
        memcpy(pattern_str+offset,pat->sn_pattern,pat->pattern_len/4);
        offset += pat->pattern_len/4;
        memcpy(pattern_list+graph_data_len, pat->hex_pattern, pat->pattern_len);
        graph_data_len += pat->pattern_len;
        /* follow each pattern with a new-line */
        pattern_list[graph_data_len] = '\n';
        graph_data_len++;
        if (cohm->sn_neg_list_func && cohm->sn_build_tree)
        {
            if (pat->sn_negative)
                cohm->sn_neg_list_func(pat->sn_pat_data, &pat->sn_neg_list);
            else
                cohm->sn_build_tree(pat->sn_pat_data, &pat->sn_rule_option_tree);
            if (cohm->sn_build_tree)
                cohm->sn_build_tree(NULL, &pat->sn_rule_option_tree);
        }
    }
    err = SHA1Reset(&sha);
    if (err)
        ERROR("SHA1Reset Error %s.\n",strerror(errno));
    err = SHA1Input(&sha,(const unsigned char *) pattern_str,pattern_length);
    if (err)
        ERROR("SHA1Input Error %s.\n",strerror(errno));
    err = SHA1Result(&sha,md);
    if (err)
        ERROR("SHA1Result Error %s.\n",strerror(errno));
    dbgl1("cavOctHfaCompile: pattern_list of total len %d\n", graph_data_len);
    if(strlen(graphpath) >= 60)
    {
        ERROR("graphpath is too long. Resetting it to default path i.e ./snortRuleDir/graphs\n"); 
        strcpy(graphpath,"./snortRuleDir/graphs/");
    }
    memcpy(pfname,pfpath,strlen(pfpath));
    for(i = 0;i < 20;i++)
    {
        sprintf(pfname+strlen(pfpath)+i*2,"%02x",*(uint8_t *)(md+i));
        sprintf((cohm->meta_data->gname)+i*2,"%02x",*(uint8_t *)(md+i));
    }
    sprintf(pfname + strlen(pfpath)+40,"%s",".txt");
    fp  = fopen(pfname, "r");
    if (fp != NULL)
    {
        pfile = 1;
        dbgl1("pattern file %s already availiable\n",pfname);
        fclose(fp);
    }
    fp  = fopen(pfname, "w");
    if (fp == NULL)
    {
        ERROR("fopen(%s) == NULL : %s\n", pfname, strerror(errno));
    }
    ret = fwrite(pattern_list, 1, graph_data_len, fp);
    if (ret != graph_data_len)
    {
        ERROR("fwrite(%s, %d) != %d : %s\n", pfname, graph_data_len, ret,
                strerror(errno));
    }
    fclose(fp);
    fp=NULL;
    free(pattern_list);
    pattern_list = NULL;
    dbgl1("cavOctHfaCompile: pattern file %s written\n", pfname);
    return 0;
}
#endif

/* Check the availaibilty of the graph from the graph_meta_data_list */
GMDATA *graph_present(char *gname)
{
    GMDATA *tmp = global_graph_meta_data;
    while (tmp != NULL)
    {
        if(!strcmp(tmp->gname,gname))
            return tmp;
        tmp = tmp->next;
    }
    return NULL;
}

/* Parse the port tables and generate the global_meta_data and
 * global_graph_meta_data_list */
void cavOctHfaParse()
{
    int i, j, k = 0;
    MDATA *tmp, *head;
    GMDATA *gtmp, *gtmp1 = NULL;
    int id;

    rule_port_tables_t *ptables = snort_conf->port_tables;
    global_graph_meta_data = NULL;
    PortTable *tmp_pt;
    PortObject *tmp_po;
    char gtable[3];

    while(k<8)
    {
        switch(k){
            case 0:
                tmp_pt = ptables->tcp_src;   //TCP SRC Port Table
                strcpy(gtable,"ts");
                break;
            case 1:
                tmp_pt = ptables->tcp_dst;   //TCP DST Port Table
                strcpy(gtable,"td");
                break;
            case 2:
                tmp_pt = ptables->udp_src;   //UDP SRC Port Table
                strcpy(gtable,"us");
                break;
            case 3:
                tmp_pt = ptables->udp_dst;   //UDP DST Port Table
                strcpy(gtable,"ud");
                break;
            case 4:
                tmp_pt = ptables->icmp_src;   //ICMP SRC Port Table
                strcpy(gtable,"cs");
                break;
            case 5:
                tmp_pt = ptables->icmp_dst;   //ICMP DST Port Table
                strcpy(gtable,"cd");
                break;
            case 6:
                tmp_pt = ptables->ip_src;   //IP SRC Port Table
                strcpy(gtable,"is");
                break;
            case 7:
                tmp_pt = ptables->ip_dst;   //IP DST Port Table
                strcpy(gtable,"id");
                break;
            default:
                break;
        }
        head = NULL;
        /* parse across each port for each port table, fetch the Port Object and
         * obtain it's meta data */
        for(i = 0;i < SFPO_MAX_PORTS; i++)
            for(j = 0; j < PM_TYPE__MAX; j++)
            {
                if(((PortObject2 *)(tmp_pt->pt_port_object[i]) != NULL) 
                        && (((PORT_GROUP *)(((PortObject2 *)(tmp_pt->pt_port_object[i]))->data)) != NULL)
                        && ((MPSE *)(((PORT_GROUP *)(((PortObject2 *)(tmp_pt->pt_port_object[i]))->data))->pgPms[j]) != NULL))
                {
                    tmp = ((CAV_OCT_HFA_MPSE *)(((MPSE *)((PORT_GROUP *)(tmp_pt->pt_port_object[i]->data))->pgPms[j])->obj))->meta_data;
                    id = tmp_pt->pt_port_object[i]->id; 
                    /* fill the meta data and also add the graph's meta data if
                     * it's meta data for this Port Object's graph is not yet added.
                     * */
                    if(tmp->gcount == 0)
                    {
                        sprintf(tmp->pgname,"%s_%01d_%07d",gtable,j,id);
                        tmp->pm_type = j;
                        tmp->gcount++;
                        if(head != NULL)
                        {
                            tmp->next = head;
                            head = tmp;
                        }
                        else
                        {
                            head = tmp;
                            head->next = NULL;
                        }

                        if(global_graph_meta_data == NULL)
                        {
                            global_graph_meta_data = SnortAlloc(sizeof(GMDATA));
                            memcpy(global_graph_meta_data,tmp,sizeof(MDATA));
                            global_graph_meta_data->next = NULL;
                            global_graph_meta_data->cache = 1000;
                            global_graph_meta_data->mg_offset = 0;
                            global_graph_meta_data->mg_flag = -1;
                            tmp->gmptr = global_graph_meta_data;
                            //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,global_graph_meta_data->gname,
                            //        global_graph_meta_data->mg_flag);
                            gtmp1 = global_graph_meta_data;
                        }
                        else
                        {
                            gtmp = NULL;
                            gtmp = graph_present(tmp->gname); 
                            if( gtmp == NULL)
                            {
                                gtmp = SnortAlloc(sizeof(GMDATA));
                                memcpy(gtmp,tmp,sizeof(MDATA));
                                gtmp->next = NULL;
                                gtmp->prev = NULL;
                                gtmp->cache = 1000;
                                gtmp->mg_offset = 0;
                                gtmp->mg_flag = -1;
                                tmp->gmptr = gtmp;
                                //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,gtmp->gname, gtmp->mg_flag);
                                gtmp->prev = gtmp1;
                                gtmp1->next = gtmp;
                                gtmp1 = gtmp;
                            }
                            else
                            {
                                gtmp->gcount++;
                                tmp->gmptr = gtmp;
                                //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,gtmp->gname, gtmp->mg_flag);
                            }
                        }

                    }
                    else
                    {
                        tmp->gcount++;
                        gtmp = NULL;
                        gtmp = graph_present(tmp->gname); 
                        //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,gtmp->gname, gtmp->mg_flag);
                        if(gtmp == NULL)
                            FatalError("Graph meta data entry should be there\n");
                        else
                            gtmp->gcount++;
                    }
                }
            }
        global_meta_data[k] = head;
        id = 0;
        k++;
        memset(gtable,0x0,3);
    }
    k = 0;
    while(k<4)
    {
        switch(k){
            case 0:
                tmp_po = ptables->tcp_anyany; // TCP ANY ANY Port Table (Port Object).
                strcpy(gtable,"ta");
                break;
            case 1:
                tmp_po = ptables->udp_anyany; // UDP ANY ANY Port Table (Port Object).
                strcpy(gtable,"ua");
                break;
            case 2:
                tmp_po = ptables->icmp_anyany; // ICMP ANY ANY Port Table (Port Object).
                strcpy(gtable,"ca");
                break;
            case 3:
                tmp_po = ptables->ip_anyany; // IP ANY ANY Port Table (Port Object).
                strcpy(gtable,"ia");
                break;
            default:
                break;
        }
        head = NULL;
        for(j = 0; j < PM_TYPE__MAX; j++)
        {
            if((((PORT_GROUP *)(tmp_po->data)) != NULL)
                    && ((MPSE *)(((PORT_GROUP *)(tmp_po->data))->pgPms[j]) != NULL))
            {
                tmp = ((CAV_OCT_HFA_MPSE *)(((MPSE *)((PORT_GROUP *)(tmp_po->data))->pgPms[j])->obj))->meta_data;
                id = tmp_po->id; 
                if(tmp->gcount == 0)
                {
                    sprintf(tmp->pgname,"%s_%01d_%07d",gtable,j,id);
                    tmp->gcount++;
                    tmp->pm_type = j;
                    if(head != NULL)
                    {
                        tmp->next = head;
                        head = tmp;
                    }
                    else
                    {
                        head = tmp;
                        head->next = NULL;
                    }

                    if(global_graph_meta_data == NULL)
                    {
                        global_graph_meta_data = SnortAlloc(sizeof(GMDATA));
                        memcpy(global_graph_meta_data,tmp,sizeof(MDATA));
                        global_graph_meta_data->next = NULL;
                        global_graph_meta_data->cache = 1000;
                        global_graph_meta_data->mg_offset = 0;
                        global_graph_meta_data->mg_flag = -1;
                        tmp->gmptr = global_graph_meta_data;
                        //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,global_graph_meta_data->gname,
                        //        global_graph_meta_data->mg_flag);
                        gtmp1 = global_graph_meta_data;
                    }
                    else
                    {
                        gtmp = NULL;
                        gtmp = graph_present(tmp->gname); 
                        if( gtmp == NULL)
                        {
                            gtmp = SnortAlloc(sizeof(GMDATA));
                            memcpy(gtmp,tmp,sizeof(MDATA));
                            gtmp->next = NULL;
                            gtmp->prev = NULL;
                            gtmp->cache = 1000;
                            gtmp->mg_offset = 0;
                            gtmp->mg_flag = -1;
                            tmp->gmptr = gtmp;
                            //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,gtmp->gname, gtmp->mg_flag);
                            gtmp->prev = gtmp1;
                            gtmp1->next = gtmp;
                            gtmp1 = gtmp;
                        }
                        else
                        {
                            gtmp->gcount++;
                            tmp->gmptr = gtmp;
                            //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,gtmp->gname, gtmp->mg_flag);
                        }
                    }
                }
                else
                {
                    tmp->gcount++;
                    gtmp = NULL;
                    gtmp = graph_present(tmp->gname); 
                    //printf("1)tmp->gname:%s ,gtmp->gname:%s mg_flag: %d\n",tmp->gname,gtmp->gname, gtmp->mg_flag);
                    if(gtmp == NULL)
                        ERROR("Graph meta data entry should be there\n");
                    else
                        gtmp->gcount++;
                }
            }
        }
        global_meta_data[k+8] = head;
        id = 0;
        k++;
    }
    return;
}


#ifndef STATIC_CACHE
void AddToTcpList(GMDATA *gtmp)
{
   if (pm_type_list[gtmp->pm_type] == NULL)
   {
     pm_type_list[gtmp->pm_type] = gtmp;
     pm_type_list[gtmp->pm_type]->next = NULL;
     pm_type_list[gtmp->pm_type]->prev = NULL;
   }
   else
   {
     gtmp->next = pm_type_list[gtmp->pm_type];
     gtmp->prev = NULL;
     pm_type_list[gtmp->pm_type]->prev = gtmp;
     pm_type_list[gtmp->pm_type] = gtmp;
   }
   return;
}

void PriListbyPatCnt(GMDATA *list)
{
    GMDATA *tmp = list;
    int i = 0;
    while ( tmp!= NULL )
    {
        i++;
        printf("%d) gname: %s pat_cnt: %d\n", i, tmp->gname, tmp->npat);
        tmp = tmp->next;
    }
}

/* swap the pointers not their content in a doubly linked list */
void lswap (GMDATA *a, GMDATA *b)
{
   GMDATA *an = NULL, *ap = NULL;
   GMDATA *bn = NULL, *bp = NULL;
   bn = b->next;
   bp = b->prev;
   an = a->next;
   ap = a->prev;

   // case 1: A next is B.
   if((an == b) || (bp == a))
   {
      if (!((an == b) && (bp == a)))
         ERROR (" list got screwed\n");

      // B values
      b->next = a;
      b->prev = ap;
      if (ap != NULL)
         ap->next = b;
      
      // A values
      a->prev = b;
      a->next = bn;
      if (bn != NULL)
         bn->prev = a;
   }
   // case 2: B next is A.
   else if((bn == a) || (ap == b))
   {
      if (!((bn == a) && (ap == b)))
         ERROR (" list got screwed\n");

      // B values
      b->prev = a;
      b->next = an;
      if (an != NULL)
         an->prev = b;

      // A values
      a->next = b;
      a->prev = bp;
      if (bp != NULL)
         bp->next = a;
   }
   // case 3: A and B are not adjacent.
   else
   {
      // B values
      b->next = an;
      b->prev = ap;
      if (an != NULL)
         an->prev = b;
      if (ap != NULL)
         ap->next = b;

      // A values
      a->next = bn;
      a->prev = bp;
      if (bn != NULL)
         bn->prev = a;
      if (bp != NULL)
         bp->next = a;
   }

   return;
}

/* Sort list by pattern count */
GMDATA * SortListbyPatCnt(GMDATA *pm_list)
{
   GMDATA *list = pm_list;
   int i = 0;
   while(list)
   {
      GMDATA *gtmp = list->next, *tmp = NULL;
      while(gtmp)
      {
        if(list->npat < gtmp->npat)
        {
            //SWAP
            lswap(list,gtmp);
            tmp = list;
            list = gtmp;
            gtmp = tmp;
        } 
        gtmp = gtmp->next;
      } 
      if(i == 0)
      {
          i++;
          pm_list = list;
      }
      //printf("===============================================================\n");
      //PriListbyPatCnt(pm_list);
      //printf("===============================================================\n");
      list = list->next;
   }
   return pm_list;
}

/* Get tot pattern count for a list */
int TotPatCnt(GMDATA *pm_list)
{
   GMDATA *list = pm_list;
   int i = 0;
   while(list)
   {
        i += list->npat;
		list = list->next;
   }
   return i;
}

/* Get tot pattern len for a list */
int TotPatLen(GMDATA *pm_list)
{
   GMDATA *list = pm_list;
   int i = 0;
   while(list)
   {
        i += list->tot_len;
		list = list->next;
   }
   return i;
}

/* Dump function to Dump global_meta_data of each Port Table */
void cavOctHfaDump()
{
#ifdef DUMP_MDATA
    MDATA *tmp;
    int k;

    printf("----------------------------------------------------------------------------------------------\n");
    printf("--- INDEX:- 0:TS, 1:TD, 2:US, 3:UD, 4:ICS, 5:ICD, 6:IPS, 7:IPD, 8:TA, 9:UA, 10:ICA, 11:IPA ---\n");
    printf("----------------------------------------------------------------------------------------------\n");
    for(k=0;k<12;k++)
    {
        printf("==================== INDEX: %d ====================\n",k);
        tmp = global_meta_data[k];
        while(tmp != NULL)
        {
            printf(" %s pganme:%s gcount:%5d npat:%5d tot_len:%8d ncase:%5d min_len:%2d max_len:%4d nshort:%3d\n",tmp->gname,tmp->pgname,tmp->gcount,tmp->npat,tmp->tot_len,tmp->ncase,tmp->min_len,tmp->max_len,tmp->nshort);
            tmp = tmp->next;
        }
    }
    printf("----------------------------------------------------------------------------------------------\n");
    printf("==============================================================================================\n");
    printf("----------------------------------------------------------------------------------------------\n");
#endif
    return;
}

/* Make the Pmtype lists for TCP graphs meta data. 
 * Also Sort Pmtype[0] graphs.
 * After this routine global_graph_meta_data contains all other graphs other
 * than TCP ones.
 * */
int cavOctHfaSort()
{

    GMDATA *gtmp = global_graph_meta_data;
    GMDATA *gtmp_prev = NULL;//Means Head

    if(gtmp == NULL)
       return 1 ; /* No patterns */

    while (gtmp != NULL)
    {
      if((!strncmp(gtmp->pgname, "ts", 2))||(!strncmp(gtmp->pgname, "td", 2))||(!strncmp(gtmp->pgname, "ta", 2)))
      {
        if (gtmp == global_graph_meta_data)
        {
           global_graph_meta_data = gtmp->next;
           AddToTcpList(gtmp);
           gtmp = global_graph_meta_data;
           gtmp_prev = NULL;
        }
        else
        {
           gtmp_prev->next = gtmp->next;
           if (gtmp->next != NULL)
              gtmp->next->prev = gtmp_prev;
           AddToTcpList(gtmp);
           gtmp = gtmp_prev->next;
        }
      }
      else
      {
        gtmp_prev = gtmp;
        gtmp = gtmp->next;
      }
    }
    
    // Sort pm_type_list[0] in descending order of number of patterns
    pm_type_list[0] = SortListbyPatCnt(pm_type_list[0]);

// Macro protected Dump metadata
#ifdef DUMP_MDATA
    printf("--------------------------------------------------------------------------------------\n");
    printf("================================== NON TCP GRAPH META DATA ===========================\n");
    printf("--------------------------------------------------------------------------------------\n");
    gtmp = global_graph_meta_data;
    while (gtmp != NULL)
    {
            printf(" %s pganme:%s gcount:%5d npat:%5d tot_len:%8d ncase:%5d min_len:%2d max_len:%4d nshort:%3d\n",gtmp->gname,gtmp->pgname,gtmp->gcount,gtmp->npat,gtmp->tot_len,gtmp->ncase,gtmp->min_len,gtmp->max_len,gtmp->nshort);
            gtmp = gtmp->next;
    }

    int k;
    for(k=0;k<5;k++)
    {
      
      printf("----------------------------------------------------------------------------------------\n");
      printf("============================ TCP PM TYPE %d GRAPH META DATA ============================\n", k);
      printf("----------------------------------------------------------------------------------------\n");
      gtmp = pm_type_list[k];
      while (gtmp != NULL)
      {
              printf(" %s pganme:%s gcount:%5d npat:%5d tot_len:%8d ncase:%5d min_len:%2d max_len:%4d nshort:%3d\n",gtmp->gname,gtmp->pgname,gtmp->gcount,gtmp->npat,gtmp->tot_len,gtmp->ncase,gtmp->min_len,gtmp->max_len,gtmp->nshort);
              gtmp = gtmp->next;
      }
    }
    printf("----------------------------------------------------------------------------------------------\n");
    printf("==============================================================================================\n");
    printf("----------------------------------------------------------------------------------------------\n");
#endif
    return 0;
}

inline uint32_t min(uint32_t a, uint32_t b) { return (a < b) ? a : b; }
inline uint32_t max(uint32_t a, uint32_t b) { return (a < b) ? b : a; }

/* Merge Graphs 
 *
 * Merging of Graphs happens on the below lists.
 *
 * pm_type_list[0]        : TCP graphs with pm_type 0.
 * global_graph_meta_data : All the non TCP graphs merged together according to
 *                          their respective port tables.
 *
 *                          UDP  src + UDP  dst  :- merge
 *                          ICMP src + ICMP dst  :- merge
 *                          IP   src + IP   dst  :- merge
 *
 *NOTE: Max limit of Merge graphs is 12 (can be changed).
 * */
void cavOctHfaGraphMerge()
{
    if(merge_graphs)
    {
        int i = 0, l = 0, act_pat = 0;
        GMDATA *tmp = NULL;       //SNORTXL:: Warning fix
        int pat_cnt_tany;
        int pat_cnt_any;
        int tot_len_tany;
        char any_gname[41];
        MDATA *tmp2;
#ifdef CAV_OCT_HFA_GCOMPILE
        int j = 0;
        char mg_pfname[100], tmp_pfname[100];
        char tmp_pattern[1000];
        FILE *fp = NULL, *fp1 = NULL;
        int k;
#endif
        tmp2 = global_meta_data[8];  // global_meta_data[8] is TCP_ANYANY 
        while (tmp2 != NULL)
        {
            if(tmp2->pm_type == 0)
                break;
            else
                tmp2 = tmp2->next;
        }

        if(tmp2 != NULL)
        {
            pat_cnt_tany = tmp2->npat;
            tot_len_tany = tmp2->tot_len;
        }
        else
        {   
            pat_cnt_tany = TotPatCnt(pm_type_list[0])/5 + 1;
            tot_len_tany = TotPatLen(pm_type_list[0])/10 + 1;
        }
        int pat_base = (pat_cnt_tany < 10) ?  (pat_cnt_tany/2 + pat_cnt_tany%2):(pat_cnt_tany/10);
        int tot_base = (tot_len_tany < 40) ? (tot_len_tany/4 + tot_len_tany%2):(tot_len_tany/40);

        for(l = 0; l < 4; l++)
        {
            switch (l)
            {
                case 0: 
                    tmp = pm_type_list[0];
                    break;
                case 1: 
                    tmp = global_graph_meta_data;
                    tmp2 = global_meta_data[9];   // UDP_ANYANY
                    break;
                case 2: 
                    tmp2 = global_meta_data[10];   // ICMP_ANYANY
                    break;
                case 3: 
                    tmp2 = global_meta_data[11];   // IP_ANYANY
                    break;
                default:
                    break;
            }

            if (tmp2 == NULL)
            {
                pat_cnt_any = 0;
                strcpy(any_gname,"no_any");
            }
            else
            {
                pat_cnt_any = tmp2->npat;
                strcpy(any_gname,tmp2->gname);
            }

            while (tmp != NULL)
            {
                act_pat = tmp->npat - pat_cnt_any;
                // pattern count is used only for TCP
                if (!l)
                {
                    if ((act_pat >= pat_base) || ((tmp->tot_len - tot_len_tany) >= tot_base))
                    {
                        tmp = tmp->next;
                        continue;
                    }
                }

                /* link the merged graph to the current graph */
                if (strcmp(any_gname,tmp->gname) || l)
                {
                    tmp->mg_flag = i;
                    tmp->mg_offset = mg_list[i].npat;
                }

                /* update the merged graph stats/parameters */ 
                mg_list[i].alive = 1;
                mg_list[i].npat += act_pat;
                if (mg_list[i].max_len < tmp->max_len)
                    mg_list[i].max_len = tmp->max_len;
                if (act_pat)
                    mg_list[i].tot_graphs++;


#ifdef CAV_OCT_HFA_GCOMPILE
                /* add patterns to the merged graph */
                if (j == 0)
                {
                    memset(mg_pfname,0,100);
                    memcpy(mg_pfname,pfpath,strlen(pfpath));
                    sprintf(mg_pfname + strlen(pfpath), "mg%d.txt", i);
                    fp  = fopen(mg_pfname, "r");
                    if (fp != NULL)
                    {
                        printf("merged graph pattern file %s already availiable\n",mg_pfname);
                        fclose(fp);
                    }
                    fp  = fopen(mg_pfname, "w");
                    if (fp == NULL)
                    {
                        ERROR("fopen(%s) == NULL : %s\n", mg_pfname, strerror(errno));
                    }
                    j++;
                }

                memset(tmp_pfname,0,100);
                memcpy(tmp_pfname,pfpath,strlen(pfpath));
                sprintf(tmp_pfname + strlen(pfpath), "%s.txt", tmp->gname);
                fp1 = fopen(tmp_pfname, "r");
                if (fp1 == NULL)
                {
                    ERROR("fopen(%s) == NULL : %s\n", tmp_pfname, strerror(errno));
                }

                for (k=0;k<act_pat;k++)
                {
                    fgets(tmp_pattern, sizeof(tmp_pattern), fp1);
                    fputs(tmp_pattern, fp);
                }
#endif

                if (((l == 0) && (!strcmp(any_gname,tmp->gname) || (mg_list[i].npat >= pat_cnt_tany))) || (tmp->next == NULL) 
                    || ((tmp->next != NULL) && (l == 1) && 
                       (!strncmp(tmp->next->pgname,"cs",2) || !strncmp(tmp->next->pgname,"cd",2) || !strncmp(tmp->next->pgname,"ca",2))) 
                    || ((tmp->next != NULL) && (l == 2) && 
                       (!strncmp(tmp->next->pgname,"is",2) || !strncmp(tmp->next->pgname,"id",2) || !strncmp(tmp->next->pgname,"ia",2)))
                    || ((l == 3) && (tmp->next == NULL)))
                {
#ifdef CAV_OCT_HFA_GCOMPILE
                    for (k=0;k<pat_cnt_any;k++)
                    {
                        fgets(tmp_pattern, sizeof(tmp_pattern), fp1);
                        fputs(tmp_pattern, fp);
                    }
                    fclose(fp);
                    fp = NULL;
                    j = 0;
#endif
                    mg_list[i].npat += pat_cnt_any;
                    mg_list[i].common_pat_cnt = pat_cnt_any;
#ifdef DUMP_MDATA
                    printf("level%d   MG Name: %s    MG Num:%d     Total_Patterns:%d \n",l,tmp->pgname,i,mg_list[i].npat);
#endif
                    i++;

                    if(l)
                    {
#ifdef CAV_OCT_HFA_GCOMPILE
                        fclose(fp1);
                        fp1=NULL;
#endif
                        tmp = tmp->next;
                        break;
                    }
                }

#ifdef CAV_OCT_HFA_GCOMPILE
                fclose(fp1);
                fp1=NULL;
#endif
                tmp = tmp->next;
            }
        }

#if 0
        int XXX = 0 , YYY = 0;
        for(i=0;i<=5;i++)
        {
            if(i == 5)
                // non TCP -- UDP,ICMP and IP    
                tmp = global_graph_meta_data;
            else
                tmp = pm_type_list[i];
            while((tmp != NULL))
            {
                if (tmp->mg_flag < 0)
                {   
                    printf("non merged gname:%s\n",tmp->gname);
                    XXX++;
           }
                if (tmp->mg_flag >= 0)
                {   
                    printf("merged gname:%s, merged graph: %d\n",tmp->gname,tmp->mg_flag);
                    YYY++;
                }
                tmp = tmp->next;
            }
        }
        printf(" total non merged graphs: %d mg0 cnt: %d\n",XXX,YYY);
#endif
    }
    return;
}
#endif

void cavOctHfaFreeGmdata()
{
    int i;
    GMDATA *tmp = NULL, *tmp1;

    for(i=0;i<=5;i++)
    {
        if(i == 5)
            // non TCP -- UDP,ICMP and IP    
            tmp = global_graph_meta_data;
        else
            tmp = pm_type_list[i];
        while((tmp != NULL))
        {
            tmp1 = tmp->next;
            free(tmp);
            tmp = tmp1;
        }
    }
}

#ifdef CAV_OCT_HFA_GCOMPILE
void cavOctHfaGcompile()
{
    int i;
    GMDATA *tmp;
    char buf[400];

    cavOctHfaParse();
#ifndef STATIC_CACHE
    cavOctHfaDump();
    if (cavOctHfaSort())
    {   /* Exit, no fast patterns */
        printf("No Fast Patterns\n");
        return;
    }
    cavOctHfaGraphMerge();
#endif

#ifndef STATIC_CACHE
    MDATA *tmp2;
    tmp2 = global_meta_data[8];  // global_meta_data[8] is TCP_ANYANY LIST 
    while (tmp2 != NULL)
    {
        if(tmp2->pm_type == 0)
            break;
        else
            tmp2 = tmp2->next;
    }

	int pat_cnt_tany;
    int tot_len_tany;
    char tany_gname[41];
    if(tmp2 != NULL)
    {
        pat_cnt_tany = tmp2->npat;
        tot_len_tany = tmp2->tot_len;
        strcpy(tany_gname,tmp2->gname);
    }
    else
    {   
        pat_cnt_tany = TotPatCnt(pm_type_list[0])/5 + 1;
        tot_len_tany = TotPatLen(pm_type_list[0])/10 + 1;
        strcpy(tany_gname,"no_tany");
    }

    int pat_base = (pat_cnt_tany < 10) ?  (pat_cnt_tany/2 + pat_cnt_tany%2):(pat_cnt_tany/10);
    int tot_base = (tot_len_tany < 40) ? (tot_len_tany/4 + tot_len_tany%2):(tot_len_tany/40);
    //Default is cn68xx
    uint32_t max_tot_cache = 16384; 
    uint32_t max_cache = 2048 , min_cache = 256, tot_cache = 0, cache_over = 0; // MAX :- 8*256 and MIN :- 1*256

    if (!strcmp(STRING(HFAC_TARGET), "cn68xx"))
    {
        max_tot_cache = 16384; 
        max_cache = 2048;
    }
    else if (!strcmp(STRING(HFAC_TARGET), "cn70xx"))
    {
        max_tot_cache = 4096; 
        max_cache = 1024; // MAX :- 4*256 and MIN :- 1*256
    }
//SNORTXL:: warning fix for x86
#ifndef CAV_OCT_HFA_GCOMPILE
    uint32_t max_break_limit = (max_hfa_len > 0)?max_hfa_len:-1;
#endif
    // Assign proper cache
    if(tmp2 != NULL)
        tot_cache += 512; // Cache for TCP-ANYANY

    for(i=4;i>=0;i--)
    {
        if(i > 0)
        {
            tmp = pm_type_list[i];
            while(tmp != NULL)
            {
                if(!cache_over && strcmp(tany_gname,tmp->gname) && (tmp->mg_flag < 0))
                {
                    if(tmp->npat >= pat_base)
                        tmp->cache = min(2*min_cache, max_tot_cache - tot_cache);
                    else
                        tmp->cache = min(1*min_cache, max_tot_cache - tot_cache);
                    tot_cache += tmp->cache;
                    if(tot_cache >= max_tot_cache)
                        cache_over = 1;
                }
                else
                {
                    if(strcmp(tany_gname,tmp->gname))
                        tmp->cache = 0;
                    else
                        tmp->cache = 512;
                }
                tmp = tmp->next;
            }
        }
        else
        {
            tmp = pm_type_list[i];
            while(tmp != NULL)
            {
                if(!cache_over && strcmp(tany_gname,tmp->gname) && (tmp->mg_flag < 0))
                {
                    if((tmp->npat - pat_cnt_tany) >= pat_base)
                    {
                        tmp->cache = ((tmp->npat - pat_cnt_tany)/pat_base)*min_cache;
                        if((tmp->cache < 1024) && ((tmp->tot_len - tot_len_tany) >= tot_base))
                            tmp->cache = 1024; // 4*min_cache
                        tmp->cache = max(min_cache, tmp->cache);
                        tmp->cache = min(max_cache, tmp->cache);
                        tmp->cache = min(tmp->cache,max_tot_cache - tot_cache);
                    }
                    else
                    {
                        tmp->cache = min(1*min_cache, max_tot_cache - tot_cache);
                        if((tmp->tot_len - tot_len_tany) >= tot_base)
                            tmp->cache = 1024; // 4*min_cache
                        tmp->cache = min(tmp->cache,max_tot_cache - tot_cache);
                    }
                    tot_cache += tmp->cache;
                    if(tot_cache >= max_tot_cache)
                        cache_over = 1;
                }
                else
                {
                    if(strcmp(tany_gname,tmp->gname))
                        tmp->cache = 0;
                    else
                        tmp->cache = 512;
                }
                tmp = tmp->next;
            }
        }
            
    }

    for (i = 0;i < 12;i++)
    {
        if(!cache_over)
        {
            if(mg_list[i].alive == 0)
                break;
            else
            {
                if (mg_list[i].common_pat_cnt == pat_cnt_tany)
                {
                    mg_list[i].cache = ((mg_list[i].npat - pat_cnt_tany)/pat_base)*min_cache;
                    mg_list[i].cache = max(min_cache, mg_list[i].cache);
                    mg_list[i].cache = min(max_cache, mg_list[i].cache);
                    mg_list[i].cache = min(mg_list[i].cache,max_tot_cache - tot_cache);
        }
        else
                    mg_list[i].cache += min(512, max_tot_cache - tot_cache);

                tot_cache += mg_list[i].cache;
                if(tot_cache >= max_tot_cache)
                    cache_over = 1;
            }
        }
    }

    // non TCP -- UDP,ICMP and IP    
    tmp = global_graph_meta_data;
    while(tmp != NULL)
    {
            tmp->cache = 0;
        tmp = tmp->next;
    }

    // Fill the redundant cache until the cache is over/exhausted
    while (!cache_over)
    {
        for(i=0;i<=5;i++)
        {
            if(i == 5)
                // non TCP -- UDP,ICMP and IP    
                tmp = global_graph_meta_data;
            else
        tmp = pm_type_list[i];
        while((tmp != NULL) && (tot_cache < max_tot_cache))
        {
            if(tmp->mg_flag < 0)
            {
                tmp->cache += 256;
                tot_cache += 256;
                }

                if(tot_cache >= max_tot_cache)
                {
                    cache_over = 1;
                    break;
            }
            tmp = tmp->next;
        }
    }

        for (i = 0;i < 12;i++)
        {
            if(mg_list[i].alive == 0)
                break;
    else
    {
                mg_list[i].cache += min(512, max_tot_cache - tot_cache);
                tot_cache += min(512,max_tot_cache - tot_cache);
    }
   
            if(tot_cache >= max_tot_cache)
            {
                cache_over = 1;
                break;
            }
        }
    }
    /* remove the existing graphs */
    if(tot_cache > max_tot_cache)
        printf(" Error: total_cache allocated exceeded max limit: %d\n",tot_cache);
    else
        printf("Total cache allotted %d  Unutilized Cache: %d\n",tot_cache, (max_tot_cache - tot_cache));
#endif
   
    snprintf(buf, sizeof(buf)-1, "echo ' ##SCRIPT TO GENERATE GRAPHS '>%s",hfa_cmd_pool);
    system(buf);

    snprintf(buf, sizeof(buf)-1, "echo 'rm -f %s*'>>%s",graphpath, hfa_cmd_pool);
    system(buf);
    for(i = 0;i<=PM_TYPE__MAX;i++)
    {
        if(i == PM_TYPE__MAX)
            tmp = global_graph_meta_data;
        else
            tmp = pm_type_list[i];
        while(tmp != NULL)
        {
            if (tmp->mg_flag < 0)
            {
                if(tmp->cache == 0)
                    snprintf(buf, sizeof(buf)-1, "echo 'hfac -out %s%s -input %s%s.txt -target %s -memonly -regex'>>%s",graphpath, tmp->gname, pfpath, tmp->gname, STRING(HFAC_TARGET), hfa_cmd_pool);
                else
                    snprintf(buf, sizeof(buf)-1, "echo 'hfac -out %s%s -input %s%s.txt -target %s -cachesize %d -regex -dfa'>>%s",graphpath, tmp->gname, pfpath, tmp->gname, STRING(HFAC_TARGET), tmp->cache, hfa_cmd_pool);
                system(buf);
            }
            tmp = tmp->next;
        }
    }
    for (i = 0;i < 12;i++)
    {
        if(mg_list[i].alive == 0)
            break;
        else
        {
            if(mg_list[i].cache == 0)
                snprintf(buf, sizeof(buf)-1, "echo 'hfac -out %smg%d -input %smg%d.txt -target %s -memonly -regex'>>%s",graphpath, i, pfpath, i, STRING(HFAC_TARGET), hfa_cmd_pool);
            else
                snprintf(buf, sizeof(buf)-1, "echo 'hfac -out %smg%d -input %smg%d.txt -target %s -cachesize %d -regex -dfa'>>%s",graphpath, i, pfpath, i, STRING(HFAC_TARGET),  mg_list[i].cache, hfa_cmd_pool);
            system(buf);
        }
    }
    snprintf(buf, sizeof(buf)-1, "echo 'wait'>>%s", hfa_cmd_pool);
    system(buf);
    snprintf(buf, sizeof(buf)-1,"echo 'echo 'Compressing the Graphs...''>>%s", hfa_cmd_pool);
    system(buf);
                    
    FILE * fp = fopen(hfa_cmd_pool,"r");
    if (fp == NULL)
        ERROR("script file %s doesn't exist\n",hfa_cmd_pool);
    else
    {
        snprintf(buf, sizeof(buf)-1, "sh %s", hfa_cmd_pool);
        system(buf);
        snprintf(buf, sizeof(buf)-1, "gzip  %s*",graphpath);
        system(buf);
        snprintf(buf, sizeof(buf)-1, "chmod -R 644  %s*",graphpath);
        system(buf);
        snprintf(buf, sizeof(buf)-1, "rm -rf %s*",pfpath);
        system(buf);
        fclose(fp);
    }
    return;
}
#endif
