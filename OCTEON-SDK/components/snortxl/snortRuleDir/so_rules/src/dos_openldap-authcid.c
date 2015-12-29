/*
 * openldap buffer overflow dos attempt
 * 
 * Copyright (C) 2006 Sourcefire, Inc. All Rights Reserved
 * 
 * Writen by Patrick Mullen <pmullen@sourcefire.com> 
 *
 * This file may contain proprietary rules that were created, tested and
 * certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
 * rules that were created by Sourcefire and other third parties and
 * distributed under the GNU General Public License (the "GPL Rules").  The
 * VRT Certified Rules contained in this file are the property of
 * Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
 * The GPL Rules created by Sourcefire, Inc. are the property of
 * Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
 * Reserved.  All other GPL Rules are owned and copyrighted by their
 * respective owners (please see www.snort.org/contributors for a list of
 * owners and their respective copyrights).  In order to determine what
 * rules are VRT Certified Rules or GPL Rules, please refer to the VRT
 * Certified Rules License Agreement.
 */


#include "sf_snort_plugin_api.h"
#include "sf_snort_packet.h"

/* declare detection functions */
static int ruleVD_OPENLDAPeval(void *p);

static RuleReference ruleVD_OPENLDAPref0 = 
{
    "bugtraq", /* type */
    "20939" /* value */
};
static RuleReference ruleVD_OPENLDAPcve =
{
    "cve", /* type */
    "2006-5779" /* value */
};


static RuleReference *ruleVD_OPENLDAPrefs[] =
{
    &ruleVD_OPENLDAPref0,
    &ruleVD_OPENLDAPcve,
    NULL
};

// missing features ends up having the rule built in a disabled state
#ifdef MISSING_DELETED
static ContentInfo ruleVD_OPENLDAPcontent_missing_feature =
{
    (u_int8_t *) VRT_RAND_STRING, /* pattern that should not invoke detection */
    0, /* depth */
    0, /* offset */
    CONTENT_BUF_NORMALIZED | CONTENT_FAST_PATTERN, /* flags */
    NULL, /* holder for boyer/moore PTR */
    NULL, /* more holder info - byteform */
    0, /* byteform length */
    0 /* increment length*/
};

static RuleOption ruleVD_OPENLDAPmissing_feature =
{
    OPTION_TYPE_CONTENT,
    {
        &ruleVD_OPENLDAPcontent_missing_feature
    }
};
#else
static FlowFlags ruleVD_OPENLDAPflow =
{
    FLOW_ESTABLISHED|FLOW_TO_SERVER
};

static RuleOption ruleVD_OPENLDAPoption0 =
{
    OPTION_TYPE_FLOWFLAGS,
    {
        &ruleVD_OPENLDAPflow
    }
};

static ContentInfo ruleVD_OPENLDAPcontent =
{
    (u_int8_t *)"|30|",       /* pattern to search for */
    1,                      /* depth */
    0,                      /* offset */
    CONTENT_BUF_NORMALIZED,                      /* flags */
    NULL,                   /* holder for boyer/moore info */
    NULL,                   /* holder for byte representation of "NetBus" */
    0,                      /* holder for length of byte representation */
    0                       /* holder of increment length */
};

static RuleOption ruleVD_OPENLDAPoption1 =
{
    OPTION_TYPE_CONTENT,
    {
        &ruleVD_OPENLDAPcontent
    }
};
#endif

RuleOption *ruleVD_OPENLDAPoptions[] =
{
#ifdef MISSING_DELETED
    &ruleVD_OPENLDAPmissing_feature,
#else
    &ruleVD_OPENLDAPoption0,
    &ruleVD_OPENLDAPoption1,
#endif
    NULL
};

Rule ruleVD_OPENLDAP = {
   /* rule header */
   {
       IPPROTO_TCP, /* proto */
       "any", /* SRCIP     */
       "any", /* SRCPORT   */
       0, /* DIRECTION */
       HOME_NET, /* DSTIP     */
       "389", /* DSTPORT   */
   },
   /* metadata */
   { 
       3,  /* genid (HARDCODED!!!) */
       13416, /* sigid 69e4e9b3-9ce8-4f40-ab8e-cfeb46a77650 */
       3, /* revision 7f3b4b4a-3cce-4767-b2cf-65f48bdd0f3e */
   
       "attempted-dos", /* classification, generic */
       0,  /* hardcoded priority XXX NOT PROVIDED BY GRAMMAR YET! */
       #ifdef MISSING_DELETED
          "DELETED DOS openldap authcid name denial of service attempt - DISABLED",     /* message */
       #else
          "DELETED DOS openldap authcid name denial of service attempt",     /* message */
       #endif
       ruleVD_OPENLDAPrefs /* ptr to references */
       ,NULL
   },
   ruleVD_OPENLDAPoptions, /* ptr to rule options */
   &ruleVD_OPENLDAPeval, /* ptr to rule detection function */
   #ifdef MISSING_DELETED
   1, /* force rule not to load by setting it to initialized. */
   #else
   0, /* am I initialized yet? */
   #endif
   0, /* number of options */
   0  /* don't alert */
};


/* detection functions */

/* process_val

   Returns the u_int32_t value contained at the pointer after skipping
   preceeding NULs.  Returns an error if the data does not fit into
   a u_int32_t.
*/
static int process_val(const u_int8_t *data, u_int32_t data_len, u_int32_t *retvalue) {
   u_int32_t actual_data_len, i;      
   *retvalue = 0;

   /* Jump over NULLs */
   i = 0;
   while((i < data_len) && (data[i] == 0)) {
      i++;
   }
   actual_data_len = data_len - i; 
   if(actual_data_len > 4) return(-1); /* Data doesn't fit into u_int32_t */

   /* Now find the actual value */
   for(;i<data_len;i++) {
      *retvalue += data[i]<<(8*(data_len - i - 1));
   }

   return(0);
}


/* skip_over_data
 
   Given an SFSnortPacket and a pointer to an index into the data,
   this function will parse the size field at that index and move
   the index to point after the size field and the data it describes.

   Size fields are as described in BER encoding.
*/
static int skip_over_data(SFSnortPacket *sp, u_int32_t *current_byte) {
   u_int32_t width = 0, value = 0;
   int retval = 0;

   const u_int8_t *beg_of_payload, *end_of_payload;
   u_int32_t payload_len;

   if(getBuffer(sp, CONTENT_BUF_NORMALIZED, &beg_of_payload, &end_of_payload) <= 0)
      return RULE_NOMATCH;

   payload_len = end_of_payload - beg_of_payload;

   if(beg_of_payload[*current_byte] & 0x80) {
      width = beg_of_payload[*current_byte] & 0x0F;
      (*current_byte)++;

      if(*current_byte >= payload_len - width)
         return(-1); 

      retval = process_val(&(beg_of_payload[*current_byte]), width, &value);
      if(retval < 0)
         return(-1);            /* width is > 4 */
      *current_byte += width;   /* width of data width specifier */
      *current_byte += value;   /* width of data itself */
   }  else {
      *current_byte += beg_of_payload[*current_byte] + 1;
   }

   return(0);
}


/* Detection algorithm --
   We're looking for more than 0x0101 (257) bytes of data in the authentication
   mechanism data field.  To do this, we minimally parse LDAP bind packets to
   get to the data and ensure we encounter the correct data types along the way.

   0x30 - Universal Sequence
   [Message size] - no data type, just a size
   [Message ID] - int data type (0x02)

   0x60 - Bind request
   [Bind Request size] - no data type, just a size
   [LDAP version] - int data type (0x02)
   [DN (username)] - string data type (0x04)

   0xa3 - Extended Auth Type, SASL
   [Auth Data Size] - no data type, just a size
   [Mechanism Name] - string data type
   [Mechanism Data] - string data type -- if > 0x0101 bytes long, RULE_MATCH

   Note we don't actually care if the data is present in this
   particular packet, which reduces evasion possibilities.
*/
static int ruleVD_OPENLDAPeval(void *p) {
#ifdef MISSING_DELETED
    return RULE_NOMATCH; /* always fail */
#else
   u_int32_t current_byte = 0;
   u_int32_t width, value;
   int retval;

   const u_int8_t *cursor_normal, *beg_of_payload, *end_of_payload;
   u_int32_t payload_len;

   SFSnortPacket *sp = (SFSnortPacket *) p;

   if(sp == NULL)
      return RULE_NOMATCH;

   if(sp->payload == NULL)
      return RULE_NOMATCH;

   /* call flow match */
   if (checkFlow(sp, ruleVD_OPENLDAPoptions[0]->option_u.flowFlags) <= 0 )
      return RULE_NOMATCH;

   /* call content match */
   if (contentMatch(sp, ruleVD_OPENLDAPoptions[1]->option_u.content, &cursor_normal) <= 0) {
      return RULE_NOMATCH;
   }

   if(getBuffer(sp, CONTENT_BUF_NORMALIZED, &beg_of_payload, &end_of_payload) <= 0)
      return RULE_NOMATCH;

   payload_len = end_of_payload - beg_of_payload;

   if(payload_len <= 26)   /* Minimum SASL bind request length (minus the auth data) */
      return RULE_NOMATCH;

   /* our contentMatch already assures us the first byte is \x30, so just jump over it */
   current_byte++;

   /* Begin packet structure processing */
   /* Packet length (only care about width of the specifier) */
   if(beg_of_payload[current_byte] & 0x80) {
      current_byte += beg_of_payload[current_byte] & 0x0F; 
   }
   current_byte++;

   /* Message number (only care about width of the specifier) */
   if(current_byte >= payload_len - 22)  
      return RULE_NOMATCH;

   if(beg_of_payload[current_byte] != 0x02) /* Int data type */
      return RULE_NOMATCH;
   current_byte++;

   /* Skip over int width and the int value */
   if(skip_over_data(sp, &current_byte) < 0)
      return RULE_NOMATCH;

   if(current_byte >= payload_len - 19) 
      return RULE_NOMATCH;

   /* Bind Request */
   if(beg_of_payload[current_byte] != 0x60) 
      return RULE_NOMATCH;

   current_byte++;

   /* Message length  (only care about width of the specifier) */
   if(beg_of_payload[current_byte] & 0x80) {
      current_byte += beg_of_payload[current_byte] & 0x0F; 
   }
   current_byte++;

   /* ldap version */
   if(current_byte >= payload_len - 15)
      return RULE_NOMATCH;

   /* ldap version */
   if(beg_of_payload[current_byte] != 0x02) /* Int data type */
      return RULE_NOMATCH;
   current_byte++;

   /* Skip over int width and the int value */
   if(skip_over_data(sp, &current_byte) < 0)
      return RULE_NOMATCH;

   if(current_byte >= payload_len - 12)  
      return RULE_NOMATCH;

   /* user name (DN) */
   /* 0x04 - string data type */
   if(beg_of_payload[current_byte] != 0x04) /* string data type */
      return RULE_NOMATCH;
   current_byte++;

   /* Skip over string length specifier and the string */
   if(skip_over_data(sp, &current_byte) < 0)
      return RULE_NOMATCH;

   if(current_byte >= payload_len - 10) 
      return RULE_NOMATCH;

   /* 0xA3 - Auth type: SASL */
   if(beg_of_payload[current_byte] != 0xA3)
      return RULE_NOMATCH;
   current_byte++;

   /* Auth data length - only care about width of specifier */
   if(beg_of_payload[current_byte] & 0x80) {
      current_byte += beg_of_payload[current_byte] & 0x0F;
   }
   current_byte++;

   if(current_byte >= payload_len - 6)  
      return RULE_NOMATCH;

   /* Auth Mechanism */
   /* 0x04 - string data type */
   if(beg_of_payload[current_byte] != 0x04)  /* string data type */
      return RULE_NOMATCH;
   current_byte++;

   /* Skip over string length specifier and the string */
   /* String value can be anything */
   if(skip_over_data(sp, &current_byte) < 0)
      return RULE_NOMATCH;

   if(current_byte >= payload_len - 4) 
      return RULE_NOMATCH;

   /* Auth data */
   /* 0x04 - string data type */
   if(beg_of_payload[current_byte] != 0x04)  /* string data type */
      return RULE_NOMATCH;
   current_byte++;

   /* Here we can't just jump over the value because it's what
      we're looking for. */
   /* length of string -- if 0x0400 (1024 dec) it's an exploit attempt */
   if(beg_of_payload[current_byte] & 0x80) {
      width = beg_of_payload[current_byte] & 0x0F;
      current_byte++;

      if(current_byte >= payload_len - width)
         return RULE_NOMATCH;

      retval = process_val(&(beg_of_payload[current_byte]), width, &value);
      if(retval < 0)
         return RULE_NOMATCH;  /* width is either 0 or > 4 */
      current_byte += width;   /* width of data width specifier */
      /* value equals the length of the string */
   }  else {
      value = beg_of_payload[current_byte];  /* length of the string */
      current_byte++;
   }

   if(value > 0x0101)    /* minimum length determined through testing */
      return RULE_MATCH;

   return RULE_NOMATCH;
#endif
}

/*
Rule *rules[] = {
    &ruleVD_OPENLDAP,
    NULL
};
*/

