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
                                                                                  
*This Software,including technical data,may be subject to U.S. export control 
* laws, including the U.S. Export Administration Act and its  associated          
* regulations, and may be subject to export or import  regulations in other       
* countries.                                                                      
                                                                                  
* TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"        
* AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS OR       
*WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH RESPECT TO   
*THE SOFTWARE,INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR  
* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF     
* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
***********************license end**************************************/ 


#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "cvmx.h"
#include "cvmx-csr-db.h"
#include "cvmx-platform.h"
#include "cvmx-helper.h"
#include "misc_defs.h"
#if 0000
#include "cvmx-config.h"
#include "global-config.h"
#include "ip-config.h"

#include "cvmx.h"
#include "cvmx-spinlock.h"
#include "cvmx-fpa.h"
#include "cvmx-pip.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-dfa.h"
#include "cvmx-pow.h"
#include "cvmx-gmx.h"
#include "cvmx-sysinfo.h"
#include "cvmx-coremask.h"
#include "cvmx-malloc.h"
#include "cvmx-bootmem.h"
#include "cvmx-packet.h"
#include "cvmx-helper.h"
#include "cvmx-scratch.h"
#include "cvmx-tim.h"
#include "cvmx-uart.h"


#include "cvm-common-errno.h"
#include "cvm-common-wqe.h"
#include "cvm-common-defs.h"
#include "cvm-common-misc.h"
#include "cvm-common-fpa.h"
#include "cvm-common-rnd.h"

#include "cvm-enet.h"

#include <lib_octeon_shared.h>
#include <octeon_mem_map.h>


#include "octeon-pci-console.h"


#include "cvm-enet.h"
#include "cvm-enet-arp.h"
#include "cvm-enet-config.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-route.h"
#include "cvm-ip-sockio.h"
#include "cvm-ip-icmp.h"
#include "cvm-ip-var.h"
#include "cvm-ip-in-var.h"
#include "cvm-tcp.h"
#include "cvm-ip-inline.h"
#include "cvm-ip-config.h"


#ifdef INET6
#include "cvm-in6.h"
#include "cvm-ip6.h"
#include "cvm-ip6-var.h"
#include "cvm-in6-var.h"
#include "cvm-nd6.h"
#include "cvm-scope6-var.h"
#include "cvm-ip6-inline.h"
#endif /* INET6 */


#include "cvmx-csr-db.h"
#endif


/* Maximum number of args in (argc, argv[]) pair */
#define CLI_MAX_ARGS          16

/* Maximum length of stringified IP address */
#define CLI_IPSTR_LEN         20

#define CLI_PROMPT            "SnortXL> "

/* Maximum number of CLI commads */
#define CLI_MAX_VERBS         32
extern CVMX_SHARED int used_port_sets;
extern CVMX_SHARED unsigned long int port_set[MAX_PORT_SETS][2];

//extern CVMX_SHARED volatile unsigned long int port1;
//extern CVMX_SHARED volatile unsigned long int port2;

void cli_main(char *inp);

/*
 * Data for tracking registered command line verbs
 */
struct {
    char *verb;
    void (*proc)(int, char *[]);
} cli_registered_verbs[CLI_MAX_VERBS];



#ifndef CONFIG_PCI_CONSOLE

static int cli_uart_printf(int uart_index, const char *format, ...) 
    __attribute__ ((format(printf, 2, 3)));
#endif


/*
 * If we want to use serial console we need to redefine printf & putchar
 * so they write to UART memory directly for output.
 *
 * If this is not done undesirable prefix shows up at the beginning of 
 * each line.
 */
#define printf(format, ...) cli_uart_printf(0, format, ##__VA_ARGS__)

#undef putchar
#define putchar(c) printf("%c", c)

#define fflush(a)   

static uint64_t
cli_convert_number(const char *str)
{
    unsigned long long result;
    if ((str[0] == '0') && (str[1] == 'x'))
    {
        if (sscanf(str+2, "%llx", &result) != 1)
            result = 0;
    }
    else
    {
        if (sscanf(str, "%lli", &result) != 1)
            result = 0;
    }
    return result;
}

static void
cli_csr_usage()
{
    printf("\n"
           "csr <CSR> [value] [<CSR> [value] ...]"
           "  -  Read or write a CSR by name.\n"
           "\n"
           "    <CSR>   Name of register to read or write. Case is ignored.\n"
           "    value   If present, write this value to the CSR. Otherwise do a read.\n"
           "            The value can be in decimal of hex (0x...).\n"
           "\n"
           "    If <CSR> is a partial name, the list of CSRs starting with it are displayed.\n"
           "\n");
}

/**
 * cli_csr
 *
 * This function implements "csr" command to peek/poke 
 * system registers
 *
 * @argv    UNIX-like arguments
 * @argc    number of entries
 */
static void
cli_csr(int argc, char *argv[])
{
#ifndef SDK_3_1
    const char *csr_name;
    uint32_t model;
    int index;


    if (argc == 1) {
        cli_csr_usage();
        return; 
    }

    CVMX_MF_COP0(model, COP0_PRID);

    index = 1;
    while (index < argc) {

        csr_name = argv[index];

        /* Find the CSR address from the name. If this fails it will return 0 */
        const CVMX_CSR_DB_ADDRESS_TYPE *csr = cvmx_csr_db_get(model, csr_name);

        if (csr) {
            /* We don't support CSRs that aren't in IO space (bit 48 set) */
            if (((csr->address & (1ull<<48)) == 0) &&
                (csr->type != CVMX_CSR_DB_TYPE_PCICONFIGEP) &&
                (csr->type != CVMX_CSR_DB_TYPE_PCICONFIGRC) &&
                (csr->type != CVMX_CSR_DB_TYPE_SRIOMAINT)) {
                printf("CSR %s: This utility can't access CSRs of this type\n", csr->name);
                return;
            }

            /* Determine if we're doing a read or a write */
            if ((index + 1 < argc) && (argv[index+1][0] >= '0') && (argv[index+1][0] <= '9')) {
                uint64_t value = cli_convert_number(argv[index+1]);

                if (csr->widthbits == 32) {
                    printf("CSR: write to 32-bit wide regs is not supported\n");
                } else {
                    cvmx_write_csr(CVMX_ADD_IO_SEG(csr->address), value);
                }
                index += 2;
            } else {
                uint64_t value;

                if (csr->widthbits == 32) {
                    printf("CSR: read from 32-bit wide regs is not supported\n");
                } else {
                    value = cvmx_read_csr(CVMX_ADD_IO_SEG(csr->address));
                    cvmx_csr_db_decode_by_name(model, csr->name, value);
                }
                index++;
            }
        } else {
            printf("CSR not found in list. Looking for prefix \"%s\"\n", csr_name);
            cvmx_csr_db_display_list(model, csr_name);
            index++;
        }
    }
#else
//Need to have code for SDK-3.1
#endif
}

/**
 * cli_show_sysinfo
 *
 * This function displays information about HW/SW system resources and 
 * implements "sysinfo" CLI command
 *
 * @argv    UNIX-like arguments
 * @argc    number of entries
 */
void
cli_show_sysinfo()
{
    uint64_t pow_total = 0;
    uint64_t pow_qoslvl[8];
    int qos=0;
    int i;


    pow_total = cvmx_read_csr(CVMX_POW_IQ_COM_CNT);
    for (qos = 0; qos < 8; qos++) {
        pow_qoslvl[qos] = cvmx_read_csr(CVMX_POW_IQ_CNTX(qos));
    }

    printf("\nTotal entries in POW = %llu\n", CAST64(pow_total));
    for (qos = 0; qos < 8; qos++) {
        printf("  QOS[%d] = %llu\n", qos, CAST64(pow_qoslvl[qos]));
    }

    printf("\nFPA POOLS\n");
    for (i = 0; i < 8; i++) {
        printf("   POOL: %d, free pages: 0x%llx\n", 
	        i, CAST64(cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(i))));
    }

    printf("\n");
}

/*
 * Argument passing in standard UNIX tradition: argv[0] 
 * command verb rest of the array - arguments.
 *
 * Processing subtree of "help" command
*/
static void
cli_help(int argc, char *argv[])
{
    int i;

    printf("\nCurrently supported commands:\n\n");

    for (i = 0; i < CLI_MAX_VERBS; i++) {
        if (cli_registered_verbs[i].verb) {
            printf("    %s\n", cli_registered_verbs[i].verb);
        }
    }
    printf("\n");
}

/*
 * cli_reboot
 *
 * This function processes subtree of "reboot" CLI command
 *
 * @argc    Number of entries in the vector
 * @argv    UNIX-like main() arguments vector
 *
 * Syntax:
 *    reboot 
 */
static void
cli_reboot(int argc, char *argv[])
{
    if (argc != 1) {
        goto usage;
    }

    cvmx_reset_octeon();

    return;

usage:
    printf("\nreboot  -- Soft reset of Octeon system\n");
    printf("\n");
}

/*
 * cli_exit
 *
 * This function processes subtree of "exit" CLI command
 *
 * @argc    Number of entries in the vector
 * @argv    UNIX-like main() arguments vector
 *
 * Syntax:
 *    exit
 */
static void
cli_exit(int argc, char *argv[])
{
    if (argc != 1) {
        goto usage;
    }

    printf("\nDisabling CLI till next reboot...\n");

    return;

usage:
    printf("\nexit -- permanently disable CLI till next reboot\n");
    printf("\n");
}
extern CVMX_SHARED volatile int printStats;
static void periodicStats(int argc, char *argv[])
{
    printStats = 1;
}

static void setTogglePorts(int argc, char *argv[])
{
        char * err;
        unsigned long int tmp1,tmp2;
        if(argc != 3)
        {
                printf("usage: settoggleports <port1> <port2>\n"
                       "\twhere ports port1 and port2 are toggling ports\n");
                return;
        }
        tmp1 = strtol(argv[1],&err,0);
        if(*err)
        {
                printf("\tInvalid port1 number : %s\n",err);
                return;
        }
        tmp2 = strtol(argv[2],&err,0);
        if(*err)
        {
                printf("\tInvalid port2 number : %s\n",err);
                return;
        }

        if (used_port_sets != MAX_PORT_SETS)
        {
            port_set[used_port_sets][0] = tmp1;
            port_set[used_port_sets][1] = tmp2;
            printf("\tToggling ports are %u <-> %u\n",tmp1,tmp2);
            used_port_sets ++;
         }

        printf("\tToggling ports are %u <-> %u\n",tmp1,tmp2);
}

static void showPorts(int argc, char *argv[])
{

    int i,j,mode,num_ports,cnt=0;
    int no_of_interfaces = cvmx_helper_get_number_of_interfaces();
    cvmx_helper_link_info_t link_info;
    for (i = 0; i < no_of_interfaces; i++)
    {
        mode = cvmx_helper_interface_get_mode(i);
        num_ports = 0;
       
        switch (mode)
        {
            case CVMX_HELPER_INTERFACE_MODE_RGMII:
              printf("Interface %d (RGMII) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_GMII:
              printf("Interface %d (GMII) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_SPI:
              printf("Interface %d (SPI) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_XAUI:
              printf("Interface %d (XAUI) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_RXAUI:
              printf("Interface %d (RXAUI) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_SGMII:
              printf("Interface %d (SGMII) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_ILK:
              printf("Interface %d (ILK) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_PCIE:
              printf("Interface %d (PCIE) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_PICMG:
              printf("Interface %d (PCIMG) Ports:",i);
              cvmx_helper_interface_probe(i);
              num_ports = cvmx_helper_ports_on_interface(i);
              goto port_lbl;
            case CVMX_HELPER_INTERFACE_MODE_DISABLED:
              num_ports = 0;
              cnt++;

port_lbl:
              for (j = 0; j < num_ports; j++)
              {
                  printf(" %d",cvmx_helper_get_ipd_port(i,j));
                  link_info = cvmx_helper_link_get(cvmx_helper_get_ipd_port(i,j));
                  if(j != num_ports-1)
                  {
                      if(link_info.s.link_up)
                          printf(" (UP),");
                      else
                          printf(",");
                  }
                  else
                  {
                      if(link_info.s.link_up)
                          printf(" (UP)\n");
                      else
                          printf("\n");
                  }
              }
              break;
            default:
              cnt++;
              break;
       
        }
    }
    if(cnt==no_of_interfaces)
    {   
        printf("No Ports are available\n");
        return;
    }
#if 0
    if(port1 != port2)
        printf("\nPort Toggling is enabled between ports %u and %u:\n",port1,port2);
    else
        printf("\nPort Toggling is disabled\n");
#endif
}

/*
 * Reading data from PCI console...
 */
#define CLI_MAX_INPUT   256

#ifdef CONFIG_PCI_CONSOLE
static uint64_t pci_console_desc_addr = 0;
#endif /* CONFIG_PCI_CONSOLE */

char cli_pci_buf[CLI_MAX_INPUT];
int  cli_pci_idx = 0;
static int char_count = 0;

static void
cli_show_prompt()
{
    printf(CLI_PROMPT);
    fflush(NULL);
    char_count = 0;
}

/*
 * Register function callback associated with particular verb
 */
static void
cli_register(char *verb, void (*f)(int, char *[]))
{
    int found = -1;
    int i;

    for (i = 0; i < CLI_MAX_VERBS; i++) {
        if (cli_registered_verbs[i].verb == NULL) {
            found = i;
            break;
        }
    }
    if (found == -1)
        return;

    cli_registered_verbs[found].verb = verb;
    cli_registered_verbs[found].proc = f;
}

void
cli_init(void)
{
    int i;

#ifdef CONFIG_PCI_CONSOLE
    /* Initialize PCI command line block */
    cvmx_bootmem_named_block_desc_t *block_desc = 
        cvmx_bootmem_find_named_block(OCTEON_PCI_CONSOLE_BLOCK_NAME);
    pci_console_desc_addr = block_desc->base_addr;
#endif /* CONFIG_PCI_CONSOLE */

    /* Initialize registered verbs */
    for (i = 0; i < CLI_MAX_VERBS; i++) { 
        cli_registered_verbs[i].verb = NULL;
        cli_registered_verbs[i].proc = NULL;
    }


    cli_register("help", cli_help);
    cli_register("csr", cli_csr);
    cli_register("reboot", cli_reboot);
    cli_register("stats", periodicStats);
    cli_register("settoggleports",setTogglePorts);
    cli_register("showports",showPorts);

    cli_show_prompt();
}

void
cli_main(char *inp)
{
    char buf[CLI_MAX_INPUT]; // local buffer copy
    char *argv[CLI_MAX_ARGS] = {NULL, };
    char *s;
    int argc = 0;
    int len;
    int i;


    if ((len = strlen(inp)) == 0) {
        return;
    }

    /* Local copy needed here as we may call it with static string */
    strcpy(buf, inp);
    inp = &buf[0];
    s = inp;

    while (s - inp < len && argc < CLI_MAX_ARGS) {

        while (*s && *s == ' ') s++;

        if (!*s) break;
    
        argv[argc++] = s;

        while (*s && *s != ' ') s++;

        *s++ = 0;
    }

    for (i = 0; i < CLI_MAX_VERBS; i++) {
        if (cli_registered_verbs[i].verb && 
            !strcmp(argv[0], cli_registered_verbs[i].verb)) {
            cli_registered_verbs[i].proc(argc, argv);
            return;
        }
    }
    printf("%s: Command unknown\n", argv[0]);
}

#ifndef CONFIG_PCI_CONSOLE
/**
 * Get a single byte from serial port.
 *
 * @param uart_index Uart to read from (0 or 1)
 * @return The byte read
 */
static uint8_t
cli_uart_read_byte(int uart_index)
{
    /* 
     * Read and return the data. Zero will be returned if 
     * there is no data.
     */
    cvmx_uart_lsr_t lsrval;

    lsrval.u64 = cvmx_read_csr(CVMX_MIO_UARTX_LSR(uart_index));

    if (lsrval.s.dr) {
        return (cvmx_read_csr(CVMX_MIO_UARTX_RBR(uart_index)));
    } else {
        return (0);
    }
}

/**
 * Put a single byte to uart port.
 *
 * @param uart_index Uart to write to (0 or 1)
 * @param ch         Byte to write
 */
static void
cli_uart_write_byte(int uart_index, uint8_t ch)
{
    cvmx_uart_lsr_t lsrval;

    /* Spin until there is room */
    do {
        lsrval.u64 = cvmx_read_csr(CVMX_MIO_UARTX_LSR(uart_index));
        if ((lsrval.s.thre == 0))
            cvmx_wait(10000);   /* Just to reduce the load on the system */
    }
    while (lsrval.s.thre == 0);

    /* Write the byte */
    cvmx_write_csr(CVMX_MIO_UARTX_THR(uart_index), ch);
}

/**
 * Version of printf for direct uart output. This bypasses the
 * normal per core banner processing.
 *
 * @param uart_index Uart to write to
 * @param format     printf format string
 * @return Number of characters written
 */
static int
cli_uart_printf(int uart_index, const char *format, ...)
{
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    int i = result;
    char *ptr = buffer;
    while (i > 0)
    {
        if (*ptr == '\n')
            cli_uart_write_byte(uart_index, '\r');
        cli_uart_write_byte(uart_index, *ptr);
        ptr++;
        i--;
    }
    return result;
}
#endif /* !CONFIG_PCI_CONSOLE */

void
cli_readline(void)
{
    char read_buffer[CLI_MAX_INPUT];
    int nchar;
    int i;
    static int first_time = 1;


    if (first_time) {
        first_time = 0; 
        putchar('\n');
        cli_show_prompt();
        printf("        + + + WELCOME TO SNORTXL CONSOLE! + + +\n");
        cli_show_prompt();
        putchar('\n');
        cli_show_prompt();
        printf("  Arrow keys are not supported, use <Back-Space> for editing!\n");
        cli_show_prompt();
        printf("  Type 'help' for list of available commands\n");
        cli_show_prompt();
        putchar('\n');
        cli_show_prompt();
    }

#ifdef CONFIG_PCI_CONSOLE

    nchar = octeon_pci_console_read(pci_console_desc_addr, 
                0, read_buffer, CLI_MAX_INPUT,  OCT_PCI_CON_FLAG_NONBLOCK);

#else /* Serial console */
    uint8_t c;

    nchar = 0;

    while ((c = cli_uart_read_byte(0))) {
        if(char_count == 0 && c == 8)
                continue;
        if(c == '\n')
                char_count = 0;
        else if(c != 8)
                char_count++;
        else
                char_count--;
        read_buffer[nchar++] = c;
    }

#endif /* CONFIG_PCI_CONSOLE */


    for (i = 0; i < nchar; i++) {

        if (read_buffer[i] == 127 || read_buffer[i] == 8) {
            putchar(0x8);
            putchar(0x20);
            putchar(0x8);
            fflush(NULL);
            cli_pci_idx--;
            continue; 
        }

        putchar(read_buffer[i]);
        fflush(NULL);

        if (read_buffer[i] == 0xd) {
            printf("\n");

            cli_pci_buf[cli_pci_idx++] = 0;

            cli_main(cli_pci_buf);

            cli_show_prompt();

            cli_pci_idx = 0;

            continue;
        }
        cli_pci_buf[cli_pci_idx++] = read_buffer[i];
    }
}
