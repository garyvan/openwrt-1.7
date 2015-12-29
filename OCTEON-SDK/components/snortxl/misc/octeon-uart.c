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
* WARRANTIES, EITHER EXPRESS,IMPLIED,STATUTORY,OR OTHERWISE,WITH RESPECT TO   
* THE SOFTWARE,INCLUDING ITS CONDITION,ITS CONFORMITY TO ANY REPRESENTATION OR  
* DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT DEFECTS, AND CAVIUM       
* SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY) WARRANTIES OF TITLE,                
* MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE,LACK OF     
* VIRUSES, ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
* CORRESPONDENCE TO DESCRIPTION. THE ENTIRE  RISK ARISING OUT OF USE OR           
* PERFORMANCE OF THE SOFTWARE LIES WITH YOU.                                      
***********************license end**************************************/ 


#include <unistd.h>
#include <cvmx.h>
#include <cvmx-spinlock.h>

#if 0000
#include "octeon-uart.h"
#endif /* 0000 */

CVMX_SHARED static cvmx_spinlock_t octeon_uart_lock =
  { CVMX_SPINLOCK_UNLOCKED_VAL };

/* Put a single byte to uart port. UART_INDEX is the uart to write to (0/1).
   CH contains the byte to write.  */
static void 
octeon_uart_write_byte (int uart_index, uint8_t ch)
{
  cvmx_uart_lsr_t lsrval;

  /* Spin until there is room */
  do
    {
      lsrval.u64 = cvmx_read_csr (CVMX_MIO_UARTX_LSR (uart_index));
    } while (lsrval.s.thre == 0);

  /* Write the byte */
  cvmx_write_csr (CVMX_MIO_UARTX_THR (uart_index), ch);
}

/* Write out the PP banner without using any C library functions to uart
   specified by UART_INDEX.  */
static void 
octeon_uart_write_banner (int uart_index)
{
  const uint64_t coreid = cvmx_get_core_num ();

  octeon_uart_write_byte (uart_index, 'P');
  octeon_uart_write_byte (uart_index, 'P');
  if (coreid < 10)
    octeon_uart_write_byte (uart_index, coreid + '0');
  else
    {
      octeon_uart_write_byte (uart_index, (coreid / 10) + '0');
      octeon_uart_write_byte (uart_index, (coreid % 10) + '0');
    }
  octeon_uart_write_byte (uart_index, ':');
  octeon_uart_write_byte (uart_index, '~');
  octeon_uart_write_byte (uart_index, 'C');
  octeon_uart_write_byte (uart_index, 'O');
  octeon_uart_write_byte (uart_index, 'N');
  octeon_uart_write_byte (uart_index, 'S');
  octeon_uart_write_byte (uart_index, 'O');
  octeon_uart_write_byte (uart_index, 'L');
  octeon_uart_write_byte (uart_index, 'E');
  octeon_uart_write_byte (uart_index, '-');
  octeon_uart_write_byte (uart_index, '>');
  octeon_uart_write_byte (uart_index, ' ');
}

void
__octeon_uart_lock (void)
{
  cvmx_spinlock_lock (&octeon_uart_lock);
}

unsigned
__octeon_uart_trylock (void)
{
  return cvmx_spinlock_trylock (&octeon_uart_lock);
}

void
__octeon_uart_unlock (void)
{
  cvmx_spinlock_unlock (&octeon_uart_lock);
}

/* Write bytes to the uart specified by UART_INDEX into BUFFER of bytes 
   in LEN.  Don't transform the original text and do not lock.  */
int 
__octeon_uart_write_raw (int uart_index, const char *buffer, size_t len)
{
  size_t ret = len;

  while (len--)
    octeon_uart_write_byte (uart_index, *buffer++);

  return ret;
}

/* Write bytes to the uart specified by UART_INDEX into BUFFER of bytes 
   in BUFFER_LEN.  */
int 
__octeon_uart_write (int uart_index, const char *buffer, size_t buffer_len)
{
  cvmx_spinlock_lock (&octeon_uart_lock);
  uart_index = 0;

  /* Just loop writing one byte at a time */
  while (buffer_len)
    {
      if (*buffer == '\n')
        octeon_uart_write_byte (uart_index, '\r');
      octeon_uart_write_byte (uart_index, *buffer);
      buffer++;
      buffer_len--;
    }

  cvmx_spinlock_unlock (&octeon_uart_lock);

  return buffer_len;
}

void octeon_uart_init()
{
	/* 
	 * force libc printf toward a dummy pci_console_write,
	 */
	extern int (*__cvmx_pci_console_write_ptr)(int, const char *, size_t);
	extern void octeon_os_set_console(int);
	__cvmx_pci_console_write_ptr = __octeon_uart_write;
#define CONSOLE_TYPE_PCI 2
	octeon_os_set_console(CONSOLE_TYPE_PCI);
}
