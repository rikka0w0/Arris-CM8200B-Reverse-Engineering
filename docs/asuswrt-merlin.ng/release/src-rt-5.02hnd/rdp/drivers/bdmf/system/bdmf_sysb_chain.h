/*
* <:copyright-BRCM:2016:GPL/GPL:standard
* 
*    Copyright (c) 2016 Broadcom 
*    All Rights Reserved
* 
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License, version 2, as published by
* the Free Software Foundation (the "GPL").
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* 
* A copy of the GPL is available at http://www.broadcom.com/licenses/GPLv2.php, or by
* writing to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
* Boston, MA 02111-1307, USA.
* 
** :>
*/

#ifndef _BDMF_SYSB_CHAIN_H_
#define _BDMF_SYSB_CHAIN_H_

#if (defined(CONFIG_BCM_WLAN) || defined(CONFIG_BCM_WLAN_MODULE))
#include <osl.h>
#endif


static inline int bdmf_sysb_is_chained(const bdmf_sysb sysb)
{
#if (defined(CONFIG_BCM_WLAN) || defined(CONFIG_BCM_WLAN_MODULE))
    return PKTISCHAINED(sysb);
#else
    return 0;
#endif
}

static inline bdmf_sysb bdmf_sysb_chain_next(const bdmf_sysb sysb)
{
#if (defined(CONFIG_BCM_WLAN) || defined(CONFIG_BCM_WLAN_MODULE))
    return PKTCLINK(sysb);
#else
    return NULL;
#endif
}

#endif
