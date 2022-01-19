/*
 * Simple singly link header
 *
 * Broadcom Proprietary and Confidential. Copyright (C) 2016,
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom.
 *
 * $Id: $
 */

#ifndef __WPS_SSLIST_H__
#define __WPS_SSLIST_H__

#ifdef __cplusplus
extern "C" {
#endif

struct wps_sslist;
typedef struct wps_sslist WPS_SSLIST;

struct wps_sslist {
	WPS_SSLIST *next;
};

WPS_SSLIST *wps_sslist_add(WPS_SSLIST **head, void *item);

#ifdef __cplusplus
}
#endif

#endif /* __WPS_SSLIST_H__ */
