/*
<:copyright-BRCM:2013:DUAL/GPL:standard

   Copyright (c) 2013 Broadcom 
   All Rights Reserved

Unless you and Broadcom execute a separate written software license
agreement governing use of this software, this software is licensed
to you under the terms of the GNU General Public License version 2
(the "GPL"), available at http://www.broadcom.com/licenses/GPLv2.php,
with the following added to such license:

   As a special exception, the copyright holders of this software give
   you permission to link this software with independent modules, and
   to copy and distribute the resulting executable under terms of your
   choice, provided that you also meet, for each linked independent
   module, the terms and conditions of the license of that module.
   An independent module is a module which is not derived from this
   software.  The special exception does not apply to any modifications
   of the software.

Not withstanding the above, under no circumstances may you combine
this software in any way with any other Broadcom software provided
under a license other than the GPL, without Broadcom's express prior
written consent.

:>
*/

#ifndef __63138_INTR_H
#define __63138_INTR_H

#ifdef __cplusplus
extern "C" {
#endif

#if 0
// FIXME! not use?
#define INTERRUPT_ID_SOFTWARE_0		0
#define INTERRUPT_ID_SOFTWARE_1		1
#endif

/*=====================================================================*/
/* BCM63138 Timer Interrupt Level Assignments                          */
/*=====================================================================*/
#if 0
// FIXME.. not use?
#define MIPS_TIMER_INT			7	// FIXME?
#endif

/*=====================================================================*/
/* Peripheral ISR Table Offset                                         */
/*=====================================================================*/
#define ISR_TABLE_OFFSET		32	// FIXME?
#define ISR_TABLE2_OFFSET		ISR_TABLE_OFFSET + 32
#define ISR_TABLE3_OFFSET		ISR_TABLE2_OFFSET + 32
#define ISR_TABLE4_OFFSET		ISR_TABLE3_OFFSET + 32

/*=====================================================================*/
/* Logical Peripheral Interrupt IDs                                    */
/*=====================================================================*/
#define INTERRUPT_ID_L2CC		(ISR_TABLE_OFFSET + 0)
#define INTERRUPT_ID_PWRWDOG		(ISR_TABLE_OFFSET + 1)
#define INTERRUPT_ID_TRAPAXI0		(ISR_TABLE_OFFSET + 2)
#define INTERRUPT_ID_TRAPAXI1		(ISR_TABLE_OFFSET + 3)
#define INTERRUPT_ID_COMMTX		(ISR_TABLE_OFFSET + 4)
#define INTERRUPT_ID_COMMRX		(ISR_TABLE_OFFSET + 5)
#define INTERRUPT_ID_PMU		(ISR_TABLE_OFFSET + 6)
#define INTERRUPT_ID_CTI		(ISR_TABLE_OFFSET + 7)
#define INTERRUPT_ID_DEFFLG0		(ISR_TABLE_OFFSET + 8)
#define INTERRUPT_ID_DEFFLG1		(ISR_TABLE_OFFSET + 9)
#define INTERRUPT_ID_PARITYFAIL_CPU0	(ISR_TABLE_OFFSET + 10)
#define INTERRUPT_ID_PARITYFAIL_CPU1	(ISR_TABLE_OFFSET + 11)
#define INTERRUPT_ID_PARITYFAIL_SCU0	(ISR_TABLE_OFFSET + 12)
#define INTERRUPT_ID_PARITYFAIL_SCU1	(ISR_TABLE_OFFSET + 13)
#define INTERRUPT_ID_ARM_TIMER		(ISR_TABLE_OFFSET + 15)
#define INTERRUPT_ID_WDTIMER		(ISR_TABLE_OFFSET + 16)
#define INTERRUPT_ID_AES		(ISR_TABLE_OFFSET + 17)
#define INTERRUPT_ID_DDRSEC		(ISR_TABLE_OFFSET + 18)
#define INTERRUPT_ID_AIPSEC		(ISR_TABLE_OFFSET + 19)
#define INTERRUPT_ID_PERIPHSEC		(ISR_TABLE_OFFSET + 20)
#define INTERRUPT_ID_PMCSEC		(ISR_TABLE_OFFSET + 21)
#define INTERRUPT_ID_UBUSERR		(ISR_TABLE_OFFSET + 22)
#define INTERRUPT_ID_MBOX2		(ISR_TABLE_OFFSET + 23)
#define INTERRUPT_ID_MBOX3		(ISR_TABLE_OFFSET + 24)
#define INTERRUPT_ID_DG     		(ISR_TABLE_OFFSET + 29)
#define INTERRUPT_ID_PMC0		(ISR_TABLE_OFFSET + 30)
#define INTERRUPT_ID_PMC1		(ISR_TABLE_OFFSET + 31)

#define INTERRUPT_ID_UART0		(ISR_TABLE2_OFFSET + 0)
#define INTERRUPT_ID_UART		INTERRUPT_ID_UART0
#define INTERRUPT_ID_UART1		(ISR_TABLE2_OFFSET + 1)
#define INTERRUPT_ID_UART2		(ISR_TABLE2_OFFSET + 2)
#define INTERRUPT_ID_AIPETB		(ISR_TABLE2_OFFSET + 3)
#define INTERRUPT_ID_UBUS2ER		(ISR_TABLE2_OFFSET + 4)
#define INTERRUPT_ID_HS_SPIM		(ISR_TABLE2_OFFSET + 5)
#define INTERRUPT_ID_NAND_FLASH		(ISR_TABLE2_OFFSET + 6)
#define INTERRUPT_ID_DDRC		(ISR_TABLE2_OFFSET + 7)
#define INTERRUPT_ID_VDSL		(ISR_TABLE2_OFFSET + 8)
#define INTERRUPT_ID_SARC		(ISR_TABLE2_OFFSET + 9)
#define INTERRUPT_ID_USBDC		(ISR_TABLE2_OFFSET + 10)
#define INTERRUPT_ID_PCMC		(ISR_TABLE2_OFFSET + 11)
#define INTERRUPT_ID_SATAERR	(ISR_TABLE2_OFFSET + 12)
#define INTERRUPT_ID_SATAC		(ISR_TABLE2_OFFSET + 13)
#define INTERRUPT_ID_RUNNER_0		(ISR_TABLE2_OFFSET + 14)
#define INTERRUPT_ID_RUNNER_1		(ISR_TABLE2_OFFSET + 15)
#define INTERRUPT_ID_RUNNER_2		(ISR_TABLE2_OFFSET + 16)
#define INTERRUPT_ID_RUNNER_3		(ISR_TABLE2_OFFSET + 17)
#define INTERRUPT_ID_RUNNER_4		(ISR_TABLE2_OFFSET + 18)
#define INTERRUPT_ID_RUNNER_5		(ISR_TABLE2_OFFSET + 19)
#define INTERRUPT_ID_RUNNER_6		(ISR_TABLE2_OFFSET + 20)
#define INTERRUPT_ID_RUNNER_7		(ISR_TABLE2_OFFSET + 21)
#define INTERRUPT_ID_RUNNER_8		(ISR_TABLE2_OFFSET + 22)
#define INTERRUPT_ID_RUNNER_9		(ISR_TABLE2_OFFSET + 23)
#define INTERRUPT_ID_RDP_SBPM		(ISR_TABLE2_OFFSET + 24)
#define INTERRUPT_ID_RDP_BPM		(ISR_TABLE2_OFFSET + 25)
#define INTERRUPT_ID_SF2_0		(ISR_TABLE2_OFFSET + 26)
#define INTERRUPT_ID_SF2_1		(ISR_TABLE2_OFFSET + 27)
#define INTERRUPT_ID_PCIE0		(ISR_TABLE2_OFFSET + 28)
#define INTERRUPT_ID_PCIE1		(ISR_TABLE2_OFFSET + 29)
#define INTERRUPT_ID_DECT_0		(ISR_TABLE2_OFFSET + 30)
#define INTERRUPT_ID_DECT_1		(ISR_TABLE2_OFFSET + 31)
#if 0
/* old naming, module owner feel free to replace if the namings up there
 * are not correct. */
#define INTERRUPT_ID_IPSEC		(ISR_TABLE_OFFSET + 8)
#define INTERRUPT_ID_USBH		(ISR_TABLE_OFFSET + 9)
#define INTERRUPT_ID_USBH20		(ISR_TABLE_OFFSET + 10)
#define INTERRUPT_ID_USBS		(ISR_TABLE_OFFSET + 11)
#define INTERRUPT_ID_PCM		(ISR_TABLE_OFFSET + 12)
#define INTERRUPT_ID_PCIE_RC		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 8)
#define INTERRUPT_ID_PCIE_EP		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 9)
#define INTERRUPT_ID_SAR		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 17)

#endif

#define INTERRUPT_ID_SAR		INTERRUPT_ID_SARC


#define INTERRUPT_ID_TIMER0		(ISR_TABLE3_OFFSET + 0)
#define INTERRUPT_ID_TIMER		INTERRUPT_ID_TIMER0
#define INTERRUPT_ID_TIMER1		(ISR_TABLE3_OFFSET + 1)
#define INTERRUPT_ID_TIMER2		(ISR_TABLE3_OFFSET + 2)
#define INTERRUPT_ID_TIMER3		(ISR_TABLE3_OFFSET + 3)
#define INTERRUPT_ID_TIMER_MAX		INTERRUPT_ID_TIMER3
#define INTERRUPT_ID_PER_MBOX0		(ISR_TABLE3_OFFSET + 4)
#define INTERRUPT_ID_PER_MBOX1		(ISR_TABLE3_OFFSET + 5)
#define INTERRUPT_ID_PER_MBOX2		(ISR_TABLE3_OFFSET + 6)
#define INTERRUPT_ID_PER_MBOX3		(ISR_TABLE3_OFFSET + 7)
#define INTERRUPT_ID_USB_OHCI		(ISR_TABLE3_OFFSET + 8)
#define INTERRUPT_ID_USB_EHCI		(ISR_TABLE3_OFFSET + 9)
#define INTERRUPT_ID_USB_XHCI		(ISR_TABLE3_OFFSET + 10)
#define INTERRUPT_ID_USB_HBR		(ISR_TABLE3_OFFSET + 11)
#define INTERRUPT_ID_USB_HEV		(ISR_TABLE3_OFFSET + 12)
#define INTERRUPT_ID_EXTERNAL_0		(ISR_TABLE3_OFFSET + 13)
#define INTERRUPT_ID_EXTERNAL_1		(ISR_TABLE3_OFFSET + 14)
#define INTERRUPT_ID_EXTERNAL_2		(ISR_TABLE3_OFFSET + 15)
#define INTERRUPT_ID_EXTERNAL_3		(ISR_TABLE3_OFFSET + 16)
#define INTERRUPT_ID_EXTERNAL_4		(ISR_TABLE3_OFFSET + 17)
#define INTERRUPT_ID_EXTERNAL_5		(ISR_TABLE3_OFFSET + 18)
#define INTERRUPT_ID_EXTERNAL_MAX	INTERRUPT_ID_EXTERNAL_5
#define MAP_EXT_IRQ_TO_GPIO(n) ((n)+32)
#define INTERRUPT_ID_I2C		(ISR_TABLE3_OFFSET + 19)
#define INTERRUPT_ID_I2S		(ISR_TABLE3_OFFSET + 20)
#define INTERRUPT_ID_RNG		(ISR_TABLE3_OFFSET + 21)
#define INTERRUPT_ID_EMMC		(ISR_TABLE3_OFFSET + 22)
#define INTERRUPT_ID_PL081		(ISR_TABLE3_OFFSET + 23)
#if 0
/* old naming, module owner feel free to replace if the namings up there
 * are not correct. */
#define INTERRUPT_ID_USB_CNTL_RX_DMA	(ISR_TABLE_OFFSET + 19)
#define INTERRUPT_ID_USB_BULK_RX_DMA	(ISR_TABLE_OFFSET + 20)
#define INTERRUPT_ID_USB_ISO_RX_DMA	(ISR_TABLE_OFFSET + 21)
#define INTERRUPT_ID_USB_CNTL_TX_DMA	(INTERNAL_HIGH_ISR_TABLE_OFFSET + 4)
#define INTERRUPT_ID_USB_BULK_TX_DMA	(INTERNAL_HIGH_ISR_TABLE_OFFSET + 5)
#define INTERRUPT_ID_USB_ISO_TX_DMA	(INTERNAL_HIGH_ISR_TABLE_OFFSET + 6)
#define INTERRUPT_ID_USB_CONNECT	(INTERNAL_HIGH_ISR_TABLE_OFFSET + 21)
#define INTERRUPT_ID_USB_DISCONNECT	(INTERNAL_HIGH_ISR_TABLE_OFFSET + 22)
#endif

#define INTERRUPT_ID_SAR_0		(ISR_TABLE4_OFFSET + 0)
#define INTERRUPT_ID_ATM_DMA_0          INTERRUPT_ID_SAR_0
#define INTERRUPT_ID_SAR_1		(ISR_TABLE4_OFFSET + 1)
#define INTERRUPT_ID_ATM_DMA_1          INTERRUPT_ID_SAR_1
#define INTERRUPT_ID_SAR_2		(ISR_TABLE4_OFFSET + 2)
#define INTERRUPT_ID_ATM_DMA_2          INTERRUPT_ID_SAR_2
#define INTERRUPT_ID_SAR_3		(ISR_TABLE4_OFFSET + 3)
#define INTERRUPT_ID_ATM_DMA_3          INTERRUPT_ID_SAR_3
#define INTERRUPT_ID_SAR_4		(ISR_TABLE4_OFFSET + 4)
#define INTERRUPT_ID_ATM_DMA_4          INTERRUPT_ID_SAR_4
#define INTERRUPT_ID_SAR_5		(ISR_TABLE4_OFFSET + 5)
#define INTERRUPT_ID_ATM_DMA_5          INTERRUPT_ID_SAR_5
#define INTERRUPT_ID_SAR_6		(ISR_TABLE4_OFFSET + 6)
#define INTERRUPT_ID_ATM_DMA_6          INTERRUPT_ID_SAR_6
#define INTERRUPT_ID_SAR_7		(ISR_TABLE4_OFFSET + 7)
#define INTERRUPT_ID_ATM_DMA_7          INTERRUPT_ID_SAR_7
#define INTERRUPT_ID_SAR_8		(ISR_TABLE4_OFFSET + 8)
#define INTERRUPT_ID_ATM_DMA_8          INTERRUPT_ID_SAR_8
#define INTERRUPT_ID_SAR_9		(ISR_TABLE4_OFFSET + 9)
#define INTERRUPT_ID_ATM_DMA_9          INTERRUPT_ID_SAR_9
#define INTERRUPT_ID_SAR_10		(ISR_TABLE4_OFFSET + 10)
#define INTERRUPT_ID_ATM_DMA_10          INTERRUPT_ID_SAR_10
#define INTERRUPT_ID_SAR_11		(ISR_TABLE4_OFFSET + 11)
#define INTERRUPT_ID_ATM_DMA_11          INTERRUPT_ID_SAR_11
#define INTERRUPT_ID_SAR_12		(ISR_TABLE4_OFFSET + 12)
#define INTERRUPT_ID_ATM_DMA_12          INTERRUPT_ID_SAR_12
#define INTERRUPT_ID_SAR_13		(ISR_TABLE4_OFFSET + 13)
#define INTERRUPT_ID_ATM_DMA_13          INTERRUPT_ID_SAR_13
#define INTERRUPT_ID_SAR_14		(ISR_TABLE4_OFFSET + 14)
#define INTERRUPT_ID_ATM_DMA_14          INTERRUPT_ID_SAR_14
#define INTERRUPT_ID_SAR_15		(ISR_TABLE4_OFFSET + 15)
#define INTERRUPT_ID_ATM_DMA_15          INTERRUPT_ID_SAR_15
#define INTERRUPT_ID_SAR_16		(ISR_TABLE4_OFFSET + 16)
#define INTERRUPT_ID_ATM_DMA_16          INTERRUPT_ID_SAR_16
#define INTERRUPT_ID_SAR_17		(ISR_TABLE4_OFFSET + 17)
#define INTERRUPT_ID_ATM_DMA_17          INTERRUPT_ID_SAR_17
#define INTERRUPT_ID_SAR_18		(ISR_TABLE4_OFFSET + 18)
#define INTERRUPT_ID_ATM_DMA_18          INTERRUPT_ID_SAR_18
#define INTERRUPT_ID_SAR_19		(ISR_TABLE4_OFFSET + 19)
#define INTERRUPT_ID_ATM_DMA_19          INTERRUPT_ID_SAR_19

#define INTERRUPT_ID_PCM_0		(ISR_TABLE4_OFFSET + 20)
#define INTERRUPT_ID_PCM_1		(ISR_TABLE4_OFFSET + 21)
#define INTERRUPT_ID_USBD_0		(ISR_TABLE4_OFFSET + 22)
#define INTERRUPT_ID_USBD_1		(ISR_TABLE4_OFFSET + 23)
#define INTERRUPT_ID_USBD_2		(ISR_TABLE4_OFFSET + 24)
#define INTERRUPT_ID_USBD_3		(ISR_TABLE4_OFFSET + 25)
#define INTERRUPT_ID_USBD_4		(ISR_TABLE4_OFFSET + 26)
#define INTERRUPT_ID_USBD_5		(ISR_TABLE4_OFFSET + 27)

#if 0
/* old naming, module owner feel free to replace if the namings up there
 * are not correct. */
#define INTERRUPT_ID_PCM_DMA_0	   (INTERNAL_HIGH_ISR_TABLE_OFFSET + 10)
#define INTERRUPT_ID_PCM_DMA_1	   (INTERNAL_HIGH_ISR_TABLE_OFFSET + 11)
#endif

#if 0
/* old interrupt ID, remove later */
#define INTERRUPT_ID_ENETSW_RX_DMA_0	(ISR_TABLE_OFFSET + 1)
#define INTERRUPT_ID_ENETSW_RX_DMA_1	(ISR_TABLE_OFFSET + 2)
#define INTERRUPT_ID_ENETSW_RX_DMA_2	(ISR_TABLE_OFFSET + 3)
#define INTERRUPT_ID_ENETSW_RX_DMA_3	(ISR_TABLE_OFFSET + 4)
#define INTERRUPT_ID_EPHY		(ISR_TABLE_OFFSET + 13)
#define INTERRUPT_ID_DG			(ISR_TABLE_OFFSET + 14)
#define INTERRUPT_ID_EPHY_ENERGY_0      (ISR_TABLE_OFFSET + 15)
#define INTERRUPT_ID_EPHY_ENERGY_1      (ISR_TABLE_OFFSET + 16)
#define INTERRUPT_ID_EPHY_ENERGY_2      (ISR_TABLE_OFFSET + 17)
#define INTERRUPT_ID_GPHY_ENERGY_0      (ISR_TABLE_OFFSET + 18)
#define INTERRUPT_ID_IPSEC_DMA_0	(ISR_TABLE_OFFSET + 22)
#define INTERRUPT_ID_XDSL		(ISR_TABLE_OFFSET + 23)
#define INTERRUPT_ID_FAP_0		(ISR_TABLE_OFFSET + 24)
#define INTERRUPT_ID_FAP_1		(ISR_TABLE_OFFSET + 25)
#define INTERRUPT_ID_ATM_DMA_0		(ISR_TABLE_OFFSET + 26)
#define INTERRUPT_ID_ATM_DMA_1		(ISR_TABLE_OFFSET + 27)
#define INTERRUPT_ID_ATM_DMA_2		(ISR_TABLE_OFFSET + 28)
#define INTERRUPT_ID_ATM_DMA_3		(ISR_TABLE_OFFSET + 29)
#define INTERRUPT_ID_WAKE_ON_IRQ	(ISR_TABLE_OFFSET + 30)
#define INTERRUPT_ID_GPHY		(ISR_TABLE_OFFSET + 31)
#define INTERRUPT_ID_IPSEC_DMA_1	(INTERNAL_HIGH_ISR_TABLE_OFFSET + 7)
#define INTERRUPT_ID_ENETSW_SYS		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 16)
#define INTERRUPT_ID_RING_OSC		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 20)
#define INTERRUPT_ID_ATM_DMA_4		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 27)
#define INTERRUPT_ID_ATM_DMA_5		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 28)
#define INTERRUPT_ID_ATM_DMA_6		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 29)
#define INTERRUPT_ID_ATM_DMA_7		(INTERNAL_HIGH_ISR_TABLE_OFFSET + 30)

#define INTERRUPT_ID_ENETSW_TX_DMA_0	(INTERNAL_EXT_ISR_TABLE_OFFSET + 0)
#define INTERRUPT_ID_ENETSW_TX_DMA_1	(INTERNAL_EXT_ISR_TABLE_OFFSET + 1)
#define INTERRUPT_ID_ENETSW_TX_DMA_2	(INTERNAL_EXT_ISR_TABLE_OFFSET + 2)
#define INTERRUPT_ID_ENETSW_TX_DMA_3	(INTERNAL_EXT_ISR_TABLE_OFFSET + 3)
#define INTERRUPT_ID_ATM_DMA_8		(INTERNAL_EXT_ISR_TABLE_OFFSET + 4)
#define INTERRUPT_ID_ATM_DMA_9		(INTERNAL_EXT_ISR_TABLE_OFFSET + 5)
#define INTERRUPT_ID_ATM_DMA_10		(INTERNAL_EXT_ISR_TABLE_OFFSET + 6)
#define INTERRUPT_ID_ATM_DMA_11		(INTERNAL_EXT_ISR_TABLE_OFFSET + 7)
#define INTERRUPT_ID_ATM_DMA_12		(INTERNAL_EXT_ISR_TABLE_OFFSET + 8)
#define INTERRUPT_ID_ATM_DMA_13		(INTERNAL_EXT_ISR_TABLE_OFFSET + 9)
#define INTERRUPT_ID_ATM_DMA_14		(INTERNAL_EXT_ISR_TABLE_OFFSET + 10)
#define INTERRUPT_ID_ATM_DMA_15		(INTERNAL_EXT_ISR_TABLE_OFFSET + 11)
#define INTERRUPT_ID_ATM_DMA_16		(INTERNAL_EXT_ISR_TABLE_OFFSET + 12)
#define INTERRUPT_ID_ATM_DMA_17		(INTERNAL_EXT_ISR_TABLE_OFFSET + 13)
#define INTERRUPT_ID_ATM_DMA_18		(INTERNAL_EXT_ISR_TABLE_OFFSET + 14)
#define INTERRUPT_ID_ATM_DMA_19		(INTERNAL_EXT_ISR_TABLE_OFFSET + 15)
#define INTERRUPT_ID_LS_SPIM		(INTERNAL_EXT_ISR_TABLE_OFFSET + 16)
#define INTERRUPT_ID_GMAC_DMA_0		(INTERNAL_EXT_ISR_TABLE_OFFSET + 17)
#define INTERRUPT_ID_GMAC_DMA_1		(INTERNAL_EXT_ISR_TABLE_OFFSET + 18)
#define INTERRUPT_ID_GMAC		(INTERNAL_EXT_ISR_TABLE_OFFSET + 19)
#endif

/* Last Physical Interrupt ID */
#define INTERRUPT_ID_LAST_PHYS		INTERRUPT_ID_USBD_5


/* Virtual interrupts */
#define	VIRTUAL_INTR_TABLE_OFFSET	(INTERRUPT_ID_LAST_PHYS + 1)

/* PCIE MSI virtual interrupts */
#define	PCIE_MSI_IDS_PER_DOMAIN		8
#define	INTERRUPT_ID_PCIE_MSI_FIRST	(VIRTUAL_INTR_TABLE_OFFSET + 0)
#define	INTERRUPT_ID_PCIE0_MSI_FIRST	INTERRUPT_ID_PCIE_MSI_FIRST
#define	INTERRUPT_ID_PCIE0_MSI_LAST	(INTERRUPT_ID_PCIE0_MSI_FIRST + PCIE_MSI_IDS_PER_DOMAIN - 1)
#define	INTERRUPT_ID_PCIE1_MSI_FIRST	(INTERRUPT_ID_PCIE0_MSI_LAST + 1)
#define	INTERRUPT_ID_PCIE1_MSI_LAST	(INTERRUPT_ID_PCIE1_MSI_FIRST + PCIE_MSI_IDS_PER_DOMAIN - 1)
#define	INTERRUPT_ID_PCIE_MSI_LAST	INTERRUPT_ID_PCIE1_MSI_LAST

/* Last Virtual Interrupt ID */
#define INTERRUPT_ID_LAST_VIRT		INTERRUPT_ID_PCIE_MSI_LAST

#define INTERRUPT_ID_LAST		INTERRUPT_ID_LAST_VIRT
#ifdef __cplusplus
}
#endif

#endif /* __BCM63138_H */

