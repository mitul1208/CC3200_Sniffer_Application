//*****************************************************************************
//
// Copyright (C) 2014 Texas Instruments Incorporated - http://www.ti.com/
//
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//
//    Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
//    Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
//    Neither the name of Texas Instruments Incorporated nor the names of
//    its contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//*****************************************************************************

//*****************************************************************************
//
// Application Name     -   Transceiver mode
// Application Overview -   This is a sample application demonstrating the
//                          use of raw sockets on a CC3200 device.Based on the
//                          user input, the application either transmits data
//                          on the channel requested or collects Rx statistics
//                          on the channel.
//
// Application Details  -
// docs\examples\CC32xx_Transceiver_Mode.pdf
// or
// http://processors.wiki.ti.com/index.php/CC32xx_Transceiver_Mode
//
//*****************************************************************************

//*****************************************************************************
//
//! \addtogroup transceiver
//! @{
//
//*****************************************************************************

// Standard includes

// Standard includes
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// Simplelink includes
#include "simplelink.h"

//Driverlib includes
#include "hw_types.h"
#include "hw_ints.h"
#include "interrupt.h"
#include "utils.h"
#include "uart.h"
#include "hw_memmap.h"
#include "prcm.h"
#include "rom.h"
#include "rom_map.h"

//Common interface includes
#include "common.h"
#ifndef NOTERM
#include "uart_if.h"
#endif

#include "pinmux.h"

#define APPLICATION_NAME        "Sniffer"
#define APPLICATION_VERSION     "1.1.1"
#define IP_ADDR_LENGTH      4
#define PREAMBLE            1        /* Preamble value 0- short, 1- long */
#define CPU_CYCLES_1MSEC (80*1000)
#define MAC_ADDR_LENGTH     (6)
#define MAC_ADDR_LEN_STR    (18)    /*xx:xx:xx:xx:xx:xx*/
#define IP_ADDR_LEN_STR     (16)    /*xxx:xxx:xxx:xxx*/
#define MAX_RECV_BUF_SIZE   1536
int buffer[MAX_RECV_BUF_SIZE] = {'\0'};
int  g_Status = 0;
int   g_Exit = 0;
#define SWAP_UINT32(val)    (((val>>24) & 0x000000FF) + ((val>>8) & 0x0000FF00) + \
                            ((val<<24) & 0xFF000000) + ((val<<8) & 0x00FF0000))
#define SWAP_UINT16(val)    ((((val)>>8) & 0x00FF) + (((val)<<8) & 0xFF00))
#define FRAME_TYPE_MASK     0x0C
#define FRAME_SUBTYPE_MASK  0xF0
// Application specific status/error codes
typedef enum {
	// Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
	TX_CONTINUOUS_FAILED = -0x7D0,
	RX_STATISTICS_FAILED = TX_CONTINUOUS_FAILED - 1,
	DEVICE_NOT_IN_STATION_MODE = RX_STATISTICS_FAILED - 1,
	INVALID_PARENT_FILTER_ID   = DEVICE_NOT_IN_STATION_MODE - 1,
	STATUS_CODE_MAX = -0xBB8
} e_AppStatusCodes;

typedef struct {
	int choice;
	int channel;
	int packets;
	SlRateIndex_e rate;
	int Txpower;
} UserIn;

typedef struct {
	int rate;
	unsigned int channel;
	int rssi;
	unsigned int padding;
	unsigned int timestamp;
} TransceiverRxOverHead_t;

/* Application specific status/error codes */

//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
volatile unsigned long g_ulStatus = 0; //SimpleLink Status
unsigned long g_ulGatewayIP = 0; //Network Gateway IP address
unsigned char g_ucConnectionSSID[SSID_LEN_MAX + 1]; //Connection SSID
unsigned char g_ucConnectionBSSID[BSSID_LEN_MAX]; //Connection BSSID

// MAC address to be filtered out
unsigned char g_ucMacAddress[SL_MAC_ADDR_LEN] = { 0xC0, 0xCB, 0x38, 0x1D, 0x09,
		0x17 };

//unsigned char g_ucMacAddress[SL_MAC_ADDR_LEN] = {0x10, 0x40, 0xF3, 0xA3, 0x07,
//                                                 0x08};
// IP address to be filtered out
unsigned char g_ucIpAddress[IP_ADDR_LENGTH] = { 0xc0, 0xa8, 0x01, 0x64 };
//unsigned char g_ucIpAddress[IP_ADDR_LENGTH] = {0xAC, 0x14, 0x0A, 0x02};

char RawData_Ping[] = {
/*---- wlan header start -----*/
0x88, /* version , type sub type */
0x02, /* Frame control flag */
0x2C, 0x00, 0x00, 0x23, 0x75, 0x55, 0x55, 0x55, /* destination */
0x00, 0x22, 0x75, 0x55, 0x55, 0x55, /* bssid */
0xC0, 0xCB, 0x38, 0x1D, 0x09, 0x17, /* source */
0x80, 0x42, 0x00, 0x00, 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, /* LLC */
/*---- ip header start -----*/
0x45, 0x00, 0x00, 0x54, 0x96, 0xA1, 0x00, 0x00, 0x40, 0x01, 0x57, 0xFA, /* checksum */
0xc0, 0xa8, 0x01, 0x64, /* src ip */
0xc0, 0xa8, 0x01, 0x02, /* dest ip  */
/* payload - ping/icmp */
'h', 'i', 'm', 'i', 't', 'u', 'l', 'h', 'o', 'w', 'a', 'r', 'u', 'd', 'o', 'i',
		'g', '?', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00 };

#if defined(ccs)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 GLOBAL VARIABLES -- End
//*****************************************************************************

//****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//****************************************************************************
static void DisplayBanner(char * AppName);
static void BoardInit(void);
//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************

//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent) {
	switch (pWlanEvent->Event) {
	case SL_WLAN_CONNECT_EVENT: {
		SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
		//
		// Information about the connected AP (like name, MAC etc) will be
		// available in 'slWlanConnectAsyncResponse_t' - Applications
		// can use it if required
		//
		//  slWlanConnectAsyncResponse_t *pEventData = NULL;
		// pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
		//

		// Copy new connection SSID and BSSID to global parameters
		memcpy(g_ucConnectionSSID,
				pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_name,
				pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_len);
		memcpy(g_ucConnectionBSSID,
				pWlanEvent->EventData.STAandP2PModeWlanConnected.bssid,
				SL_BSSID_LENGTH);

		UART_PRINT("[WLAN EVENT] STA Connected to the AP: %s , "
				"BSSID: %x:%x:%x:%x:%x:%x\n\r", g_ucConnectionSSID,
				g_ucConnectionBSSID[0], g_ucConnectionBSSID[1],
				g_ucConnectionBSSID[2], g_ucConnectionBSSID[3],
				g_ucConnectionBSSID[4], g_ucConnectionBSSID[5]);
	}
		break;

	case SL_WLAN_DISCONNECT_EVENT: {
		slWlanConnectAsyncResponse_t* pEventData = NULL;

		CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
		CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

		pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

		// If the user has initiated 'Disconnect' request,
		//'reason_code' is SL_WLAN_DISCONNECT_USER_INITIATED_DISCONNECTION
		if (SL_WLAN_DISCONNECT_USER_INITIATED_DISCONNECTION
				== pEventData->reason_code) {
			UART_PRINT("[WLAN EVENT]Device disconnected from the AP: %s,"
					" BSSID: %x:%x:%x:%x:%x:%x on application's"
					" request \n\r", g_ucConnectionSSID, g_ucConnectionBSSID[0],
					g_ucConnectionBSSID[1], g_ucConnectionBSSID[2],
					g_ucConnectionBSSID[3], g_ucConnectionBSSID[4],
					g_ucConnectionBSSID[5]);
		} else {
			UART_PRINT("[WLAN ERROR]Device disconnected from the AP AP: %s,"
					" BSSID: %x:%x:%x:%x:%x:%x on an ERROR..!! \n\r",
					g_ucConnectionSSID, g_ucConnectionBSSID[0],
					g_ucConnectionBSSID[1], g_ucConnectionBSSID[2],
					g_ucConnectionBSSID[3], g_ucConnectionBSSID[4],
					g_ucConnectionBSSID[5]);
		}
		memset(g_ucConnectionSSID, 0, sizeof(g_ucConnectionSSID));
		memset(g_ucConnectionBSSID, 0, sizeof(g_ucConnectionBSSID));
	}
		break;

	default: {
		UART_PRINT("[WLAN EVENT] Unexpected event [0x%x]\n\r",
				pWlanEvent->Event);
	}
		break;
	}
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent) {
	switch (pNetAppEvent->Event) {
	case SL_NETAPP_IPV4_IPACQUIRED_EVENT: {
		SlIpV4AcquiredAsync_t *pEventData = NULL;
		SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);
		//Ip Acquired Event Data
		pEventData = &pNetAppEvent->EventData.ipAcquiredV4;
		//Gateway IP address
		g_ulGatewayIP = pEventData->gateway;

		UART_PRINT("[NETAPP EVENT] IP Acquired: IP=%d.%d.%d.%d , "
				"Gateway=%d.%d.%d.%d\n\r",
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip, 3),
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip, 2),
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip, 1),
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip, 0),
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway, 3),
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway, 2),
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway, 1),
				SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway, 0));
	}
		break;
	default: {
		UART_PRINT("[NETAPP EVENT] Unexpected event [0x%x] \n\r",
				pNetAppEvent->Event);
	}
		break;
	}
}

//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent,
		SlHttpServerResponse_t *pHttpResponse) {
	// Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent) {
	//
	// Most of the general errors are not FATAL are are to be handled
	// appropriately by the application
	//
	UART_PRINT("[GENERAL EVENT] - ID=[%d] Sender=[%d]\n\n",
			pDevEvent->EventData.deviceEvent.status,
			pDevEvent->EventData.deviceEvent.sender);
}

//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock) {
	//
	// This application doesn't work w/ socket - Events are not expected
	//

}

//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End
//*****************************************************************************

//*****************************************************************************
//
//! \brief This function initializes the application variables
//!
//! \param    None
//!
//! \return None
//!
//*****************************************************************************
static void InitializeAppVariables() {
	g_ulStatus = 0;
	g_ulGatewayIP = 0;
	memset(g_ucConnectionSSID, 0, sizeof(g_ucConnectionSSID));
	memset(g_ucConnectionBSSID, 0, sizeof(g_ucConnectionBSSID));
}

//*****************************************************************************
//! \brief This function puts the device in its default state. It:
//!           - Set the mode to STATION
//!           - Configures connection policy to Auto and AutoSmartConfig
//!           - Deletes all the stored profiles
//!           - Enables DHCP
//!           - Disables Scan policy
//!           - Sets Tx power to maximum
//!           - Sets power policy to normal
//!           - Unregister mDNS services
//!           - Remove all filters
//!
//! \param   none
//! \return  On success, zero is returned. On error, negative is returned
//*****************************************************************************
static long ConfigureSimpleLinkToDefaultState() {
	SlVersionFull ver = { 0 };
	_WlanRxFilterOperationCommandBuff_t RxFilterIdMask = { 0 };

	unsigned char ucVal = 1;
	unsigned char ucConfigOpt = 0;
	unsigned char ucConfigLen = 0;
	unsigned char ucPower = 0;

	long lRetVal = -1;
	long lMode = -1;

	lMode = sl_Start(0, 0, 0);
	ASSERT_ON_ERROR(lMode);

	// If the device is not in station-mode, try configuring it in station-mode
	if (ROLE_STA != lMode) {
		if (ROLE_AP == lMode) {
			// If the device is in AP mode, we need to wait for this event
			// before doing anything
			while (!IS_IP_ACQUIRED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
				_SlNonOsMainLoopTask();
#endif
			}
		}

		// Switch to STA role and restart
		lRetVal = sl_WlanSetMode(ROLE_STA);
		ASSERT_ON_ERROR(lRetVal);

		lRetVal = sl_Stop(0xFF);
		ASSERT_ON_ERROR(lRetVal);

		lRetVal = sl_Start(0, 0, 0);
		ASSERT_ON_ERROR(lRetVal);

		// Check if the device is in station again
		if (ROLE_STA != lRetVal) {
			// We don't want to proceed if the device is not coming up in STA-mode
			return DEVICE_NOT_IN_STATION_MODE;
		}
	}

	// Get the device's version-information
	ucConfigOpt = SL_DEVICE_GENERAL_VERSION;
	ucConfigLen = sizeof(ver);
	lRetVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &ucConfigOpt,
			&ucConfigLen, (unsigned char *) (&ver));
	ASSERT_ON_ERROR(lRetVal);

	UART_PRINT("Host Driver Version: %s\n\r", SL_DRIVER_VERSION);
	UART_PRINT("Build Version %d.%d.%d.%d.31.%d.%d.%d.%d.%d.%d.%d.%d\n\r",
			ver.NwpVersion[0], ver.NwpVersion[1], ver.NwpVersion[2],
			ver.NwpVersion[3], ver.ChipFwAndPhyVersion.FwVersion[0],
			ver.ChipFwAndPhyVersion.FwVersion[1],
			ver.ChipFwAndPhyVersion.FwVersion[2],
			ver.ChipFwAndPhyVersion.FwVersion[3],
			ver.ChipFwAndPhyVersion.PhyVersion[0],
			ver.ChipFwAndPhyVersion.PhyVersion[1],
			ver.ChipFwAndPhyVersion.PhyVersion[2],
			ver.ChipFwAndPhyVersion.PhyVersion[3]);

	// Set connection policy to Auto + SmartConfig
	//      (Device's default connection policy)
	lRetVal = sl_WlanPolicySet(SL_POLICY_CONNECTION,
			SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
	ASSERT_ON_ERROR(lRetVal);

	// Remove all profiles
	lRetVal = sl_WlanProfileDel(0xFF);
	ASSERT_ON_ERROR(lRetVal);

	//
	// Device in station-mode. Disconnect previous connection if any
	// The function returns 0 if 'Disconnected done', negative number if already
	// disconnected Wait for 'disconnection' event if 0 is returned, Ignore
	// other return-codes
	//
	lRetVal = sl_WlanDisconnect();
	if (0 == lRetVal) {
		// Wait
		while (IS_CONNECTED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
			_SlNonOsMainLoopTask();
#endif
		}
	}

	// Enable DHCP client
	lRetVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE, 1, 1, &ucVal);
	ASSERT_ON_ERROR(lRetVal);

	// Disable scan
	ucConfigOpt = SL_SCAN_POLICY(0);
	lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN, ucConfigOpt, NULL, 0);
	ASSERT_ON_ERROR(lRetVal);

	// Set Tx power level for station mode
	// Number between 0-15, as dB offset from max power - 0 will set max power
	ucPower = 0;
	lRetVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID,
	WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (unsigned char *) &ucPower);
	ASSERT_ON_ERROR(lRetVal);

	// Set PM policy to normal
	lRetVal = sl_WlanPolicySet(SL_POLICY_PM, SL_NORMAL_POLICY, NULL, 0);
	ASSERT_ON_ERROR(lRetVal);

	// Unregister mDNS services
	lRetVal = sl_NetAppMDNSUnRegisterService(0, 0);
	ASSERT_ON_ERROR(lRetVal);

	// Remove  all 64 filters (8*8)
	memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
	lRetVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *) &RxFilterIdMask,
			sizeof(_WlanRxFilterOperationCommandBuff_t));
	ASSERT_ON_ERROR(lRetVal);

	lRetVal = sl_Stop(SL_STOP_TIMEOUT);
	ASSERT_ON_ERROR(lRetVal);

	InitializeAppVariables();

	return lRetVal; // Success
}

//*****************************************************************************
//
//! Application startup display on UART
//!
//! \param  AppName
//!
//! \return none
//!
//*****************************************************************************
static void DisplayBanner(char * AppName) {
	printf("\n\n\n\r");
	printf("\t\t *************************************************\n\r");
	printf("\t\t\t CC3200 %s Application       \n\r", AppName);
	printf("\t\t *************************************************\n\r");
	printf("\n\n\n\r");
}

//*****************************************************************************
//
//! Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void BoardInit(void) {
	/* In case of TI-RTOS vector table is initialize by OS itself */
#ifndef USE_TIRTOS
	//
	// Set vector table base
	//
#if defined(ccs)
	MAP_IntVTableBaseSet((unsigned long) &g_pfnVectors[0]);
#endif
#if defined(ewarm)
	MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif
	//
	// Enable Processor
	//
	MAP_IntMasterEnable();
	MAP_IntEnable(FAULT_SYSTICK);

	PRCMCC3200MCUInit();
}

/*!
    \brief This function creates filters based on rule specified by user

    \param[in]   Input : Filter chosen
    \param[in]   FilterNumber : Chosen filter type ( Source MAC ID, Dst MAC ID,
                                BSS ID,  IP Address etc)
    \param[in]   Filterparams: parameters  of chosen filter type
    \param[in]   Filter Rule:  Check for equal or Not
    \param[in]   Filter Rule : If Rule match, to drop packet or pass to Host
    \param[in]   parent Id : in case sub-filter of existing filer, id of the parent filter

    \return      Unique filter ID in long format for success, -ve otherwise

    \note

    \warning
*/
static _i32 RxFiltersExample(_i8 input, _i32 filterNumber,
                                const _u8 *filterParam, _i8 equalOrNot,
                                _i8 dropOrNot, _i8 parentId)
{
    SlrxFilterID_t          FilterId = 0;
    SlrxFilterRuleType_t    RuleType = 0;
    SlrxFilterFlags_t       FilterFlags = {0};
    SlrxFilterRule_t        Rule = {0};
    SlrxFilterTrigger_t     Trigger = {0};
    SlrxFilterAction_t      Action = {0};

    _u8 MacMAsk[6]      = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    _u8 FrameMask[1]    = {0xFF};
    _u8 IPMask[4]       = {0xFF,0xFF,0xFF,0xFF};
    _u8 zeroMask[4]     = {0x00,0x00,0x00,0x00};

    _i32 retVal = -1;
    _u8 frameByte = 0;

    switch(input)
    {
        case '1': /* Create filter */
            /* Rule definition */
            RuleType = HEADER;
            FilterFlags.IntRepresentation = RX_FILTER_BINARY;
            /* When RX_FILTER_COUNTER7 is bigger than 0 */
            Trigger.Trigger = NO_TRIGGER;

            /* connection state and role */
            Trigger.TriggerArgConnectionState.IntRepresentation = RX_FILTER_CONNECTION_STATE_STA_NOT_CONNECTED;
            Trigger.TriggerArgRoleStatus.IntRepresentation = RX_FILTER_ROLE_PROMISCUOUS;

            switch (filterNumber)
            {
                case 1:
                    Rule.HeaderType.RuleHeaderfield = MAC_SRC_ADDRESS_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB6BytesRuleArgs[0],
                                                                       filterParam, 6);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                           MacMAsk, 6);
                    break;
                case 2:
                    Rule.HeaderType.RuleHeaderfield = MAC_DST_ADDRESS_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB6BytesRuleArgs[0],
                                                                       filterParam, 6);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                           MacMAsk, 6);
                    break;
                case 3:
                    Rule.HeaderType.RuleHeaderfield = BSSID_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB6BytesRuleArgs[0],
                                                                       filterParam, 6);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                           MacMAsk, 6);
                    break;
                case 4:
                {
                    frameByte = (*filterParam & FRAME_TYPE_MASK);

                    Rule.HeaderType.RuleHeaderfield = FRAME_TYPE_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB1BytesRuleArgs[0],
                                                                       &frameByte, 1);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                          FrameMask, 1);
                }
                break;
                case 5:
                {
                    if(parentId <=0 )
                    {
                        printf("\n[Error] Enter a parent frame type filter id for frame subtype filter\r\n");
                        return INVALID_PARENT_FILTER_ID;
                    }

                    frameByte = (*filterParam & FRAME_SUBTYPE_MASK);

                    Rule.HeaderType.RuleHeaderfield = FRAME_SUBTYPE_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB1BytesRuleArgs[0],
                                                                       &frameByte, 1);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                          FrameMask, 1);
                }
                    break;
                case 6:
                    Rule.HeaderType.RuleHeaderfield = IPV4_SRC_ADRRESS_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB4BytesRuleArgs[0],
                                                                       filterParam, 4);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                            IPMask, 4);
                    break;
                case 7:
                    Rule.HeaderType.RuleHeaderfield = IPV4_DST_ADDRESS_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB4BytesRuleArgs[0],
                                                                       filterParam, 4);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                            IPMask, 4);
                    break;
                case 8:
                    Rule.HeaderType.RuleHeaderfield = FRAME_LENGTH_FIELD;
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB4BytesRuleArgs[0],
                                                                          zeroMask, 4);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                            IPMask, 4);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgs.RxFilterDB4BytesRuleArgs[1],
                                                                       filterParam, 4);
                    memcpy(Rule.HeaderType.RuleHeaderArgsAndMask.RuleHeaderArgsMask,
                                                                            IPMask, 4);
                    break;
            }

            switch(equalOrNot)
            {
                case 'y':
                    Rule.HeaderType.RuleCompareFunc = COMPARE_FUNC_EQUAL;
                    break;
                case 'h':
                    Rule.HeaderType.RuleCompareFunc = COMPARE_FUNC_NOT_IN_BETWEEN;
                    break;
                case 'l':
                    Rule.HeaderType.RuleCompareFunc = COMPARE_FUNC_IN_BETWEEN;
                    break;
                case 'n':
                    Rule.HeaderType.RuleCompareFunc = COMPARE_FUNC_NOT_EQUAL_TO;
                    break;
            }

            Trigger.ParentFilterID = parentId;

            /* Action */
            if(dropOrNot == 'y')
            {
                Action.ActionType.IntRepresentation = RX_FILTER_ACTION_DROP;
            }
            else
            {
                Action.ActionType.IntRepresentation = RX_FILTER_ACTION_NULL;
            }

            retVal = sl_WlanRxFilterAdd(RuleType,
                                            FilterFlags,
                                            &Rule,
                                            &Trigger,
                                            &Action,
                                            &FilterId);
            if( retVal < 0)
            {
                printf("\nError creating the filter. Error number: %d.\n",retVal);
                ASSERT_ON_ERROR(retVal);
            }

            printf("\nThe filter ID is %d\n",FilterId);
            break;

        case '2': /* remove filter */
        {
                _WlanRxFilterOperationCommandBuff_t     RxFilterIdMask ;
                memset(RxFilterIdMask.FilterIdMask, 0xFF , 8);
                retVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                                    sizeof(_WlanRxFilterOperationCommandBuff_t));
                ASSERT_ON_ERROR(retVal);

        }
        break;

        case '3' : /* enable\disable filter */
        {
            _WlanRxFilterOperationCommandBuff_t     RxFilterIdMask ;
            memset(RxFilterIdMask.FilterIdMask, 0xFF , 8);
            retVal = sl_WlanRxFilterSet(SL_ENABLE_DISABLE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                                sizeof(_WlanRxFilterOperationCommandBuff_t));
            ASSERT_ON_ERROR(retVal);
        }

        break;
    }

    return FilterId;
}

/*!
    \brief This function display the frame subtype of the received packet.

    \param[in]   none

    \return         None

    \note

    \warning
*/
static void PrintFrameSubtype(_u8 MAC)
{
    printf("Frame Subtype:\n");
    switch (MAC)
    {
        case 0x8:
            printf("Data (%02x)\n",MAC);
            break;

        case 0x40:
            printf("Probe Request (%02x)\n",MAC);
            break;

        case 0x50:
            printf("Probe Response (%02x)\n",MAC);
            break;

        case 0x80:
            printf("Beacon (%02x)\n",MAC);
            break;

        case 0x88:
            printf("QOS Data (%02x)\n",MAC);
            break;

        case 0xd4:
            printf("Acknowledgement (%02x)\n",MAC);
            break;

        case 0x0b:
            printf("Authentication (%02x)\n",MAC);
            break;

        case 0x1c:
            printf("Clear to Send (%02x)\n",MAC);
            break;

        case 0x1b:
            printf("Request to Send (%02x)\n",MAC);
            break;

        case 0x09:
            printf("ATIM (%02x)\n",MAC);
            break;

        case 0x19:
            printf("802.11 Block Acknowledgement (%02x)\n",MAC);
            break;

        default:
            printf("Unknown (%02x)\n",MAC);
            break;
    }
}

/*!
    \brief This function displays the parameter required to create the filter
           of selected type.

    \param[in]   sel : filter type selected

    \return         None

    \note

    \warning
*/
static void PrintFilterType(int sel)
{
    printf("\nFilter Parameter:\n");
    switch(sel)
    {
        case 1:
            printf("Source MAC Address\n");
            break;
        case 2:
            printf("Destination MAC Address\n");
            break;
        case 3:
            printf("BSSID\n");
            break;
        case 4:
            printf("Frame type\n");
            break;
        case 5:
            printf("Frame Subtype\n");
            break;
        case 6:
            printf("Source IP Address\n");
            break;
        case 7:
            printf("Destination IP Address\n");
            break;
        case 8:
            printf("Packet Length\n");
            break;
    }
}



/*!
    \brief This function displays the filter options and read parameters to
            create the filter.

    \param[in]   none

    \return      0 for success, -ve otherwise

    \note

    \warning
*/
static _i32 FiltersMenu()
{
    int  selection = -1;
    int   equalYesNo = -1;
    int   dropYesNo = -1;
    int  frameTypeLength = 0;
    int  fatherId = 0;
    int  macAddress[MAC_ADDR_LENGTH] = {'\0'};
    int  ipAddress[IP_ADDR_LENGTH] = {'\0'};
    int   filterData[MAC_ADDR_LENGTH] = {'\0'};
    int  retVal = -1;
    int  idx = 0;

    printf("\nPlease select a filter parameter:\n");
    printf("\n1. Source MAC address\n");
    printf("2. Destination MAC address\n");
    printf("3. BSSID\n");
    printf("4. Frame type\n");
    printf("5. Frame subtype\n");
    printf("6. Source IP address\n");
    printf("7. Destination IP address\n");
    printf("8. Packet length\n");
    printf("9. Remove filter and exit menu\n");
    printf("10. Enable filter and exit menu\n");
    printf("Selection: \n");
    while(1)
    {
        fflush(stdin);
        scanf("%d",&selection);

        switch(selection)
        {
            case 1:
            case 2:
            case 3:
                PrintFilterType(selection);
                printf("\nEnter the MAC address (xx:xx:xx:xx:xx:xx): \n");
                fflush(stdin);
                scanf("%2x:%2x:%2x:%2x:%2x:%2x", &macAddress[0],
                                                 &macAddress[1],
                                                 &macAddress[2],
                                                 &macAddress[3],
                                                 &macAddress[4],
                                                 &macAddress[5]);
                for(idx = 0 ; idx < MAC_ADDR_LENGTH ; idx++ )
                {
                    filterData[idx] = (int)macAddress[idx];
                }
                break;

            case 4:
                PrintFilterType(selection);
                printf("Enter the frame type byte: \n");
                fflush(stdin);
                scanf("%2x",&frameTypeLength);
                filterData[0] = (int)frameTypeLength;
                break;

            case 5:
                PrintFilterType(selection);

                printf("\nCreating a frame subtype filter requires a parent frame type filter\r\n");

                printf("Enter the frame type byte: \n");
                fflush(stdin);
                scanf("%2x",&frameTypeLength);
                filterData[0] = (int)frameTypeLength;
                break;

            case 6:
            case 7:
                PrintFilterType(selection);
                printf("Enter the IP address: \n");
                fflush(stdin);
                scanf("%u.%u.%u.%u",&ipAddress[0],&ipAddress[1],&ipAddress[2],
                                                                 &ipAddress[3]);
                for(idx = 0 ; idx < IP_ADDR_LENGTH ; idx++ )
                {
                    filterData[idx] = (_u8)ipAddress[idx];
                }
                break;

            case 8:
                PrintFilterType(selection);
                printf("Enter desired length in Bytes (Maximum = 1472): \n");
                fflush(stdin);
                scanf("%u",&frameTypeLength);
                *(int *)filterData = SWAP_UINT32(frameTypeLength);
                printf("Target what lengths? (h - Higher than %u | l - Lower than %u): \n",
                                                  frameTypeLength,frameTypeLength);
                fflush(stdin);
                scanf("%c",&equalYesNo);
                printf("Drop packets or not? (y/n): \n");
                fflush(stdin);
                scanf("%c",&dropYesNo);
                printf("Enter filter ID of parent. Otherwise 0: \n");
                fflush(stdin);
                scanf("%u", &fatherId);
                retVal= RxFiltersExample('1',selection,filterData,equalYesNo,dropYesNo,
                                                                   (int)fatherId);
                ASSERT_ON_ERROR(retVal);

                printf("\nPlease select a filter parameter:\n");
                printf("\n1. Source MAC address\n");
                printf("2. Destination MAC address\n");
                printf("3. BSSID\n");
                printf("4. Frame type\n");
                printf("5. Frame subtype\n");
                printf("6. Source IP address\n");
                printf("7. Destination IP address\n");
                printf("8. Packet length\n");
                printf("9. Remove filter and exit menu\n");
                printf("10. Enable filter and exit menu\n");
                printf("\nSelection: \n");
                continue;
                break;

            case 9:
                retVal = RxFiltersExample('2',0,NULL,0,0,0);
                ASSERT_ON_ERROR(retVal);

                return SUCCESS;
                break;

            case 10:
                retVal = RxFiltersExample('3',0,NULL,0,0,0);
                ASSERT_ON_ERROR(retVal);

                return SUCCESS;
                break;

            default:
                continue;
        }

        printf("Equal or not equal? (y/n): \n");
        fflush(stdin);
        scanf("%c",&equalYesNo);

        printf("Drop the packet? (y/n): \n");
        fflush(stdin);
        scanf("%c",&dropYesNo);

        printf("Enter filter ID of parent. Otherwise 0:: \n");
        fflush(stdin);
        scanf("%u", &fatherId, sizeof(fatherId));

        retVal = RxFiltersExample('1', selection, filterData,
                         equalYesNo, dropYesNo, (_i8)fatherId);
        if((retVal < 0) && (retVal != INVALID_PARENT_FILTER_ID))
        {
            return retVal;
        }

        printf("\nPlease select a filter parameter:\n");
        printf("\n1. Source MAC address\n");
        printf("2. Destination MAC address\n");
        printf("3. BSSID\n");
        printf("4. Frame type\n");
        printf("5. Frame subtype\n");
        printf("6. Source IP address\n");
        printf("7. Destination IP address\n");
        printf("8. Packet length\n");
        printf("9. Remove and exit\n");
        printf("10. Enable and exit\n");
        printf("Selection:\n");
    }

    return SUCCESS;
}

/*!
    \brief This function configures the filter based on user input

    \param[in]   none

    \return         0 on sucess, -ve otherwise

    \note

    \warning
*/
static int ChooseFilters()
{
    int retVal = -1;
    int  ch = -1;

    printf("Enter 'f' to configure MAC filters or 'q' to exit: \n");
    fflush(stdin);

    ch = getchar();

    if(ch == 'f' || ch == 'F')
    {
        retVal = FiltersMenu();
        ASSERT_ON_ERROR(retVal);
    }
    else if(ch == 'q' || ch == 'Q')
    {
        //g_Exit = 1;
    }



    return SUCCESS;
}

/*!
    \brief This function opens a raw socket, receives the frames and display them.

    \param[in]   channel    : channel for the raw socket
    \param[in]   numpackets : number of packets to be received

    \return      0 for success, -ve otherwise

    \note

    \warning
*/
static int Sniffer(int channel,int numpackets)
{
    TransceiverRxOverHead_t *frameRadioHeader = 0;
    int MAC[MAX_RECV_BUF_SIZE] = {'\0'};
    int hexempty = 0xcc;

    int retVal = -1;
    int sd = -1;

    /********************* Open Socket for transceiver   *********************/
    sd = sl_Socket(SL_AF_RF,SL_SOCK_RAW,channel);
    ASSERT_ON_ERROR(sd);

    /************************************ Creating filters *****************/
    retVal = ChooseFilters();
    ASSERT_ON_ERROR(retVal);

    /************ Receiving frames from the CC3100 and printing to screen*****/
    if (!g_Exit)
    {
        printf("\nCollecting Packets...\n");

        while(numpackets > 0)
        {
            retVal = sl_Recv(sd,buffer,MAX_RECV_BUF_SIZE,0);
            ASSERT_ON_ERROR(retVal);

            frameRadioHeader = (TransceiverRxOverHead_t *)buffer;
            printf("\nTimestamp: %i microsec\n",frameRadioHeader->timestamp);
            printf("Signal Strength: %i dB\n",frameRadioHeader->rssi);

            memcpy(MAC, buffer, sizeof(buffer));

            PrintFrameSubtype(MAC[8]);

            printf("Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            MAC[12],MAC[13], MAC[14],MAC[15], MAC[16],MAC[17]);

            printf("Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            MAC[18],MAC[19], MAC[20],MAC[21], MAC[22],MAC[23]);

            numpackets--;
         //   Sleep(500);
        }
    }
    retVal = sl_Close(sd);
    ASSERT_ON_ERROR(retVal);
    return SUCCESS;
}

//*****************************************************************************
//
//! main
//!
//! This function
//!        1. Main function for the application.
//!        2. Make sure there is no profile before activating this test.
//!     3. This test is not optimized for current consumption at this stage.
//!
//! \return none
//
//*****************************************************************************

int main() {
	long lRetVal = -1;
	unsigned char policyVal;
	int channel;
	int numpackets;


	//
	// Initialize Board configuration
	//
	BoardInit();

	//
	//
	//Pin muxing
	//
	PinMuxConfig();

	// Configuring UART
	//
	InitTerm();
	DisplayBanner(APPLICATION_NAME);

	InitializeAppVariables();

	//
	// Following function configure the device to default state by cleaning
	// the persistent settings stored in NVMEM (viz. connection profiles &
	// policies, power policy etc)
	//
	// Applications may choose to skip this step if the developer is sure
	// that the device is in its default state at start of applicaton
	//
	// Note that all profiles and persistent settings that were done on the
	// device will be lost
	//
	lRetVal = ConfigureSimpleLinkToDefaultState();
	if (lRetVal < 0) {
		if (DEVICE_NOT_IN_STATION_MODE == lRetVal)
			UART_PRINT(
					"Failed to configure the device in its default state \n\r");
		LOOP_FOREVER()
		;
	}
	printf("Device is configured in default state \n\r");

	CLR_STATUS_BIT_ALL(g_ulStatus);

	//
	// Assumption is that the device is configured in station mode already
	// and it is in its default state
	//
	lRetVal = sl_Start(0, 0, 0);
	if (lRetVal < 0 || ROLE_STA != lRetVal) {
		UART_PRINT("Failed to start the device \n\r");
		LOOP_FOREVER()
		;
	}

	printf("Device started as STATION \n");

	//
	// reset all network policies
	//
	lRetVal = sl_WlanPolicySet( SL_POLICY_CONNECTION,
			SL_CONNECTION_POLICY(0, 0, 0, 0, 0), &policyVal,
			1 /*PolicyValLen*/);
	if (lRetVal < 0) {
		printf("Failed to set policy \n");
		LOOP_FOREVER()
		;
	}

	printf("The command prompt can display a maximum of 50 packets.\n\n");
	    printf("Please input desired channel number and click \"Enter\".\n");
	    printf("Valid channels range from 1 to 13 (11 is standard): \n");
	    fflush(stdin);
	    scanf("%d",&channel);
	    printf("Please input desired number of packets and click \"Enter\": \n");
	    fflush(stdin);
	    scanf("%d",&numpackets);

	   lRetVal = Sniffer(channel, numpackets);
	        if(lRetVal < 0)
	            LOOP_FOREVER();

}

