/*
 * Snapintosh Unified Wireless Stack
 *
 * Ordered compilation parts for:
 *  1. NIST P-256 ECDH, RFC 4493 AES-128-CMAC (f4/f5/f6/g2), KDF-SHA-256
 *  2. QCC2072 WMI + macOS 26A428 IO80211InfraProtocol WCL Scan/Assoc/Key/PM/TWT
 *  3. Bluetooth 5.4 HCI/L2CAP & LE Secure Connections SMP
 *  4. Apple Wireless Direct Link (AWDL) & AirDrop 802.11 Engine
 */

#include <string.h>
#include "wireless-stack.h"

#include "wireless-stack/crypto.c"
#include "wireless-stack/wifi-qcc2072.c"
#include "wireless-stack/wifi-roam-pm.c"
#include "wireless-stack/bt-smp.c"
#include "wireless-stack/awdl.c"
