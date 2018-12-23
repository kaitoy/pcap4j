/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * ARP Hardware Type
 *
 * @see <a
 *     href="http://www.iana.org/assignments/arp-parameters/arp-parameters.xml#arp-parameters-2">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class ArpHardwareType extends NamedNumber<Short, ArpHardwareType> {

  /** */
  private static final long serialVersionUID = -4679864421785826910L;

  /** Ethernet (10Mb): 1 */
  public static final ArpHardwareType ETHERNET = new ArpHardwareType((short) 1, "Ethernet (10Mb)");

  /** Experimental Ethernet (3Mb): 2 */
  public static final ArpHardwareType EXPERIMENTAL_ETHERNET =
      new ArpHardwareType((short) 2, "Experimental Ethernet (3Mb)");

  /** Amateur Radio AX.25: 3 */
  public static final ArpHardwareType AMATEUR_RADIO_AX_25 =
      new ArpHardwareType((short) 3, "Amateur Radio AX.25");

  /** Proteon ProNET Token Ring: 4 */
  public static final ArpHardwareType PROTEON_PRONET_TOKEN_RING =
      new ArpHardwareType((short) 4, "Proteon ProNET Token Ring");

  /** Chaos: 5 */
  public static final ArpHardwareType CHAOS = new ArpHardwareType((short) 5, "Chaos");

  /** IEEE 802 Networks: 6 */
  public static final ArpHardwareType IEEE_802_NETWORKS =
      new ArpHardwareType((short) 6, "IEEE 802 Networks");

  /** ARCNET: 7 */
  public static final ArpHardwareType ARCNET = new ArpHardwareType((short) 7, "ARCNET");

  /** Hyperchannel: 8 */
  public static final ArpHardwareType HYPERCHANNEL = new ArpHardwareType((short) 8, "Hyperchannel");

  /** Lanstar: 9 */
  public static final ArpHardwareType LANSTAR = new ArpHardwareType((short) 9, "Lanstar");

  /** Autonet Short Address: 10 */
  public static final ArpHardwareType AUTONET_SHORT_ADDRESS =
      new ArpHardwareType((short) 10, "Autonet Short Address");

  /** LocalTalk: 11 */
  public static final ArpHardwareType LOCALTALK = new ArpHardwareType((short) 11, "LocalTalk");

  /** LocalNet (IBM PCNet or SYTEK LocalNET): 12 */
  public static final ArpHardwareType LOCALNET =
      new ArpHardwareType((short) 12, "LocalNet (IBM PCNet or SYTEK LocalNET)");

  /** Ultra link: 13 */
  public static final ArpHardwareType ULTRA_LINK = new ArpHardwareType((short) 13, "Ultra link");

  /** SMDS: 14 */
  public static final ArpHardwareType SMDS = new ArpHardwareType((short) 14, "SMDS");

  /** Frame Relay: 15 */
  public static final ArpHardwareType FRAME_RELAY = new ArpHardwareType((short) 15, "Frame Relay");

  /** Asynchronous Transmission Mode (ATM): 16 */
  public static final ArpHardwareType ATM_16 =
      new ArpHardwareType((short) 16, "Asynchronous Transmission Mode (ATM)");

  /** HDLC: 17 */
  public static final ArpHardwareType HDLC = new ArpHardwareType((short) 17, "HDLC");

  /** Fibre Channel: 18 */
  public static final ArpHardwareType FIBRE_CHANNEL =
      new ArpHardwareType((short) 18, "Fibre Channel");

  /** Asynchronous Transmission Mode (ATM): 19 */
  public static final ArpHardwareType ATM_19 =
      new ArpHardwareType((short) 19, "Asynchronous Transmission Mode (ATM)");

  /** Serial Line: 20 */
  public static final ArpHardwareType SERIAL_LINE = new ArpHardwareType((short) 20, "Serial Line");

  /** Asynchronous Transmission Mode (ATM): 21 */
  public static final ArpHardwareType ATM_21 =
      new ArpHardwareType((short) 21, "Asynchronous Transmission Mode (ATM)");

  /** MIL-STD-188-220: 22 */
  public static final ArpHardwareType MIL_STD_188_220 =
      new ArpHardwareType((short) 22, "MIL-STD-188-220");

  /** Metricom: 23 */
  public static final ArpHardwareType METRICOM = new ArpHardwareType((short) 23, "Metricom");

  /** IEEE 1394.1995: 24 */
  public static final ArpHardwareType IEEE_1394_1995 =
      new ArpHardwareType((short) 24, "IEEE 1394.1995");

  /** MAPOS: 25 */
  public static final ArpHardwareType MAPOS = new ArpHardwareType((short) 25, "MAPOS");

  /** Twinaxial: 26 */
  public static final ArpHardwareType TWINAXIAL = new ArpHardwareType((short) 26, "Twinaxial");

  /** EUI-64: 27 */
  public static final ArpHardwareType EUI_64 = new ArpHardwareType((short) 27, "EUI-64");

  /** HIPARP: 28 */
  public static final ArpHardwareType HIPARP = new ArpHardwareType((short) 28, "HIPARP");

  /** IP and ARP over ISO 7816-3: 29 */
  public static final ArpHardwareType IP_AND_ARP_OVER_ISO_7816_3 =
      new ArpHardwareType((short) 29, "IP and ARP over ISO 7816-3");

  /** ARPSec: 30 */
  public static final ArpHardwareType ARPSEC = new ArpHardwareType((short) 30, "ARPSec");

  /** IPsec tunnel: 31 */
  public static final ArpHardwareType IPSEC_TUNNEL =
      new ArpHardwareType((short) 31, "IPsec tunnel");

  /** InfiniBand: 32 */
  public static final ArpHardwareType INFINIBAND = new ArpHardwareType((short) 32, "InfiniBand");

  /** TIA-102 Project 25 Common Air Interface (CAI): 33 */
  public static final ArpHardwareType CAI =
      new ArpHardwareType((short) 33, "TIA-102 Project 25 Common Air Interface (CAI)");

  /** Wiegand Interface: 34 */
  public static final ArpHardwareType WIEGAND_INTERFACE =
      new ArpHardwareType((short) 34, "Wiegand Interface");

  /** Pure IP: 35 */
  public static final ArpHardwareType PURE_IP = new ArpHardwareType((short) 35, "Pure IP");

  /** HW_EXP1: 36 */
  public static final ArpHardwareType HW_EXP1 = new ArpHardwareType((short) 36, "HW_EXP1");

  /** HFI: 37 */
  public static final ArpHardwareType HFI = new ArpHardwareType((short) 37, "HFI");

  /** HW_EXP2: 256 */
  public static final ArpHardwareType HW_EXP2 = new ArpHardwareType((short) 256, "HW_EXP2");

  private static final Map<Short, ArpHardwareType> registry =
      new HashMap<Short, ArpHardwareType>(40);

  static {
    registry.put(ETHERNET.value(), ETHERNET);
    registry.put(EXPERIMENTAL_ETHERNET.value(), EXPERIMENTAL_ETHERNET);
    registry.put(AMATEUR_RADIO_AX_25.value(), AMATEUR_RADIO_AX_25);
    registry.put(PROTEON_PRONET_TOKEN_RING.value(), PROTEON_PRONET_TOKEN_RING);
    registry.put(CHAOS.value(), CHAOS);
    registry.put(IEEE_802_NETWORKS.value(), IEEE_802_NETWORKS);
    registry.put(ARCNET.value(), ARCNET);
    registry.put(HYPERCHANNEL.value(), HYPERCHANNEL);
    registry.put(LANSTAR.value(), LANSTAR);
    registry.put(AUTONET_SHORT_ADDRESS.value(), AUTONET_SHORT_ADDRESS);
    registry.put(LOCALTALK.value(), LOCALTALK);
    registry.put(LOCALNET.value(), LOCALNET);
    registry.put(ULTRA_LINK.value(), ULTRA_LINK);
    registry.put(SMDS.value(), SMDS);
    registry.put(FRAME_RELAY.value(), FRAME_RELAY);
    registry.put(ATM_16.value(), ATM_16);
    registry.put(HDLC.value(), HDLC);
    registry.put(FIBRE_CHANNEL.value(), FIBRE_CHANNEL);
    registry.put(ATM_19.value(), ATM_19);
    registry.put(SERIAL_LINE.value(), SERIAL_LINE);
    registry.put(ATM_21.value(), ATM_21);
    registry.put(MIL_STD_188_220.value(), MIL_STD_188_220);
    registry.put(METRICOM.value(), METRICOM);
    registry.put(IEEE_1394_1995.value(), IEEE_1394_1995);
    registry.put(MAPOS.value(), MAPOS);
    registry.put(TWINAXIAL.value(), TWINAXIAL);
    registry.put(EUI_64.value(), EUI_64);
    registry.put(HIPARP.value(), HIPARP);
    registry.put(IP_AND_ARP_OVER_ISO_7816_3.value(), IP_AND_ARP_OVER_ISO_7816_3);
    registry.put(ARPSEC.value(), ARPSEC);
    registry.put(IPSEC_TUNNEL.value(), IPSEC_TUNNEL);
    registry.put(INFINIBAND.value(), INFINIBAND);
    registry.put(CAI.value(), CAI);
    registry.put(WIEGAND_INTERFACE.value(), WIEGAND_INTERFACE);
    registry.put(PURE_IP.value(), PURE_IP);
    registry.put(HW_EXP1.value(), HW_EXP1);
    registry.put(HFI.value(), HFI);
    registry.put(HW_EXP2.value(), HW_EXP2);
  }

  /**
   * @param value value
   * @param name name
   */
  public ArpHardwareType(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a ArpHardwareType object.
   */
  public static ArpHardwareType getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new ArpHardwareType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a ArpHardwareType object.
   */
  public static ArpHardwareType register(ArpHardwareType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(ArpHardwareType o) {
    return value().compareTo(o.value());
  }
}
