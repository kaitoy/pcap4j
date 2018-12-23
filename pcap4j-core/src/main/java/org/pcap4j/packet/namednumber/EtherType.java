/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 * Ether Type
 *
 * @see <a
 *     href="http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class EtherType extends NamedNumber<Short, EtherType> {

  /** */
  private static final long serialVersionUID = 7866667243677334444L;

  /** */
  public static final int IEEE802_3_MAX_LENGTH = 1500;

  /** IPv4: 0x0800 */
  public static final EtherType IPV4 = new EtherType((short) 0x0800, "IPv4");

  /** ARP: 0x0806 */
  public static final EtherType ARP = new EtherType((short) 0x0806, "ARP");

  /** IEEE 802.1Q VLAN-tagged frames: 0x8100 */
  public static final EtherType DOT1Q_VLAN_TAGGED_FRAMES =
      new EtherType((short) 0x8100, "IEEE 802.1Q VLAN-tagged frames");

  /** RARP: 0x8035 */
  public static final EtherType RARP = new EtherType((short) 0x8035, "RARP");

  /** Appletalk: 0x809b */
  public static final EtherType APPLETALK = new EtherType((short) 0x809b, "Appletalk");

  /** IPv6: 0x86dd */
  public static final EtherType IPV6 = new EtherType((short) 0x86dd, "IPv6");

  /** PPP: 0x880b */
  public static final EtherType PPP = new EtherType((short) 0x880b, "PPP");

  /** MPLS: 0x8847 */
  public static final EtherType MPLS = new EtherType((short) 0x8847, "MPLS");

  /** PPPoE Discovery Stage: 0x8863 */
  public static final EtherType PPPOE_DISCOVERY_STAGE =
      new EtherType((short) 0x8863, "PPPoE Discovery Stage");

  /** PPPoE Session Stage: 0x8864 */
  public static final EtherType PPPOE_SESSION_STAGE =
      new EtherType((short) 0x8864, "PPPoE Session Stage");

  private static final Map<Short, EtherType> registry = new HashMap<Short, EtherType>();

  static {
    registry.put(IPV4.value(), IPV4);
    registry.put(ARP.value(), ARP);
    registry.put(DOT1Q_VLAN_TAGGED_FRAMES.value(), DOT1Q_VLAN_TAGGED_FRAMES);
    registry.put(RARP.value(), RARP);
    registry.put(APPLETALK.value(), APPLETALK);
    registry.put(IPV6.value(), IPV6);
    registry.put(PPP.value(), PPP);
    registry.put(MPLS.value(), MPLS);
    registry.put(PPPOE_DISCOVERY_STAGE.value(), PPPOE_DISCOVERY_STAGE);
    registry.put(PPPOE_SESSION_STAGE.value(), PPPOE_SESSION_STAGE);
  }

  /**
   * @param value value
   * @param name name
   */
  public EtherType(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a EtherType object.
   */
  public static EtherType getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else if ((value & 0xFFFF) <= IEEE802_3_MAX_LENGTH) {
      return new EtherType(value, "Length");
    } else {
      return new EtherType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a EtherType object.
   */
  public static EtherType register(EtherType type) {
    return registry.put(type.value(), type);
  }

  /** @return a string representation of this value. */
  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(EtherType o) {
    return value().compareTo(o.value());
  }

  @Override
  public String toString() {
    if ((value() & 0xFFFF) <= IEEE802_3_MAX_LENGTH) {
      StringBuilder sb = new StringBuilder(70);
      return sb.append("Length (").append(value() & 0xFFFF).append(" bytes)").toString();
    } else {
      return super.toString();
    }
  }
}
