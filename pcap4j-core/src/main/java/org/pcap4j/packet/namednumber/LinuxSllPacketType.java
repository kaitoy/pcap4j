/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * Linux SLL Packet Type
 *
 * @see <a href="https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h">pcap/sll.h</a>
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class LinuxSllPacketType extends NamedNumber<Short, LinuxSllPacketType> {

  /** */
  private static final long serialVersionUID = 8331027096398154722L;

  /** A packet addressed to the local host: 0 */
  public static final LinuxSllPacketType LINUX_SLL_HOST =
      new LinuxSllPacketType((short) 0, "A packet addressed to the local host");

  /** A physical layer broadcast packet: 1 */
  public static final LinuxSllPacketType LINUX_SLL_BROADCAST =
      new LinuxSllPacketType((short) 1, "A physical layer broadcast packet");

  /** A packet sent to a physical layer multicast address: 2 */
  public static final LinuxSllPacketType LINUX_SLL_MULTICAST =
      new LinuxSllPacketType((short) 2, "A packet sent to a physical layer multicast address");

  /** A packet to some other host that has been caught by a device driver in promiscuous mode: 3 */
  public static final LinuxSllPacketType LINUX_SLL_OTHERHOST =
      new LinuxSllPacketType((short) 3, "A packet to some other host");

  /** A packet originated from the local host that is looped back to a packet socket: 4 */
  public static final LinuxSllPacketType LINUX_SLL_OUTGOING =
      new LinuxSllPacketType((short) 4, "A packet originated from the local host");

  private static final Map<Short, LinuxSllPacketType> registry =
      new HashMap<Short, LinuxSllPacketType>();

  static {
    registry.put(LINUX_SLL_HOST.value(), LINUX_SLL_HOST);
    registry.put(LINUX_SLL_BROADCAST.value(), LINUX_SLL_BROADCAST);
    registry.put(LINUX_SLL_MULTICAST.value(), LINUX_SLL_MULTICAST);
    registry.put(LINUX_SLL_OTHERHOST.value(), LINUX_SLL_OTHERHOST);
    registry.put(LINUX_SLL_OUTGOING.value(), LINUX_SLL_OUTGOING);
  }

  /**
   * @param value value
   * @param name name
   */
  public LinuxSllPacketType(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a EtherType object.
   */
  public static LinuxSllPacketType getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new LinuxSllPacketType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a EtherType object.
   */
  public static LinuxSllPacketType register(LinuxSllPacketType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public int compareTo(LinuxSllPacketType o) {
    return value().compareTo(o.value());
  }
}
