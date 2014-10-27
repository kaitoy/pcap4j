/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.3.1
 */
public final class LinuxSllPacketType extends NamedNumber<Short, LinuxSllPacketType> {

  // pcap/sll.h

  /**
   *
   */
  private static final long serialVersionUID = 8331027096398154722L;

  /**
   * A packet addressed to the local host.
   */
  public static final LinuxSllPacketType LINUX_SLL_HOST
    = new LinuxSllPacketType((short)0, "A packet addressed to the local host");

  /**
   * A physical layer broadcast packet.
   */
  public static final LinuxSllPacketType LINUX_SLL_BROADCAST
    = new LinuxSllPacketType((short)1, "A physical layer broadcast packet");

  /**
   * A packet sent to a physical layer multicast address.
   */
  public static final LinuxSllPacketType LINUX_SLL_MULTICAST
    = new LinuxSllPacketType((short)2, "A packet sent to a physical layer multicast address");

  /**
   * A packet to some other host that has been caught by a device driver in promiscuous mode.
   */
  public static final LinuxSllPacketType LINUX_SLL_OTHERHOST
    = new LinuxSllPacketType((short)3, "A packet to some other host");

  /**
   * A packet originated from the local host that is looped back to a packet socket.
   */
  public static final LinuxSllPacketType LINUX_SLL_OUTGOING
    = new LinuxSllPacketType((short)4, "A packet originated from the local host");

  private static final Map<Short, LinuxSllPacketType> registry
    = new HashMap<Short, LinuxSllPacketType>();

  static {
    for (Field field: LinuxSllPacketType.class.getFields()) {
      if (LinuxSllPacketType.class.isAssignableFrom(field.getType())) {
        try {
          LinuxSllPacketType f = (LinuxSllPacketType)field.get(null);
          registry.put(f.value(), f);
        } catch (IllegalArgumentException e) {
          throw new AssertionError(e);
        } catch (IllegalAccessException e) {
          throw new AssertionError(e);
        } catch (NullPointerException e) {
          continue;
        }
      }
    }
  }

  /**
   *
   * @param value
   * @param name
   */
  public LinuxSllPacketType(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a EtherType object.
   */
  public static LinuxSllPacketType getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new LinuxSllPacketType(value, "unknown");
    }
  }

  /**
   *
   * @param type
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