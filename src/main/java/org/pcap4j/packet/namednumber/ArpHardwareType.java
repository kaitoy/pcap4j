/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class ArpHardwareType extends NamedNumber<Short> {

  /**
   *
   */
  private static final long serialVersionUID = -4679864421785826910L;

  // http://www.iana.org/assignments/arp-parameters/arp-parameters.xml#hardware-type-rules

  /**
   *
   */
  public static final ArpHardwareType ETHERNET
    = new ArpHardwareType((short)1, "Ethernet(10Mb)");

  /**
   *
   */
  public static final ArpHardwareType EXPERIMENTAL_ETHERNET
    = new ArpHardwareType((short)2, "ExperimentalEthernet(3Mb)");

  /**
   *
   */
  public static final ArpHardwareType FRAME_RELAY
    = new ArpHardwareType((short)15, "FrameRelay");

  /**
   *
   */
  public static final ArpHardwareType IPSEC_TUNNEL
    = new ArpHardwareType((short)31, "IPsec tunnel");

  private static final Map<Short, ArpHardwareType> registry
    = new HashMap<Short, ArpHardwareType>();

  static {
    for (Field field: ArpHardwareType.class.getFields()) {
      if (ArpHardwareType.class.isAssignableFrom(field.getType())) {
        try {
          ArpHardwareType f = (ArpHardwareType)field.get(null);
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
  public ArpHardwareType(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static ArpHardwareType getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new ArpHardwareType(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return
   */
  public static ArpHardwareType register(ArpHardwareType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(Short o) {
    return value().compareTo(o);
  }

}