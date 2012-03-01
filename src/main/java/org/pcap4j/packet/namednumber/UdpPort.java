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
 * @since pcap4j 0.9.6
 */
public final class UdpPort extends NamedNumber<Short> {

  /**
   *
   */
  private static final long serialVersionUID = -7898348444366318292L;

  //http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml

  /**
   *
   */
  public static final UdpPort SNMP
    = new UdpPort((short)161, "SNMP");

  /**
   *
   */
  public static final UdpPort SNMP_TRAP
    = new UdpPort((short)162, "SNMP Trap");

  private static final Map<Short, UdpPort> registry
    = new HashMap<Short, UdpPort>();

  static {
    for (Field field: UdpPort.class.getFields()) {
      if (field.getType().isAssignableFrom(UdpPort.class)) {
        try {
          UdpPort typeCode = (UdpPort)field.get(null);
          registry.put(typeCode.value(), typeCode);
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

  private UdpPort(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static UdpPort getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new UdpPort(value, "unknown");
    }
  }

  /**
   *
   * @return
   */
  @Override
  public String valueAsString() {
    return String.valueOf(0xFFFF & value());
  }

  @Override
  public int compareTo(Short o) {
    return value().compareTo(o);
  }

}