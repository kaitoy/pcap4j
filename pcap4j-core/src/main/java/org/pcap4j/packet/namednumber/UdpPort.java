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
      if (UdpPort.class.isAssignableFrom(field.getType())) {
        try {
          UdpPort f = (UdpPort)field.get(null);
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
  public UdpPort(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a UdpPort object.
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
   * @param port
   * @return a UdpPort object.
   */
  public static UdpPort register(UdpPort port) {
    return registry.put(port.value(), port);
  }

  /**
   * @return the value of this object as an int.
   */
  public int valueAsInt() {
    return 0xFFFF & value();
  }

  /**
   *
   * @return a string representation of this value.
   */
  @Override
  public String valueAsString() {
    return String.valueOf(valueAsInt());
  }

  @Override
  public int compareTo(Short o) {
    return value().compareTo(o);
  }

}