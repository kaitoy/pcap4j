/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.12
 */
public final class TcpPort extends NamedNumber<Short, TcpPort> {

  /**
   *
   */
  private static final long serialVersionUID = 3906499626286793530L;

  // http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml

  /**
   *
   */
  public static final TcpPort SNMP
    = new TcpPort((short)161, "SNMP");

  /**
   *
   */
  public static final TcpPort SNMP_TRAP
    = new TcpPort((short)162, "SNMP Trap");

  private static final Map<Short, TcpPort> registry
    = new HashMap<Short, TcpPort>();

  static {
    for (Field field: TcpPort.class.getFields()) {
      if (TcpPort.class.isAssignableFrom(field.getType())) {
        try {
          TcpPort f = (TcpPort)field.get(null);
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
  public TcpPort(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a TcpPort object.
   */
  public static TcpPort getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new TcpPort(value, "unknown");
    }
  }

  /**
   *
   * @param port
   * @return a TcpPort object.
   */
  public static TcpPort register(TcpPort port) {
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
  public int compareTo(TcpPort o) {
    return value().compareTo(o.value());
  }

}
