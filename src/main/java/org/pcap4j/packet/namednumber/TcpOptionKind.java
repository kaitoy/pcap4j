/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
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
public final class TcpOptionKind extends NamedNumber<Byte> {

  // http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml

  /**
   *
   */
  private static final long serialVersionUID = -7033971699970069137L;

  /**
   *
   */
  public static final TcpOptionKind END_OF_OPTION_LIST
    = new TcpOptionKind((byte)0, "End of Option List");

  /**
   *
   */
  public static final TcpOptionKind NO_OPERATION
    = new TcpOptionKind((byte)1, "No Operation");

  /**
   *
   */
  public static final TcpOptionKind MAXIMUM_SEGMENT_SIZE
    = new TcpOptionKind((byte)2, "Maximum Segment Size");

  private static final Map<Byte, TcpOptionKind> registry
    = new HashMap<Byte, TcpOptionKind>();

  static {
    for (Field field: TcpOptionKind.class.getFields()) {
      if (TcpOptionKind.class.isAssignableFrom(field.getType())) {
        try {
          TcpOptionKind f = (TcpOptionKind)field.get(null);
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
  public TcpOptionKind(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static TcpOptionKind getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new TcpOptionKind(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return
   */
  public static TcpOptionKind register(TcpOptionKind type) {
    return registry.put(type.value(), type);
  }

  @Override
  public int compareTo(Byte o) { return value().compareTo(o); }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

}