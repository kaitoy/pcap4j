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
 * @since pcap4j 0.9.1
 */
public final class DataLinkType extends NamedNumber<Integer, DataLinkType> {

  /**
   *
   */
  private static final long serialVersionUID = -4299486028394578120L;

  // pcap/bpf.h

  /**
   *
   */
  public static final DataLinkType NULL
    = new DataLinkType(0, "Null"); // BSD loopback encapsulation

  /**
   *
   */
  public static final DataLinkType EN10MB
    = new DataLinkType(1, "Ethernet"); // Ethernet (10Mb, 100Mb, 1000Mb, and up)

  /**
   *
   */
  public static final DataLinkType IEEE802
    = new DataLinkType(6, "Token Ring"); // 802.5 Token Ring

  /**
   *
   */
  public static final DataLinkType PPP
    = new DataLinkType(9, "PPP"); // Point-to-point Protocol

  /**
   *
   */
  public static final DataLinkType FDDI
    = new DataLinkType(10, "FDDI"); // FDDI

  /**
   *
   */
  public static final DataLinkType IEEE802_11
    = new DataLinkType(105, "Wireless"); // IEEE 802.11 wireless

  /**
   *
   */
  public static final DataLinkType DOCSIS
    = new DataLinkType(143, "DOCSIS"); // DOCSIS

  private static final Map<Integer, DataLinkType> registry
    = new HashMap<Integer, DataLinkType>();

  static {
    for (Field field: DataLinkType.class.getFields()) {
      if (DataLinkType.class.isAssignableFrom(field.getType())) {
        try {
          DataLinkType f = (DataLinkType)field.get(null);
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
  public DataLinkType(Integer value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a DataLinkType object.
   */
  public static DataLinkType getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new DataLinkType(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return a DataLinkType object.
   */
  public static DataLinkType register(DataLinkType type) {
    return registry.put(type.value(), type);
  }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(DataLinkType o) {
    return value().compareTo(o.value());
  }

}