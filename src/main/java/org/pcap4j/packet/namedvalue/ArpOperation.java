/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namedvalue;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public
final class ArpOperation
extends NamedNumber<Short> implements Comparable<Short> {

  // http://www.iana.org/assignments/arp-parameters/arp-parameters.xml#arp-parameters-1

  /**
   *
   */
  public static final ArpOperation REQUEST
    = new ArpOperation((short)1, "REQUEST");

  /**
   *
   */
  public static final ArpOperation REPLY
    = new ArpOperation((short)2, "REPLY");

  private static Map<Short, ArpOperation> registry
    = new HashMap<Short, ArpOperation>();

  static {
    for (Field field: ArpOperation.class.getFields()) {
      if (field.getType().isAssignableFrom(ArpOperation.class)) {
        try {
          ArpOperation typeCode = (ArpOperation)field.get(null);
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

  private ArpOperation(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static ArpOperation getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new ArpOperation(value, "unknown");
    }
  }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  /**
   *
   */
  public int compareTo(Short o) {
    return value().compareTo(o);
  }

}