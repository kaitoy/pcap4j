/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

/**
 * Transport layer Port
 *
 * @author Ferran Altimiras
 * @since pcap4j 1.7.5
 */
public abstract class Port extends NamedNumber<Short, Port> {

  /**
   * @param value value
   * @param name name
   */
  public Port(Short value, String name) {
    super(value, name);
  }

  /** @return the value of this object as an int. */
  public int valueAsInt() {
    return 0xFFFF & value();
  }

  @Override
  public String valueAsString() {
    return String.valueOf(valueAsInt());
  }

  @Override
  public int compareTo(Port o) {
    return value().compareTo(o.value());
  }
}
