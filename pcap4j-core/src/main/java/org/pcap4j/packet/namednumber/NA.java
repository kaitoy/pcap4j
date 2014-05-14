/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;


/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class NA extends NamedNumber<Byte, NA> {

  /**
   *
   */
  private static final long serialVersionUID = -1260181531930282735L;

  /**
   *
   */
  public static final NA N_A
    = new NA((byte)0, "N/A");

  /**
   *
   * @param value
   * @param name
   */
  private NA(Byte value, String name) {
    super(value, name);
  }

  @Override
  public int compareTo(NA o) {
    return value().compareTo(o.value());
  }

}