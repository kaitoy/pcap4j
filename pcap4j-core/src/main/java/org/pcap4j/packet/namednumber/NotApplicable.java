/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;


/**
 * N/A
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class NotApplicable extends NamedNumber<Byte, NotApplicable> {

  /**
   *
   */
  private static final long serialVersionUID = -1260181531930282735L;

  /**
   *
   */
  public static final NotApplicable UNKNOWN
    = new NotApplicable((byte)0, "Unknown");

  /**
   *
   */
  public static final NotApplicable FRAGMENTED
    = new NotApplicable((byte)1, "Fragmented");

  /**
   *
   */
  public static final NotApplicable COMPRESSED
    = new NotApplicable((byte)2, "Compressed");

  /**
   *
   */
  public static final NotApplicable ENCRYPTED
    = new NotApplicable((byte)3, "Encrypted");

  /**
   *
   */
  public static final NotApplicable UNKNOWN_IP_V6_EXTENSION
    = new NotApplicable((byte)4, "Unknown IPv6 Extension");

  /**
   *
   * @param value
   * @param name
   */
  private NotApplicable(Byte value, String name) {
    super(value, name);
  }

  @Override
  public int compareTo(NotApplicable o) {
    return value().compareTo(o.value());
  }

}