/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2015  Pcap4J.org
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

  /** */
  private static final long serialVersionUID = -1260181531930282735L;

  /** Unknown: 0 */
  public static final NotApplicable UNKNOWN = new NotApplicable((byte) 0, "Unknown");

  /** Fragmented: 1 */
  public static final NotApplicable FRAGMENTED = new NotApplicable((byte) 1, "Fragmented");

  /** Compressed: 2 */
  public static final NotApplicable COMPRESSED = new NotApplicable((byte) 2, "Compressed");

  /** Encrypted: 3 */
  public static final NotApplicable ENCRYPTED = new NotApplicable((byte) 3, "Encrypted");

  /** Unknown IPv6 Extension: 4 */
  public static final NotApplicable UNKNOWN_IP_V6_EXTENSION =
      new NotApplicable((byte) 4, "Unknown IPv6 Extension");

  /**
   * @param value value
   * @param name name
   */
  private NotApplicable(Byte value, String name) {
    super(value, name);
  }

  @Override
  public int compareTo(NotApplicable o) {
    return value().compareTo(o.value());
  }
}
