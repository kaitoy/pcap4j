/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * GTP version
 *
 * @author waveform
 * @since pcap4j 0.9.11
 */
public final class GtpVersion extends NamedNumber<Byte, GtpVersion> {

  /**
   *
   */
  private static final long serialVersionUID = -6737808159892354431L;

  /**
   * Version 1 [GTP-U , GTP-C , GTP']
   */
  public static final GtpVersion GTPv1
    = new GtpVersion((byte)1, "GTPv1");

  /**
   * Version 2 [GTP-C , GTP']
   */
  public static final GtpVersion GTPv2
    = new GtpVersion((byte)2, "GTPv2");

  private static final Map<Byte, GtpVersion> registry
    = new HashMap<Byte, GtpVersion>();

  static {
    registry.put(GTPv1.value(), GTPv1);
    registry.put(GTPv2.value(), GTPv2);
  }

  /**
   *
   * @param value value
   * @param name name
   */
  public GtpVersion(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value value
   * @return a GtpVersion object.
   */
  public static GtpVersion getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return null;
    }
  }

  /**
   *
   * @param version version
   * @return a GtpVersion object.
   */
  public static GtpVersion register(GtpVersion version) {
    return registry.put(version.value(), version);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(GtpVersion o) {
    return value().compareTo(o.value());
  }

}
