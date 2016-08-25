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
 * GTP code
 *
 * @see <a href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI TS 129 060 V12.6.0</a>
 * @author Waveform
 * @since pcap4j 1.6.6
 */
public final class GtpCode extends NamedNumber<Byte, GtpCode> {

  /**
   *
   */
  private static final long serialVersionUID = -6737808159892354431L;

  /**
   * [GTP-U]
   */
  public static final GtpCode GTP_U
    = new GtpCode((byte)1, "GTP_U");

  /**
   * [GTP-C]
   */
  public static final GtpCode GTP_C
    = new GtpCode((byte)1, "GTP_C");

  /**
   * [GTP']
   */
  public static final GtpCode GTP_
    = new GtpCode((byte)0, "GTP'");

  private static  Map<Byte , GtpCode> map ;
  private static final Map<GtpVersion , Map<Byte, GtpCode>> registry
    = new HashMap<GtpVersion , Map<Byte, GtpCode>>();

  static {
    map = new HashMap<Byte , GtpCode>();
    map.put(GTP_U.value(), GTP_U);
    map.put(GTP_C.value(), GTP_C);
    map.put(GTP_.value(), GTP_);
    registry.put(GtpVersion.GTPv1, map);
    map = new HashMap<Byte , GtpCode>();
    map.put(GTP_C.value(), GTP_C);
    map.put(GTP_.value(), GTP_);
    registry.put(GtpVersion.GTPv2, map);
  }

  /**
   *
   * @param value value
   * @param name name
   */
  public GtpCode(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value value
   * @param version version
   * @return a GtpCode object.
   */
  public static GtpCode getInstance(GtpVersion version , Byte value) {
    if (registry.containsKey(version) && registry.get(version).containsKey(value)) {
      return registry.get(version).get(value);
    }
    else {
      return null;
    }
  }

  /**
   *
   * @param version version
   * @param code code
   * @return a GtpCode object.
   */
  public static GtpCode register(GtpVersion version, GtpCode code) {
  Map<Byte , GtpCode>map = new HashMap<Byte , GtpCode>();
  map.put(code.value(), code);
    registry.put(version, map);
    return code;
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(GtpCode o) {
    return value().compareTo(o.value());
  }

}
