/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * @see <a
 *     href="https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/15.02.00_60/ts_138415v150200p.pdf">ETSI
 *     TS 138 415 V15.2.0</a>
 * @author Kaito Yamada
 * @since pcap4j 1.8.3
 */
public final class GtpV1ExtPduSessionContainerPduType
    extends NamedNumber<Byte, GtpV1ExtPduSessionContainerPduType> {

  /** */
  private static final long serialVersionUID = -6220918834013752191L;

  /** DL PDU SESSION INFORMATION: 0 */
  public static final GtpV1ExtPduSessionContainerPduType DL_PDU_SESSION_INFORMATION =
      new GtpV1ExtPduSessionContainerPduType((byte) 0, "DL PDU SESSION INFORMATION");

  /** UL PDU SESSION INFORMATION: 1 */
  public static final GtpV1ExtPduSessionContainerPduType UL_PDU_SESSION_INFORMATION =
      new GtpV1ExtPduSessionContainerPduType((byte) 1, "UL PDU SESSION INFORMATION");

  private static final Map<Byte, GtpV1ExtPduSessionContainerPduType> registry =
      new HashMap<Byte, GtpV1ExtPduSessionContainerPduType>();

  static {
    registry.put(DL_PDU_SESSION_INFORMATION.value(), DL_PDU_SESSION_INFORMATION);
    registry.put(UL_PDU_SESSION_INFORMATION.value(), UL_PDU_SESSION_INFORMATION);
  }

  /**
   * @param value value
   * @param name name
   */
  public GtpV1ExtPduSessionContainerPduType(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
          value
              + " is invalid value. PDU type of GTPv1 PDU Session Container must be between 0 and 15");
    }
  }

  /**
   * @param value value
   * @return a GtpV1ExtPduSessionContainerPduType object.
   */
  public static GtpV1ExtPduSessionContainerPduType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new GtpV1ExtPduSessionContainerPduType(value, "unknown");
    }
  }

  /**
   * @param version version
   * @return a GtpV1ExtPduSessionContainerPduType object.
   */
  public static GtpV1ExtPduSessionContainerPduType register(
      GtpV1ExtPduSessionContainerPduType version) {
    return registry.put(version.value(), version);
  }

  @Override
  public int compareTo(GtpV1ExtPduSessionContainerPduType o) {
    return value().compareTo(o.value());
  }
}
