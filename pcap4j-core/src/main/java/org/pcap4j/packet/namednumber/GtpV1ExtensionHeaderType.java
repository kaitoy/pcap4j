/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 * GTPv1 Extension Header Type
 *
 * @see <a
 *     href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI
 *     TS 129 060 V12.6.0</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class GtpV1ExtensionHeaderType extends NamedNumber<Byte, GtpV1ExtensionHeaderType> {

  /** */
  private static final long serialVersionUID = -4403955365412522031L;

  /** No more extension headers: 0000 0000 */
  public static final GtpV1ExtensionHeaderType NO_MORE_EXTENSION_HEADERS =
      new GtpV1ExtensionHeaderType((byte) 0x00, "No more extension headers");

  /** MBMS support indication: 0000 0001 */
  public static final GtpV1ExtensionHeaderType MBMS_SUPPORT_INDICATION =
      new GtpV1ExtensionHeaderType((byte) 0x01, "MBMS support indication");

  /** MS Info Change Reporting support indication: 0000 0010 */
  public static final GtpV1ExtensionHeaderType MS_INFO_CHANGE_REPORTING_SUPPORT_INDICATION =
      new GtpV1ExtensionHeaderType((byte) 0x02, "MS Info Change Reporting support indication");

  /** PDCP PDU number: 1100 0000 */
  public static final GtpV1ExtensionHeaderType PDCP_PDU_NUMBER =
      new GtpV1ExtensionHeaderType((byte) 0xC0, "PDCP PDU number");

  /** Suspend Request: 1100 0001 */
  public static final GtpV1ExtensionHeaderType SUSPEND_REQUEST =
      new GtpV1ExtensionHeaderType((byte) 0xC1, "Suspend Request");

  /** Suspend Response: 1100 0010 */
  public static final GtpV1ExtensionHeaderType SUSPEND_RESPONSE =
      new GtpV1ExtensionHeaderType((byte) 0xC2, "Suspend Response");

  /** PDU Session Container: 1000 0101 */
  public static final GtpV1ExtensionHeaderType PDU_SESSION_CONTAINER =
      new GtpV1ExtensionHeaderType((byte) 0x85, "PDU Session Container");

  private static final Map<Byte, GtpV1ExtensionHeaderType> registry =
      new HashMap<Byte, GtpV1ExtensionHeaderType>();

  static {
    registry.put(NO_MORE_EXTENSION_HEADERS.value(), NO_MORE_EXTENSION_HEADERS);
    registry.put(MBMS_SUPPORT_INDICATION.value(), MBMS_SUPPORT_INDICATION);
    registry.put(
        MS_INFO_CHANGE_REPORTING_SUPPORT_INDICATION.value(),
        MS_INFO_CHANGE_REPORTING_SUPPORT_INDICATION);
    registry.put(PDCP_PDU_NUMBER.value(), PDCP_PDU_NUMBER);
    registry.put(SUSPEND_REQUEST.value(), SUSPEND_REQUEST);
    registry.put(SUSPEND_RESPONSE.value(), SUSPEND_RESPONSE);
    registry.put(PDU_SESSION_CONTAINER.value(), PDU_SESSION_CONTAINER);
  }

  /** @return a ComprehensionRequirement object. */
  public ComprehensionRequirement getComprehensionRequirement() {
    int val = (value() >> 6) & 0x03;
    return ComprehensionRequirement.values()[val];
  }

  /**
   * @param value value
   * @param name name
   */
  public GtpV1ExtensionHeaderType(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a GtpV1MessageType object.
   */
  public static GtpV1ExtensionHeaderType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new GtpV1ExtensionHeaderType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a GtpV1MessageType object.
   */
  public static GtpV1ExtensionHeaderType register(GtpV1ExtensionHeaderType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(GtpV1ExtensionHeaderType o) {
    return value().compareTo(o.value());
  }

  /**
   * Comprehension requirement of Extension Header Type (Definition of bits 7 and 8 of the Extension
   * Header Type)
   *
   * @see <a
   *     href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI
   *     TS 129 060 V12.6.0</a>
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public static enum ComprehensionRequirement {

    /**
     * Comprehension of this extension header is not required. An Intermediate Node shall forward it
     * to any Receiver Endpoint
     */
    NOT_REQUIRED_SHALL_FORWARD,

    /**
     * Comprehension of this extension header is not required. An Intermediate Node shall discard
     * the Extension Header Content and not forward it to any Receiver Endpoint. Other extension
     * headers shall be treated independently of this extension header.
     */
    NOT_REQUIRED_SHALL_DISCARD,

    /**
     * Comprehension of this extension header is required by the Endpoint Receiver but not by an
     * Intermediate Node. An Intermediate Node shall forward the whole field to the Endpoint
     * Receiver.
     */
    REQUIRED_BY_ENDPOINT,

    /**
     * Comprehension of this header type is required by recipient (either Endpoint Receiver or
     * Intermediate Node)
     */
    REQUIRED_BY_RECIPIENT,
  }
}
