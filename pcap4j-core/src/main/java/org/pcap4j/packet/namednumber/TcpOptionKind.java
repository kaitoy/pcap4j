/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * TCP Option Kind
 *
 * @see <a
 *     href="http://www.iana.org/assignments/tcp-parameters/tcp-parameters.xml#tcp-parameters-1">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.12
 */
public final class TcpOptionKind extends NamedNumber<Byte, TcpOptionKind> {

  /** */
  private static final long serialVersionUID = -7033971699970069137L;

  /** End of Option List: 0 */
  public static final TcpOptionKind END_OF_OPTION_LIST =
      new TcpOptionKind((byte) 0, "End of Option List");

  /** No-Operation: 1 */
  public static final TcpOptionKind NO_OPERATION = new TcpOptionKind((byte) 1, "No Operation");

  /** Maximum Segment Size: 2 */
  public static final TcpOptionKind MAXIMUM_SEGMENT_SIZE =
      new TcpOptionKind((byte) 2, "Maximum Segment Size");

  /** Window Scale: 3 */
  public static final TcpOptionKind WINDOW_SCALE = new TcpOptionKind((byte) 3, "Window Scale");

  /** SACK Permitted: 4 */
  public static final TcpOptionKind SACK_PERMITTED = new TcpOptionKind((byte) 4, "SACK Permitted");

  /** SACK: 5 */
  public static final TcpOptionKind SACK = new TcpOptionKind((byte) 5, "SACK");

  /** Echo: 6 */
  public static final TcpOptionKind ECHO = new TcpOptionKind((byte) 6, "Echo");

  /** Echo Reply: 7 */
  public static final TcpOptionKind ECHO_REPLY = new TcpOptionKind((byte) 7, "Echo Reply");

  /** Timestamps: 8 */
  public static final TcpOptionKind TIMESTAMPS = new TcpOptionKind((byte) 8, "Timestamps");

  /** Partial Order Connection Permitted: 9 */
  public static final TcpOptionKind PARTIAL_ORDER_CONNECTION_PERMITTED =
      new TcpOptionKind((byte) 9, "Partial Order Connection Permitted");

  /** Partial Order Service Profile: 10 */
  public static final TcpOptionKind PARTIAL_ORDER_SERVICE_PROFILE =
      new TcpOptionKind((byte) 10, "Partial Order Service Profile");

  /** CC: 11 */
  public static final TcpOptionKind CC = new TcpOptionKind((byte) 11, "CC");

  /** CC.NEW: 12 */
  public static final TcpOptionKind CC_NEW = new TcpOptionKind((byte) 12, "CC.NEW");

  /** CC.ECHO: 13 */
  public static final TcpOptionKind CC_ECHO = new TcpOptionKind((byte) 13, "CC.ECHO");

  /** TCP Alternate Checksum Request: 14 */
  public static final TcpOptionKind TCP_ALTERNATE_CHECKSUM_REQUEST =
      new TcpOptionKind((byte) 14, "TCP Alternate Checksum Request");

  /** TCP Alternate Checksum Data: 15 */
  public static final TcpOptionKind TCP_ALTERNATE_CHECKSUM_DATA =
      new TcpOptionKind((byte) 15, "TCP Alternate Checksum Data");

  /** Skeeter: 16 */
  public static final TcpOptionKind SKEETER = new TcpOptionKind((byte) 16, "Skeeter");

  /** Bubba: 17 */
  public static final TcpOptionKind BUBBA = new TcpOptionKind((byte) 17, "Bubba");

  /** Trailer Checksum: 18 */
  public static final TcpOptionKind TRAILER_CHECKSUM =
      new TcpOptionKind((byte) 18, "Trailer Checksum");

  /** MD5 Signature: 19 */
  public static final TcpOptionKind MD5_SIGNATURE = new TcpOptionKind((byte) 19, "MD5 Signature");

  /** SCPS Capabilities: 20 */
  public static final TcpOptionKind SCPS_CAPABILITIES =
      new TcpOptionKind((byte) 20, "SCPS Capabilities");

  /** Selective Negative Acknowledgements: 21 */
  public static final TcpOptionKind SELECTIVE_NEGATIVE_ACKNOWLEDGEMENTS =
      new TcpOptionKind((byte) 21, "Selective Negative Acknowledgements");

  /** Record Boundaries: 22 */
  public static final TcpOptionKind RECORD_BOUNDARIES =
      new TcpOptionKind((byte) 22, "Record Boundaries");

  /** Corruption experienced: 23 */
  public static final TcpOptionKind CORRUPTION_EXPERIENCED =
      new TcpOptionKind((byte) 23, "Corruption experienced");

  /** SNAP: 24 */
  public static final TcpOptionKind SNAP = new TcpOptionKind((byte) 24, "SNAP");

  /** TCP Compression Filter: 26 */
  public static final TcpOptionKind TCP_COMPRESSION_FILTER =
      new TcpOptionKind((byte) 26, "TCP Compression Filter");

  /** Quick-Start Response: 27 */
  public static final TcpOptionKind QUICK_START_RESPONSE =
      new TcpOptionKind((byte) 27, "Quick-Start Response");

  /** User Timeout: 28 */
  public static final TcpOptionKind USER_TIMEOUT = new TcpOptionKind((byte) 28, "User Timeout");

  /** TCP Authentication Option (TCP-AO): 29 */
  public static final TcpOptionKind TCP_AO = new TcpOptionKind((byte) 29, "TCP-AO");

  /** Multipath TCP (MPTCP): 30 */
  public static final TcpOptionKind MPTCP = new TcpOptionKind((byte) 30, "MPTCP");

  /** TCP Fast Open Cookie: 34 */
  public static final TcpOptionKind TCP_FAST_OPEN_COOKIE =
      new TcpOptionKind((byte) 34, "TCP Fast Open Cookie");

  private static final Map<Byte, TcpOptionKind> registry = new HashMap<Byte, TcpOptionKind>();

  static {
    registry.put(END_OF_OPTION_LIST.value(), END_OF_OPTION_LIST);
    registry.put(NO_OPERATION.value(), NO_OPERATION);
    registry.put(MAXIMUM_SEGMENT_SIZE.value(), MAXIMUM_SEGMENT_SIZE);
    registry.put(WINDOW_SCALE.value(), WINDOW_SCALE);
    registry.put(SACK_PERMITTED.value(), SACK_PERMITTED);
    registry.put(SACK.value(), SACK);
    registry.put(ECHO.value(), ECHO);
    registry.put(ECHO_REPLY.value(), ECHO_REPLY);
    registry.put(TIMESTAMPS.value(), TIMESTAMPS);
    registry.put(PARTIAL_ORDER_CONNECTION_PERMITTED.value(), PARTIAL_ORDER_CONNECTION_PERMITTED);
    registry.put(PARTIAL_ORDER_SERVICE_PROFILE.value(), PARTIAL_ORDER_SERVICE_PROFILE);
    registry.put(CC.value(), CC);
    registry.put(CC_NEW.value(), CC_NEW);
    registry.put(CC_ECHO.value(), CC_ECHO);
    registry.put(TCP_ALTERNATE_CHECKSUM_REQUEST.value(), TCP_ALTERNATE_CHECKSUM_REQUEST);
    registry.put(TCP_ALTERNATE_CHECKSUM_DATA.value(), TCP_ALTERNATE_CHECKSUM_DATA);
    registry.put(SKEETER.value(), SKEETER);
    registry.put(BUBBA.value(), BUBBA);
    registry.put(TRAILER_CHECKSUM.value(), TRAILER_CHECKSUM);
    registry.put(MD5_SIGNATURE.value(), MD5_SIGNATURE);
    registry.put(SCPS_CAPABILITIES.value(), SCPS_CAPABILITIES);
    registry.put(SELECTIVE_NEGATIVE_ACKNOWLEDGEMENTS.value(), SELECTIVE_NEGATIVE_ACKNOWLEDGEMENTS);
    registry.put(RECORD_BOUNDARIES.value(), RECORD_BOUNDARIES);
    registry.put(CORRUPTION_EXPERIENCED.value(), CORRUPTION_EXPERIENCED);
    registry.put(SNAP.value(), SNAP);
    registry.put(TCP_COMPRESSION_FILTER.value(), TCP_COMPRESSION_FILTER);
    registry.put(QUICK_START_RESPONSE.value(), QUICK_START_RESPONSE);
    registry.put(USER_TIMEOUT.value(), USER_TIMEOUT);
    registry.put(TCP_AO.value(), TCP_AO);
    registry.put(MPTCP.value(), MPTCP);
    registry.put(TCP_FAST_OPEN_COOKIE.value(), TCP_FAST_OPEN_COOKIE);
  }

  /**
   * @param value value
   * @param name name
   */
  public TcpOptionKind(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a TcpOptionKind object.
   */
  public static TcpOptionKind getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new TcpOptionKind(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a TcpOptionKind object.
   */
  public static TcpOptionKind register(TcpOptionKind type) {
    return registry.put(type.value(), type);
  }

  @Override
  public int compareTo(TcpOptionKind o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
