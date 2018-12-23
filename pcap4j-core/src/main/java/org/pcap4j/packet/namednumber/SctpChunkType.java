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
 * SCTP Chunk Type
 *
 * @see <a href="https://tools.ietf.org/html/rfc4960#section-3.2">RFC 4960</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class SctpChunkType extends NamedNumber<Byte, SctpChunkType> {

  /** */
  private static final long serialVersionUID = -5598298520049931819L;

  /** Payload Data: 0 */
  public static final SctpChunkType DATA = new SctpChunkType((byte) 0, "Payload Data");

  /** Initiation: 1 */
  public static final SctpChunkType INIT = new SctpChunkType((byte) 1, "Initiation");

  /** Initiation Acknowledgement: 2 */
  public static final SctpChunkType INIT_ACK =
      new SctpChunkType((byte) 2, "Initiation Acknowledgement");

  /** Selective Acknowledgement: 3 */
  public static final SctpChunkType SACK = new SctpChunkType((byte) 3, "Selective Acknowledgement");

  /** Heartbeat Request: 4 */
  public static final SctpChunkType HEARTBEAT = new SctpChunkType((byte) 4, "Heartbeat Request");

  /** Heartbeat Acknowledgement: 5 */
  public static final SctpChunkType HEARTBEAT_ACK =
      new SctpChunkType((byte) 5, "Heartbeat Acknowledgement");

  /** Abort: 6 */
  public static final SctpChunkType ABORT = new SctpChunkType((byte) 6, "Abort");

  /** Shutdown: 7 */
  public static final SctpChunkType SHUTDOWN = new SctpChunkType((byte) 7, "Shutdown");

  /** Shutdown Acknowledgement: 8 */
  public static final SctpChunkType SHUTDOWN_ACK =
      new SctpChunkType((byte) 8, "Shutdown Acknowledgement");

  /** Operation Error: 9 */
  public static final SctpChunkType ERROR = new SctpChunkType((byte) 9, "Operation Error");

  /** State Cookie: 10 */
  public static final SctpChunkType COOKIE_ECHO = new SctpChunkType((byte) 10, "State Cookie");

  /** Cookie Acknowledgement: 11 */
  public static final SctpChunkType COOKIE_ACK =
      new SctpChunkType((byte) 11, "Cookie Acknowledgement");

  /** Explicit Congestion Notification Echo: 12 */
  public static final SctpChunkType ECNE =
      new SctpChunkType((byte) 12, "Explicit Congestion Notification Echo");

  /** Congestion Window Reduced: 13 */
  public static final SctpChunkType CWR = new SctpChunkType((byte) 13, "Congestion Window Reduced");

  /** Shutdown Complete: 14 */
  public static final SctpChunkType SHUTDOWN_COMPLETE =
      new SctpChunkType((byte) 14, "Shutdown Complete");

  private static final Map<Byte, SctpChunkType> registry = new HashMap<Byte, SctpChunkType>();

  static {
    registry.put(DATA.value(), DATA);
    registry.put(INIT.value(), INIT);
    registry.put(INIT_ACK.value(), INIT_ACK);
    registry.put(SACK.value(), SACK);
    registry.put(HEARTBEAT.value(), HEARTBEAT);
    registry.put(HEARTBEAT_ACK.value(), HEARTBEAT_ACK);
    registry.put(ABORT.value(), ABORT);
    registry.put(SHUTDOWN.value(), SHUTDOWN);
    registry.put(SHUTDOWN_ACK.value(), SHUTDOWN_ACK);
    registry.put(ERROR.value(), ERROR);
    registry.put(COOKIE_ECHO.value(), COOKIE_ECHO);
    registry.put(COOKIE_ACK.value(), COOKIE_ACK);
    registry.put(ECNE.value(), ECNE);
    registry.put(CWR.value(), CWR);
    registry.put(SHUTDOWN_COMPLETE.value(), SHUTDOWN_COMPLETE);
  }

  /** @return an ActionForUnkownType object. */
  public ActionForUnkownType getActionForUnkownType() {
    int val = (value() >> 6) & 0x03;
    return ActionForUnkownType.values()[val];
  }

  /**
   * @param value value
   * @param name name
   */
  public SctpChunkType(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a SctpChunkType object.
   */
  public static SctpChunkType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new SctpChunkType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a SctpChunkType object.
   */
  public static SctpChunkType register(SctpChunkType type) {
    return registry.put(type.value(), type);
  }

  /** @return the value of this object as an int. */
  public int valueAsInt() {
    return 0xFF & value();
  }

  /** @return a string representation of this value. */
  @Override
  public String valueAsString() {
    return String.valueOf(valueAsInt());
  }

  @Override
  public int compareTo(SctpChunkType o) {
    return value().compareTo(o.value());
  }

  /**
   * Action that must be taken if the processing endpoint does not recognize the Chunk Type.
   * (highest-order 2 bits of the Chunk Type)
   *
   * @see <a href="https://tools.ietf.org/html/rfc4960#section-3.2">RFC 4960</a>
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public static enum ActionForUnkownType {

    /**
     * Stop processing this SCTP packet and discard it, do not process any further chunks within it.
     */
    DISCARD,

    /**
     * Stop processing this SCTP packet and discard it, do not process any further chunks within it,
     * and report the unrecognized chunk in an 'Unrecognized Chunk Type'.
     */
    DISCARD_AND_REPORT,

    /** Skip this chunk and continue processing. */
    SKIP,

    /**
     * Skip this chunk and continue processing, but report in an ERROR chunk using the 'Unrecognized
     * Chunk Type' cause of error.
     */
    SKIP_AND_REPORT,
  }
}
