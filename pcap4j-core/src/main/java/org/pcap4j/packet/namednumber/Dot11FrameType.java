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
 * Type and subtype of an IEEE802.11 frame
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11FrameType extends NamedNumber<Byte, Dot11FrameType> {

  /** */
  private static final long serialVersionUID = 863329177944877431L;

  /** Association request: 0 (00 0000) */
  public static final Dot11FrameType ASSOCIATION_REQUEST =
      new Dot11FrameType((byte) 0, "Association request");

  /** Association response: 1 (00 0001) */
  public static final Dot11FrameType ASSOCIATION_RESPONSE =
      new Dot11FrameType((byte) 1, "Association response");

  /** Reassociation request: 2 (00 0010) */
  public static final Dot11FrameType REASSOCIATION_REQUEST =
      new Dot11FrameType((byte) 2, "Reassociation request");

  /** Reassociation response: 3 (00 0011) */
  public static final Dot11FrameType REASSOCIATION_RESPONSE =
      new Dot11FrameType((byte) 3, "Reassociation response");

  /** Probe request: 4 (00 0100) */
  public static final Dot11FrameType PROBE_REQUEST = new Dot11FrameType((byte) 4, "Probe request");

  /** Probe response: 5 (00 0101) */
  public static final Dot11FrameType PROBE_RESPONSE =
      new Dot11FrameType((byte) 5, "Probe response");

  /** Timing Advertisement: 6 (00 0110) */
  public static final Dot11FrameType TIMING_ADVERTISEMENT =
      new Dot11FrameType((byte) 6, "Timing Advertisement");

  /** Beacon: 8 (00 1000) */
  public static final Dot11FrameType BEACON = new Dot11FrameType((byte) 8, "Beacon");

  /** ATIM: 9 (00 1001) */
  public static final Dot11FrameType ATIM = new Dot11FrameType((byte) 9, "ATIM");

  /** Disassociation: 10 (00 1010) */
  public static final Dot11FrameType DISASSOCIATION =
      new Dot11FrameType((byte) 10, "Disassociation");

  /** Authentication: 11 (00 1011) */
  public static final Dot11FrameType AUTHENTICATION =
      new Dot11FrameType((byte) 11, "Authentication");

  /** Deauthentication: 12 (00 1100) */
  public static final Dot11FrameType DEAUTHENTICATION =
      new Dot11FrameType((byte) 12, "Deauthentication");

  /** Action: 13 (00 1101) */
  public static final Dot11FrameType ACTION = new Dot11FrameType((byte) 13, "Action");

  /** Action No Ack: 14 (00 1110) */
  public static final Dot11FrameType ACTION_NO_ACK = new Dot11FrameType((byte) 14, "Action No Ack");

  /** Control Wrapper: 23 (01 0111) */
  public static final Dot11FrameType CONTROL_WRAPPER =
      new Dot11FrameType((byte) 23, "Control Wrapper");

  /** Block Ack Request: 24 (01 1000) */
  public static final Dot11FrameType BLOCK_ACK_REQUEST =
      new Dot11FrameType((byte) 24, "Block Ack Request");

  /** Block Ack: 25 (01 1001) */
  public static final Dot11FrameType BLOCK_ACK = new Dot11FrameType((byte) 25, "Block Ack");

  /** PS-Poll: 26 (01 1010) */
  public static final Dot11FrameType PS_POLL = new Dot11FrameType((byte) 26, "PS-Poll");

  /** RTS: 27 (01 1011) */
  public static final Dot11FrameType RTS = new Dot11FrameType((byte) 27, "RTS");

  /** CTS: 28 (01 1100) */
  public static final Dot11FrameType CTS = new Dot11FrameType((byte) 28, "CTS");

  /** ACK: 29 (01 1101) */
  public static final Dot11FrameType ACK = new Dot11FrameType((byte) 29, "ACK");

  /** CF-End: 30 (01 1110) */
  public static final Dot11FrameType CF_END = new Dot11FrameType((byte) 30, "CF-End");

  /** CF-End + CF-Ack: 31 (01 1111) */
  public static final Dot11FrameType CF_END_CF_ACK =
      new Dot11FrameType((byte) 31, "CF-End + CF-Ack");

  /** Data: 32 (10 0000) */
  public static final Dot11FrameType DATA = new Dot11FrameType((byte) 32, "Data");

  /** Data + CF-Ack: 33 (10 0001) */
  public static final Dot11FrameType DATA_CF_ACK = new Dot11FrameType((byte) 33, "Data + CF-Ack");

  /** Data + CF-Poll: 34 (10 0010) */
  public static final Dot11FrameType DATA_CF_POLL = new Dot11FrameType((byte) 34, "Data + CF-Poll");

  /** Data + CF-Ack + CF-Poll: 35 (10 0011) */
  public static final Dot11FrameType DATA_CF_ACK_CF_POLL =
      new Dot11FrameType((byte) 35, "Data + CF-Ack + CF-Poll");

  /** Null (no data): 36 (10 0100) */
  public static final Dot11FrameType NULL = new Dot11FrameType((byte) 36, "Null");

  /** CF-Ack (no data): 37 (10 0101) */
  public static final Dot11FrameType CF_ACK = new Dot11FrameType((byte) 37, "CF-Ack");

  /** CF-Poll (no data): 38 (10 0110) */
  public static final Dot11FrameType CF_POLL = new Dot11FrameType((byte) 38, "CF-Poll");

  /** CF-Ack + CF-Poll (no data): 39 (10 0111) */
  public static final Dot11FrameType CF_ACK_CF_POLL =
      new Dot11FrameType((byte) 39, "CF-Ack + CF-Poll");

  /** QoS Data: 40 (10 1000) */
  public static final Dot11FrameType QOS_DATA = new Dot11FrameType((byte) 40, "QoS Data");

  /** QoS Data + CF-Ack: 41 (10 1001) */
  public static final Dot11FrameType QOS_DATA_CF_ACK =
      new Dot11FrameType((byte) 41, "QoS Data + CF-Ack");

  /** QoS Data + CF-Poll: 42 (10 1010) */
  public static final Dot11FrameType QOS_DATA_CF_POLL =
      new Dot11FrameType((byte) 42, "QoS Data + CF-Poll");

  /** QoS Data + CF-Ack + CF-Poll: 43 (10 1011) */
  public static final Dot11FrameType QOS_DATA_CF_ACK_CF_POLL =
      new Dot11FrameType((byte) 43, "QoS Data + CF-Ack + CF-Poll");

  /** QoS Null (no data): 44 (10 1100) */
  public static final Dot11FrameType QOS_NULL = new Dot11FrameType((byte) 44, "QoS Null");

  /** QoS CF-Poll (no data): 46 (10 1110) */
  public static final Dot11FrameType QOS_CF_POLL = new Dot11FrameType((byte) 46, "QoS CF-Poll");

  /** QoS CF-Ack + CF-Poll (no data): 47 (10 1111) */
  public static final Dot11FrameType QOS_CF_ACK_CF_POLL =
      new Dot11FrameType((byte) 47, "QoS CF-Ack + CF-Poll");

  private static final Map<Byte, Dot11FrameType> registry = new HashMap<Byte, Dot11FrameType>();

  static {
    registry.put(ASSOCIATION_REQUEST.value(), ASSOCIATION_REQUEST);
    registry.put(ASSOCIATION_RESPONSE.value(), ASSOCIATION_RESPONSE);
    registry.put(REASSOCIATION_REQUEST.value(), REASSOCIATION_REQUEST);
    registry.put(REASSOCIATION_RESPONSE.value(), REASSOCIATION_RESPONSE);
    registry.put(PROBE_REQUEST.value(), PROBE_REQUEST);
    registry.put(PROBE_RESPONSE.value(), PROBE_RESPONSE);
    registry.put(TIMING_ADVERTISEMENT.value(), TIMING_ADVERTISEMENT);
    registry.put(BEACON.value(), BEACON);
    registry.put(ATIM.value(), ATIM);
    registry.put(DISASSOCIATION.value(), DISASSOCIATION);
    registry.put(AUTHENTICATION.value(), AUTHENTICATION);
    registry.put(DEAUTHENTICATION.value(), DEAUTHENTICATION);
    registry.put(ACTION.value(), ACTION);
    registry.put(ACTION_NO_ACK.value(), ACTION_NO_ACK);
    registry.put(CONTROL_WRAPPER.value(), CONTROL_WRAPPER);
    registry.put(BLOCK_ACK_REQUEST.value(), BLOCK_ACK_REQUEST);
    registry.put(BLOCK_ACK.value(), BLOCK_ACK);
    registry.put(PS_POLL.value(), PS_POLL);
    registry.put(RTS.value(), RTS);
    registry.put(CTS.value(), CTS);
    registry.put(ACK.value(), ACK);
    registry.put(CF_END.value(), CF_END);
    registry.put(CF_END_CF_ACK.value(), CF_END_CF_ACK);
    registry.put(DATA.value(), DATA);
    registry.put(DATA_CF_ACK.value(), DATA_CF_ACK);
    registry.put(DATA_CF_POLL.value(), DATA_CF_POLL);
    registry.put(DATA_CF_ACK_CF_POLL.value(), DATA_CF_ACK_CF_POLL);
    registry.put(NULL.value(), NULL);
    registry.put(CF_ACK.value(), CF_ACK);
    registry.put(CF_POLL.value(), CF_POLL);
    registry.put(CF_ACK_CF_POLL.value(), CF_ACK_CF_POLL);
    registry.put(QOS_DATA.value(), QOS_DATA);
    registry.put(QOS_DATA_CF_ACK.value(), QOS_DATA_CF_ACK);
    registry.put(QOS_DATA_CF_POLL.value(), QOS_DATA_CF_POLL);
    registry.put(QOS_DATA_CF_ACK_CF_POLL.value(), QOS_DATA_CF_ACK_CF_POLL);
    registry.put(QOS_NULL.value(), QOS_NULL);
    registry.put(QOS_CF_POLL.value(), QOS_CF_POLL);
    registry.put(QOS_CF_ACK_CF_POLL.value(), QOS_CF_ACK_CF_POLL);
  }

  private final Type type;

  /**
   * @param value value
   * @param name name
   */
  public Dot11FrameType(Byte value, String name) {
    super(value, name);
    if ((value & 0xC0) != 0) {
      throw new IllegalArgumentException(value + " is invalid value. (value & 0xC0) must be 0.");
    }

    switch (value >> 4) {
      case 0:
        this.type = Type.MANAGEMENT;
        break;
      case 1:
        this.type = Type.CONTROL;
        break;
      case 2:
        this.type = Type.DATA;
        break;
      case 3:
        this.type = Type.RESERVED;
        break;
      default:
        throw new AssertionError("Never get here.");
    }
  }

  /** @return type */
  public Type getType() {
    return type;
  }

  /**
   * @param value value
   * @return a Dot11FrameType object.
   */
  public static Dot11FrameType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11FrameType(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a Dot11FrameType object.
   */
  public static Dot11FrameType register(Dot11FrameType number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(Dot11FrameType o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  /**
   * Type of IEEE802.11 frame
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static enum Type {

    /** Management (00) */
    MANAGEMENT(0),

    /** Control (01) */
    CONTROL(1),

    /** Data (10) */
    DATA(2),

    /** Reserved (11) */
    RESERVED(3);

    private final int value;

    private Type(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }
}
