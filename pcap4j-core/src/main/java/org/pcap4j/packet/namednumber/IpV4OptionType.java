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
 * IPv4 Option Type
 *
 * @see <a href="http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4OptionType extends NamedNumber<Byte, IpV4OptionType> {

  /** */
  private static final long serialVersionUID = -7033971699970069137L;

  /** End of Option List: 0 */
  public static final IpV4OptionType END_OF_OPTION_LIST =
      new IpV4OptionType((byte) 0, "End of Option List");

  /** No Operation: 1 */
  public static final IpV4OptionType NO_OPERATION = new IpV4OptionType((byte) 1, "No Operation");

  /** Security: 130 */
  public static final IpV4OptionType SECURITY = new IpV4OptionType((byte) 130, "Security");

  /** Loose Source Route: 131 */
  public static final IpV4OptionType LOOSE_SOURCE_ROUTING =
      new IpV4OptionType((byte) 131, "Loose Source Routing");

  /** Time Stamp: 68 */
  public static final IpV4OptionType INTERNET_TIMESTAMP =
      new IpV4OptionType((byte) 68, "Internet Timestamp");

  /** Extended Security: 133 */
  public static final IpV4OptionType EXTENDED_SECURITY =
      new IpV4OptionType((byte) 133, "Extended Security");

  /** Commercial Security (CIPSO): 134 */
  public static final IpV4OptionType CIPSO = new IpV4OptionType((byte) 134, "CIPSO");

  /** Record Route: 7 */
  public static final IpV4OptionType RECORD_ROUTE = new IpV4OptionType((byte) 7, "Record Route");

  /** Stream ID: 136 */
  public static final IpV4OptionType STREAM_ID = new IpV4OptionType((byte) 136, "Stream ID");

  /** Strict Source Route: 137 */
  public static final IpV4OptionType STRICT_SOURCE_ROUTING =
      new IpV4OptionType((byte) 137, "Strict Source Routing");

  /** ZSU: 10 */
  public static final IpV4OptionType ZSU = new IpV4OptionType((byte) 10, "ZSU");

  /** MTU Probe (MTUP): 11 */
  public static final IpV4OptionType MTUP = new IpV4OptionType((byte) 11, "MTUP");

  /** MTU Reply (MTUR): 12 */
  public static final IpV4OptionType MTUR = new IpV4OptionType((byte) 12, "MTUR");

  /** FINN: 205 */
  public static final IpV4OptionType FINN = new IpV4OptionType((byte) 205, "FINN");

  /** VISA: 142 */
  public static final IpV4OptionType VISA = new IpV4OptionType((byte) 142, "VISA");

  /** ENCODE: 15 */
  public static final IpV4OptionType ENCODE = new IpV4OptionType((byte) 15, "ENCODE");

  /** IMI Traffic Descriptor (IMITD): 144 */
  public static final IpV4OptionType IMITD = new IpV4OptionType((byte) 144, "IMITD");

  /** Extended Internet Protocol (EIP): 145 */
  public static final IpV4OptionType EIP = new IpV4OptionType((byte) 145, "EIP");

  /** Traceroute: 82 */
  public static final IpV4OptionType TRACEROUTE = new IpV4OptionType((byte) 82, "Traceroute");

  /** Address Extension: 147 */
  public static final IpV4OptionType ADDRESS_EXTENSION =
      new IpV4OptionType((byte) 147, "Address Extension");

  /** Router Alert: 148 */
  public static final IpV4OptionType ROUTER_ALERT = new IpV4OptionType((byte) 148, "Router Alert");

  /** Selective Directed Broadcast: 149 */
  public static final IpV4OptionType SELECTIVE_DIRECTED_BROADCAST =
      new IpV4OptionType((byte) 149, "Selective Directed Broadcast");

  /** Dynamic Packet State: 151 */
  public static final IpV4OptionType DYNAMIC_PACKET_STATE =
      new IpV4OptionType((byte) 151, "Dynamic Packet State");

  /** Upstream Multicast Packet: 152 */
  public static final IpV4OptionType UPSTREAM_MULTICAST_PACKET =
      new IpV4OptionType((byte) 152, "Upstream Multicast Packet");

  /** Quick-Start: 25 */
  public static final IpV4OptionType QUICK_START = new IpV4OptionType((byte) 25, "Quick-Start");

  private static final Map<Byte, IpV4OptionType> registry = new HashMap<Byte, IpV4OptionType>();

  static {
    registry.put(END_OF_OPTION_LIST.value(), END_OF_OPTION_LIST);
    registry.put(NO_OPERATION.value(), NO_OPERATION);
    registry.put(SECURITY.value(), SECURITY);
    registry.put(LOOSE_SOURCE_ROUTING.value(), LOOSE_SOURCE_ROUTING);
    registry.put(INTERNET_TIMESTAMP.value(), INTERNET_TIMESTAMP);
    registry.put(EXTENDED_SECURITY.value(), EXTENDED_SECURITY);
    registry.put(CIPSO.value(), CIPSO);
    registry.put(RECORD_ROUTE.value(), RECORD_ROUTE);
    registry.put(STREAM_ID.value(), STREAM_ID);
    registry.put(STRICT_SOURCE_ROUTING.value(), STRICT_SOURCE_ROUTING);
    registry.put(ZSU.value(), ZSU);
    registry.put(MTUP.value(), MTUP);
    registry.put(MTUR.value(), MTUR);
    registry.put(FINN.value(), FINN);
    registry.put(VISA.value(), VISA);
    registry.put(ENCODE.value(), ENCODE);
    registry.put(IMITD.value(), IMITD);
    registry.put(EIP.value(), EIP);
    registry.put(TRACEROUTE.value(), TRACEROUTE);
    registry.put(ADDRESS_EXTENSION.value(), ADDRESS_EXTENSION);
    registry.put(ROUTER_ALERT.value(), ROUTER_ALERT);
    registry.put(SELECTIVE_DIRECTED_BROADCAST.value(), SELECTIVE_DIRECTED_BROADCAST);
    registry.put(DYNAMIC_PACKET_STATE.value(), DYNAMIC_PACKET_STATE);
    registry.put(UPSTREAM_MULTICAST_PACKET.value(), UPSTREAM_MULTICAST_PACKET);
    registry.put(QUICK_START.value(), QUICK_START);
  }

  private final boolean copied;
  private final IpV4OptionClass optionClass;
  private final byte number;

  /**
   * @param value value
   * @param name name
   */
  public IpV4OptionType(Byte value, String name) {
    super(value, name);

    this.copied = (value & 0x80) != 0;
    this.number = (byte) (value & 0x1F);

    switch (value & 0x60) {
      case 0x00:
        this.optionClass = IpV4OptionClass.CONTROL;
        break;
      case 0x20:
        this.optionClass = IpV4OptionClass.RESERVED_FOR_FUTURE_USE1;
        break;
      case 0x40:
        this.optionClass = IpV4OptionClass.DEBUGGING_AND_MEASUREMENT;
        break;
      case 0x60:
        this.optionClass = IpV4OptionClass.RESERVED_FOR_FUTURE_USE3;
        break;
      default:
        throw new AssertionError("Never get here");
    }
  }

  /**
   * @return true if the copied flag of the packet represented by this object is true; false
   *     otherwise.
   */
  public boolean isCopied() {
    return copied;
  }

  /** @return optionClass */
  public IpV4OptionClass getOptionClass() {
    return optionClass;
  }

  /** @return number */
  public byte getNumber() {
    return number;
  }

  /**
   * @param value value
   * @return a IpV4OptionType object.
   */
  public static IpV4OptionType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4OptionType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a IpV4OptionType object.
   */
  public static IpV4OptionType register(IpV4OptionType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public int compareTo(IpV4OptionType o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static enum IpV4OptionClass {

    /** */
    CONTROL((byte) 0),

    /** */
    RESERVED_FOR_FUTURE_USE1((byte) 1),

    /** */
    DEBUGGING_AND_MEASUREMENT((byte) 2),

    /** */
    RESERVED_FOR_FUTURE_USE3((byte) 3);

    private final byte value;

    private IpV4OptionClass(byte value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }
}
