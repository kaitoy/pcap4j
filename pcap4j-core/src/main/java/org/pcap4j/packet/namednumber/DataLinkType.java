/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.Pcap4jPropertiesLoader;
import com.sun.jna.Platform;

/**
 * Pcap Data Link Type
 *
 * @see <a href="https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/bpf.h">pcap/bpf.h</a>
 * @see <a href="http://www.tcpdump.org/linktypes.html">tcpdump.org</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class DataLinkType extends NamedNumber<Integer, DataLinkType> {

  /**
   *
   */
  private static final long serialVersionUID = -4299486028394578120L;

  /**
   * Null (BSD loopback encapsulation): 0
   */
  public static final DataLinkType NULL
    = new DataLinkType(0, "Null");

  /**
   * Ethernet (10Mb, 100Mb, 1000Mb, and up): 1
   */
  public static final DataLinkType EN10MB
    = new DataLinkType(1, "Ethernet");

  /**
   * 802.5 Token Ring: 6
   */
  public static final DataLinkType IEEE802
    = new DataLinkType(6, "Token Ring");

  /**
   * Point-to-point Protocol: 9
   */
  public static final DataLinkType PPP
    = new DataLinkType(9, "PPP");

  /**
   * FDDI: 10
   */
  public static final DataLinkType FDDI
    = new DataLinkType(10, "FDDI");

  /**
   * RAW IP packet: 14 on OpenBSD, or 12 on the others.
   * If you want to change this value,
   * set the property org.pcap4j.dlt.raw (system property or pcap4j.properties)
   * to an integer before using this class.
   * @see Pcap4jPropertiesLoader
   * @see <a href="https://github.com/kaitoy/pcap4j/blob/master/pcap4j-core/src/main/java/org/pcap4j/pcap4j.properties">pcap4j.properties</a>
   */
  public static final DataLinkType RAW;

  /**
   * PPP over serial with HDLC encapsulation: 50
   */
  public static final DataLinkType PPP_SERIAL
    = new DataLinkType(50, "PPP over serial with HDLC encapsulation");

  /**
   * IEEE 802.11 wireless: 105
   */
  public static final DataLinkType IEEE802_11
    = new DataLinkType(105, "Wireless");

  /**
   * Linux cooked-mode capture (SLL): 113
   */
  public static final DataLinkType LINUX_SLL
    = new DataLinkType(113, "Linux cooked-mode capture");

  /**
   * DOCSIS MAC frames: 143
   */
  public static final DataLinkType DOCSIS
    = new DataLinkType(143, "DOCSIS");

  private static final Map<Integer, DataLinkType> registry
    = new HashMap<Integer, DataLinkType>();

  static {
    registry.put(0, NULL);
    registry.put(1, EN10MB);
    registry.put(6, IEEE802);
    registry.put(9, PPP);
    registry.put(10, FDDI);
    registry.put(50, PPP_SERIAL);
    registry.put(105, IEEE802_11);
    registry.put(113, LINUX_SLL);
    registry.put(143, DOCSIS);

    Integer raw = Pcap4jPropertiesLoader.getInstance().getDltRaw();
    if (raw != null) {
      RAW = new DataLinkType(raw, "RAW");
    }
    else {
      if (Platform.isOpenBSD()) {
        RAW = new DataLinkType(14, "RAW");
      }
      else {
        RAW = new DataLinkType(12, "RAW");
      }
    }
  }

  /**
   *
   * @param value
   * @param name
   */
  public DataLinkType(Integer value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a DataLinkType object.
   */
  public static DataLinkType getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new DataLinkType(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return a DataLinkType object.
   */
  public static DataLinkType register(DataLinkType type) {
    return registry.put(type.value(), type);
  }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(DataLinkType o) {
    return value().compareTo(o.value());
  }

}
