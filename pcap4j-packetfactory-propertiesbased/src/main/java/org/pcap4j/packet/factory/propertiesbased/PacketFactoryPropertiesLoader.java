/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.propertiesbased;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.IcmpV6CommonPacket.IpV6NeighborDiscoveryOption;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.IpV6SimpleTrafficClass;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.UnknownDnsRData;
import org.pcap4j.packet.UnknownIpV4InternetTimestampOptionData;
import org.pcap4j.packet.UnknownIpV4Option;
import org.pcap4j.packet.UnknownIpV6NeighborDiscoveryOption;
import org.pcap4j.packet.UnknownIpV6Option;
import org.pcap4j.packet.UnknownIpV6RoutingData;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.UnknownRadiotapData;
import org.pcap4j.packet.UnknownSctpChunk;
import org.pcap4j.packet.UnknownTcpOption;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.packet.namednumber.IpV6NeighborDiscoveryOptionType;
import org.pcap4j.packet.namednumber.IpV6OptionType;
import org.pcap4j.packet.namednumber.IpV6RoutingType;
import org.pcap4j.packet.namednumber.NamedNumber;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;
import org.pcap4j.packet.namednumber.SctpChunkType;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.util.PropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class PacketFactoryPropertiesLoader {

  /** */
  public static final String PACKET_FACTORY_PROPERTIES_PATH_KEY =
      PacketFactoryPropertiesLoader.class.getPackage().getName() + ".properties";

  /** */
  public static final String PACKET_CLASS_KEY_BASE = Packet.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_PACKET_CLASS_KEY = PACKET_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String IPV4_OPTION_CLASS_KEY_BASE = IpV4Option.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_IPV4_OPTION_KEY = IPV4_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String TCP_OPTION_CLASS_KEY_BASE = TcpOption.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_TCP_OPTION_KEY = TCP_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String IPV4_INTERNET_TIMESTAMP_DATA_CLASS_KEY_BASE =
      IpV4InternetTimestampOptionData.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_IPV4_INTERNET_TIMESTAMP_DATA_KEY =
      IPV4_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String IPV6_OPTION_CLASS_KEY_BASE = IpV6Option.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_IPV6_OPTION_KEY = IPV6_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String IPV6_ROUTING_DATA_CLASS_KEY_BASE =
      IpV6RoutingData.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_IPV6_ROUTING_DATA_KEY =
      IPV6_ROUTING_DATA_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String IPV6_NEIGHBOR_DISCOVERY_OPTION_CLASS_KEY_BASE =
      IpV6NeighborDiscoveryOption.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_IPV6_NEIGHBOR_DISCOVERY_OPTION_KEY =
      IPV6_NEIGHBOR_DISCOVERY_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String RADIOTAP_DATA_FIELD_CLASS_KEY_BASE =
      RadiotapData.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_RADIOTAP_DATA_FIELD_KEY =
      RADIOTAP_DATA_FIELD_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String SCTP_CHUNK_CLASS_KEY_BASE = SctpChunk.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_SCTP_CHUNK_KEY = SCTP_CHUNK_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String DNS_RDATA_CLASS_KEY_BASE = DnsRData.class.getName() + ".classFor.";

  /** */
  public static final String UNKNOWN_DNS_RDATA_KEY = DNS_RDATA_CLASS_KEY_BASE + "unknownNumber";

  /** */
  public static final String IPV4_TOS_CLASS_KEY = IpV4Tos.class.getName() + ".class";

  /** */
  public static final String IPV6_TRAFFIC_CLASS_CLASS_KEY =
      IpV6TrafficClass.class.getName() + ".class";

  /** */
  public static final String IPV6_FLOW_LABEL_CLASS_KEY = IpV6FlowLabel.class.getName() + ".class";

  private static final PacketFactoryPropertiesLoader INSTANCE = new PacketFactoryPropertiesLoader();

  private PropertiesLoader loader =
      new PropertiesLoader(
          System.getProperty(
              PACKET_FACTORY_PROPERTIES_PATH_KEY,
              PacketFactoryPropertiesLoader.class.getPackage().getName().replace('.', '/')
                  + "/packet-factory.properties"),
          true,
          true);

  private PacketFactoryPropertiesLoader() {}

  /** @return the singleton instance of PacketFactoryPropertiesLoader. */
  public static PacketFactoryPropertiesLoader getInstance() {
    return INSTANCE;
  }

  /**
   * @param <T> number
   * @param number number
   * @return a class which implements Packet for a specified NamedNumber.
   */
  public <T extends NamedNumber<?, ?>> Class<? extends Packet> getPacketClass(T number) {
    String val = number.valueAsString();
    if (number instanceof EtherType) {
      EtherType et = (EtherType) number;
      if ((et.value() & 0xFFFF) <= EtherType.IEEE802_3_MAX_LENGTH) {
        val = "LLC";
      }
    }

    StringBuilder sb = new StringBuilder(110);
    sb.append(PACKET_CLASS_KEY_BASE).append(number.getClass().getName()).append(".").append(val);
    return loader.<Packet>getClass(sb.toString(), getUnknownPacketClass());
  }

  /** @return a class which implements Packet for an unknown packet. */
  public Class<? extends Packet> getUnknownPacketClass() {
    return loader.<Packet>getClass(UNKNOWN_PACKET_CLASS_KEY, UnknownPacket.class);
  }

  /**
   * @param targetClass targetClass
   * @param numberClass numberClass
   * @return a class which implements {@link org.pcap4j.packet.factory.PacketFactory PacketFactory}
   *     for specified classes.
   */
  public Class<? extends PacketFactory<?, ?>> getPacketFactoryClass(
      Class<?> targetClass, Class<? extends NamedNumber<?, ?>> numberClass) {
    StringBuilder sb = new StringBuilder(200);
    sb.append(targetClass.getName());
    if (!numberClass.equals(NotApplicable.class)) {
      sb.append(".classifiedBy.").append(numberClass.getName());
    }
    sb.append(".isMadeBy");
    String key = sb.toString();

    Class<? extends PacketFactory<?, ?>> factory = loader.getClass(key, null);

    if (factory == null) {
      String value = loader.getProp().getProperty(key);
      if (value == null) {
        throw new IllegalStateException("Can't get a value by the key: " + key);
      } else {
        sb = new StringBuilder(110);
        sb.append("Invalid value(").append(value).append(") for the key: ").append(key);
        throw new IllegalStateException(sb.toString());
      }
    }

    return factory;
  }

  /**
   * @param type type
   * @return a class which implements IpV4Option for a specified type.
   */
  public Class<? extends IpV4Option> getIpV4OptionClass(IpV4OptionType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(IPV4_OPTION_CLASS_KEY_BASE)
        .append(type.getClass().getName())
        .append(".")
        .append(type.valueAsString());
    return loader.<IpV4Option>getClass(sb.toString(), getUnknownIpV4OptionClass());
  }

  /** @return a class which implements IpV4Option for an unknown type. */
  public Class<? extends IpV4Option> getUnknownIpV4OptionClass() {
    return loader.<IpV4Option>getClass(UNKNOWN_IPV4_OPTION_KEY, UnknownIpV4Option.class);
  }

  /**
   * @param type type
   * @return a class which implements TcpOption for a specified type.
   */
  public Class<? extends TcpOption> getTcpOptionClass(TcpOptionKind type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(TCP_OPTION_CLASS_KEY_BASE)
        .append(type.getClass().getName())
        .append(".")
        .append(type.valueAsString());
    return loader.<TcpOption>getClass(sb.toString(), getUnknownTcpOptionClass());
  }

  /** @return a class which implements TcpOption for an unknown type. */
  public Class<? extends TcpOption> getUnknownTcpOptionClass() {
    return loader.<TcpOption>getClass(UNKNOWN_TCP_OPTION_KEY, UnknownTcpOption.class);
  }

  /**
   * @param flag flag
   * @return a class which implements IpV4InternetTimestampOptionData for a specified flag.
   */
  public Class<? extends IpV4InternetTimestampOptionData> getIpV4InternetTimestampDataClass(
      IpV4InternetTimestampOptionFlag flag) {
    StringBuilder sb = new StringBuilder(150);
    sb.append(IPV4_INTERNET_TIMESTAMP_DATA_CLASS_KEY_BASE)
        .append(flag.getClass().getName())
        .append(".")
        .append(flag.valueAsString());
    return loader.<IpV4InternetTimestampOptionData>getClass(
        sb.toString(), getUnknownIpV4InternetTimestampDataClass());
  }

  /** @return a class which implements IpV4InternetTimestampOptionData for an unknown flag. */
  public Class<? extends IpV4InternetTimestampOptionData>
      getUnknownIpV4InternetTimestampDataClass() {
    return loader.<IpV4InternetTimestampOptionData>getClass(
        UNKNOWN_IPV4_INTERNET_TIMESTAMP_DATA_KEY, UnknownIpV4InternetTimestampOptionData.class);
  }

  /**
   * @param type type
   * @return a class which implements IpV6Option for a specified type.
   */
  public Class<? extends IpV6Option> getIpV6OptionClass(IpV6OptionType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(IPV6_OPTION_CLASS_KEY_BASE)
        .append(type.getClass().getName())
        .append(".")
        .append(type.valueAsString());
    return loader.<IpV6Option>getClass(sb.toString(), getUnknownIpV6OptionClass());
  }

  /** @return a class which implements IpV6Option for an unknown type. */
  public Class<? extends IpV6Option> getUnknownIpV6OptionClass() {
    return loader.<IpV6Option>getClass(UNKNOWN_IPV6_OPTION_KEY, UnknownIpV6Option.class);
  }

  /**
   * @param type type
   * @return a class which implements IpV6RoutingData for a specified type.
   */
  public Class<? extends IpV6RoutingData> getIpV6RoutingDataClass(IpV6RoutingType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(IPV6_ROUTING_DATA_CLASS_KEY_BASE)
        .append(type.getClass().getName())
        .append(".")
        .append(type.valueAsString());
    return loader.<IpV6RoutingData>getClass(sb.toString(), getUnknownIpV6RoutingDataClass());
  }

  /** @return a class which implements IpV6RoutingData for an unknown type. */
  public Class<? extends IpV6RoutingData> getUnknownIpV6RoutingDataClass() {
    return loader.<IpV6RoutingData>getClass(
        UNKNOWN_IPV6_ROUTING_DATA_KEY, UnknownIpV6RoutingData.class);
  }

  /**
   * @param type type
   * @return a class which implements IpV6NeighborDiscoveryOption for a specified type.
   */
  public Class<? extends IpV6NeighborDiscoveryOption> getIpV6NeighborDiscoveryOptionClass(
      IpV6NeighborDiscoveryOptionType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(IPV6_NEIGHBOR_DISCOVERY_OPTION_CLASS_KEY_BASE)
        .append(type.getClass().getName())
        .append(".")
        .append(type.valueAsString());
    return loader.<IpV6NeighborDiscoveryOption>getClass(
        sb.toString(), getUnknownIpV6NeighborDiscoveryOptionClass());
  }

  /** @return a class which implements IpV6NeighborDiscoveryOption for an unknown type. */
  public Class<? extends IpV6NeighborDiscoveryOption> getUnknownIpV6NeighborDiscoveryOptionClass() {
    return loader.<IpV6NeighborDiscoveryOption>getClass(
        UNKNOWN_IPV6_NEIGHBOR_DISCOVERY_OPTION_KEY, UnknownIpV6NeighborDiscoveryOption.class);
  }

  /**
   * @param num num
   * @return a class which implements RadiotapDataField for a specified type.
   */
  public Class<? extends RadiotapData> getRadiotapDataFieldClass(RadiotapPresentBitNumber num) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(RADIOTAP_DATA_FIELD_CLASS_KEY_BASE)
        .append(num.getClass().getName())
        .append(".")
        .append(num.valueAsString());
    return loader.<RadiotapData>getClass(sb.toString(), getUnknownRadiotapDataFieldClass());
  }

  /** @return a class which implements RadiotapDataField for an unknown type. */
  public Class<? extends RadiotapData> getUnknownRadiotapDataFieldClass() {
    return loader.<RadiotapData>getClass(
        UNKNOWN_RADIOTAP_DATA_FIELD_KEY, UnknownRadiotapData.class);
  }

  /**
   * @param type type
   * @return a class which implements SctpChunk for a specified type.
   */
  public Class<? extends SctpChunk> getSctpChunkClass(SctpChunkType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(SCTP_CHUNK_CLASS_KEY_BASE)
        .append(type.getClass().getName())
        .append(".")
        .append(type.valueAsString());
    return loader.<SctpChunk>getClass(sb.toString(), getUnknownSctpChunkClass());
  }

  /** @return a class which implements SctpChunk for an unknown type. */
  public Class<? extends SctpChunk> getUnknownSctpChunkClass() {
    return loader.<SctpChunk>getClass(UNKNOWN_SCTP_CHUNK_KEY, UnknownSctpChunk.class);
  }

  /**
   * @param type type
   * @return a class which implements DnsRData for a specified type.
   */
  public Class<? extends DnsRData> getDnsRDataClass(DnsResourceRecordType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(DNS_RDATA_CLASS_KEY_BASE)
        .append(type.getClass().getName())
        .append(".")
        .append(type.valueAsString());
    return loader.<DnsRData>getClass(sb.toString(), getUnknownDnsRDataClass());
  }

  /** @return a class which implements DnsRData for an unknown type. */
  public Class<? extends DnsRData> getUnknownDnsRDataClass() {
    return loader.<DnsRData>getClass(UNKNOWN_DNS_RDATA_KEY, UnknownDnsRData.class);
  }

  /** @return a class which implements IpV4Tos. */
  public Class<? extends IpV4Tos> getIpV4TosClass() {
    return loader.<IpV4Tos>getClass(IPV4_TOS_CLASS_KEY, IpV4Rfc1349Tos.class);
  }

  /** @return a class which implements IpV6TrafficClass. */
  public Class<? extends IpV6TrafficClass> getIpV6TrafficClassClass() {
    return loader.<IpV6TrafficClass>getClass(
        IPV6_TRAFFIC_CLASS_CLASS_KEY, IpV6SimpleTrafficClass.class);
  }

  /** @return a class which implements IpV6FlowLabel. */
  public Class<? extends IpV6FlowLabel> getIpV6FlowLabelClass() {
    return loader.<IpV6FlowLabel>getClass(IPV6_FLOW_LABEL_CLASS_KEY, IpV6SimpleFlowLabel.class);
  }
}
