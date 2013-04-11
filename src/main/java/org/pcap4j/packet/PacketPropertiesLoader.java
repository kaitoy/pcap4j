/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.IpV4Packet.IpV4Tos;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6ExtRoutingPacket.IpV6RoutingData;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.factory.ClassifiedDataFactory;
import org.pcap4j.packet.factory.IpV4TosFactory;
import org.pcap4j.packet.factory.IpV6FlowLabelFactory;
import org.pcap4j.packet.factory.IpV6TrafficClassFactory;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.factory.PropertiesBasedIpV4TosFactory;
import org.pcap4j.packet.factory.PropertiesBasedIpV6FlowLabelFactory;
import org.pcap4j.packet.factory.PropertiesBasedIpV6TrafficClassFactory;
import org.pcap4j.packet.factory.StaticUnknownPacketFactory;
import org.pcap4j.packet.namednumber.IpV4InternetTimestampOptionFlag;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.packet.namednumber.IpV6OptionType;
import org.pcap4j.packet.namednumber.IpV6RoutingHeaderType;
import org.pcap4j.packet.namednumber.NamedNumber;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.util.PropertiesLoader;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PacketPropertiesLoader {

  /**
   *
   */
  public static final String PACKET_PROPERTIES_PATH_KEY
    = PacketPropertiesLoader.class.getPackage().getName()
        + ".properties";

  /**
   *
   */
  public static final String ICMPV4_CALC_CHECKSUM_KEY
    = PacketPropertiesLoader.class.getPackage().getName()
        + ".icmpv4.calcChecksumAtBuild";

  /**
   *
   */
  public static final String IPV4_CALC_CHECKSUM_KEY
    = PacketPropertiesLoader.class.getPackage().getName()
        + ".ipv4.calcChecksumAtBuild";

  /**
   *
   */
  public static final String TCPV4_CALC_CHECKSUM_KEY
    = PacketPropertiesLoader.class.getPackage().getName()
        + ".tcpv4.calcChecksumAtBuild";

  /**
   *
   */
  public static final String TCPV6_CALC_CHECKSUM_KEY
    = PacketPropertiesLoader.class.getPackage().getName()
        + ".tcpv6.calcChecksumAtBuild";

  /**
   *
   */
  public static final String UDPV4_CALC_CHECKSUM_KEY
    = PacketPropertiesLoader.class.getPackage().getName()
        + ".udpv4.calcChecksumAtBuild";

  /**
   *
   */
  public static final String UDPV6_CALC_CHECKSUM_KEY
    = PacketPropertiesLoader.class.getPackage().getName()
        + ".udpv6.calcChecksumAtBuild";

  /**
   *
   */
  public static final String PACKET_FACTORY_CLASS_KEY_BASE
    = Packet.class.getName() + ".classifiedBy.";

  /**
   *
   */
  public static final String PACKET_CLASS_KEY_BASE
    = Packet.class.getName() + ".classFor.";

  /**
   *
   */
  public static final String UNKNOWN_PACKET_CLASS_KEY
    = PACKET_CLASS_KEY_BASE + "unknownNumber";

  /**
   *
   */
  public static final String IPV4_OPTION_CLASS_KEY_BASE
    = IpV4Option.class.getName() + ".classFor.";

  /**
   *
   */
  public static final String UNKNOWN_IPV4_OPTION_KEY
    = IPV4_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /**
   *
   */
  public static final String TCP_OPTION_CLASS_KEY_BASE
    = TcpOption.class.getName() + ".classFor.";

  /**
   *
   */
  public static final String UNKNOWN_TCP_OPTION_KEY
    = TCP_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /**
   *
   */
  public static final String IPV4_INTERNET_TIMESTAMP_DATA_CLASS_KEY_BASE
    = IpV4InternetTimestampOptionData.class.getName() + ".classFor.";

  /**
   *
   */
  public static final String UNKNOWN_IPV4_INTERNET_TIMESTAMP_DATA_KEY
    = IPV4_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /**
   *
   */
  public static final String IPV6_OPTION_CLASS_KEY_BASE
    = IpV6Option.class.getName() + ".classFor.";

  /**
   *
   */
  public static final String UNKNOWN_IPV6_OPTION_KEY
    = IPV6_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /**
   *
   */
  public static final String IPV6_ROUTING_DATA_CLASS_KEY_BASE
    = IpV6RoutingData.class.getName() + ".classFor.";

  /**
   *
   */
  public static final String UNKNOWN_IPV6_ROUTING_DATA_KEY
    = IPV6_OPTION_CLASS_KEY_BASE + "unknownNumber";

  /**
   *
   */
  public static final String IPV4_TOS_FACTORY_CLASS_KEY
    = IpV4Tos.class.getName() + ".isMadeBy";

  /**
   *
   */
  public static final String IPV4_TOS_CLASS_KEY
    = IpV4Tos.class.getName() + ".class";

  /**
   *
   */
  public static final String IPV6_TRAFFIC_CLASS_FACTORY_CLASS_KEY
    = IpV6TrafficClass.class.getName() + ".isMadeBy";

  /**
   *
   */
  public static final String IPV6_TRAFFIC_CLASS_CLASS_KEY
    = IpV6TrafficClass.class.getName() + ".class";

  /**
   *
   */
  public static final String IPV6_FLOW_LABEL_FACTORY_CLASS_KEY
    = IpV6FlowLabel.class.getName() + ".isMadeBy";

  /**
   *
   */
  public static final String IPV6_FLOW_LABEL_CLASS_KEY
    = IpV6FlowLabel.class.getName() + ".class";


  private static final PacketPropertiesLoader INSTANCE
    = new PacketPropertiesLoader();

  private PropertiesLoader loader
    = new PropertiesLoader(
        System.getProperty(
          PACKET_PROPERTIES_PATH_KEY,
          PacketPropertiesLoader.class.getPackage().getName()
            .replace('.', '/') + "/packet.properties"
        ),
        true,
        true
      );

  private PacketPropertiesLoader() {}

  /**
   *
   * @return
   */
  public static PacketPropertiesLoader getInstance() {
    return INSTANCE;
  }

  /**
   *
   * @return
   */
  public boolean icmpV4CalcChecksum() {
    return loader.getBoolean(
             ICMPV4_CALC_CHECKSUM_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean ipV4CalcChecksum() {
    return loader.getBoolean(
             IPV4_CALC_CHECKSUM_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean tcpV4CalcChecksum() {
    return loader.getBoolean(
             TCPV4_CALC_CHECKSUM_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean tcpV6CalcChecksum() {
    return loader.getBoolean(
             TCPV6_CALC_CHECKSUM_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean udpV4CalcChecksum() {
    return loader.getBoolean(
             UDPV4_CALC_CHECKSUM_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @return
   */
  public boolean udpV6CalcChecksum() {
    return loader.getBoolean(
             UDPV6_CALC_CHECKSUM_KEY,
             Boolean.FALSE
           ).booleanValue();
  }

  /**
   *
   * @param numberClass
   * @return
   */
  public Class<? extends PacketFactory<NamedNumber<?>>>
  getPacketFactoryClass(Class<? extends NamedNumber<?>> numberClass) {
    StringBuilder sb = new StringBuilder(130);
    sb.append(PACKET_FACTORY_CLASS_KEY_BASE)
      .append(numberClass.getName())
      .append(".isMadeBy");
    return loader.<PacketFactory<NamedNumber<?>>>getClass(
             sb.toString(),
             StaticUnknownPacketFactory.class
           );
  }

  /**
   *
   * @param number
   * @return
   */
  public <T extends NamedNumber<?>>
  Class<? extends Packet> getPacketClass(T number) {
    StringBuilder sb = new StringBuilder(110);
    sb.append(PACKET_CLASS_KEY_BASE)
      .append(number.getClass().getName())
      .append(".")
      .append(number.valueAsString());
    return loader.<Packet>getClass(
             sb.toString(),
             getUnknownPacketClass()
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends Packet> getUnknownPacketClass() {
    return loader.<Packet>getClass(
             UNKNOWN_PACKET_CLASS_KEY,
             UnknownPacket.class
           );
  }

  /**
   *
   * @param targetClass
   * @param numberClass
   * @return
   */
  public Class<? extends ClassifiedDataFactory<?, ?>>
  getClassifiedDataFactoryClass(
    Class<?> targetClass, Class<? extends NamedNumber<?>> numberClass
  ) {
    StringBuilder sb = new StringBuilder(200);
    sb.append(targetClass.getName())
      .append(".classifiedBy.")
      .append(numberClass.getName())
      .append(".isMadeBy");
    String key = sb.toString();

    Class<? extends ClassifiedDataFactory<?, ?>> factory
      = loader.getClass(
          key,
          null
        );

    if (factory == null) {
      String value = loader.getProp().getProperty(key);
      if (value == null) {
        throw new IllegalStateException("Can't get a value by the key: " + key);
      }
      else {
        sb = new StringBuilder(110);
        sb.append("Invalid value(").append(value)
          .append(") for the key: ").append(key);
        throw new IllegalStateException(sb.toString());
      }
    }

    return factory;
  }

  /**
   *
   * @param type
   * @return
   */
  public Class<? extends IpV4Option> getIpV4OptionClass(IpV4OptionType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(IPV4_OPTION_CLASS_KEY_BASE)
      .append(type.getClass().getName())
      .append(".")
      .append(type.valueAsString());
    return loader.<IpV4Option>getClass(
             sb.toString(),
             getUnknownIpV4OptionClass()
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV4Option> getUnknownIpV4OptionClass() {
    return loader.<IpV4Option>getClass(
             UNKNOWN_IPV4_OPTION_KEY,
             UnknownIpV4Option.class
           );
  }

  /**
   *
   * @param type
   * @return
   */
  public Class<? extends TcpOption> getTcpOptionClass(TcpOptionKind type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(TCP_OPTION_CLASS_KEY_BASE)
      .append(type.getClass().getName())
      .append(".")
      .append(type.valueAsString());
    return loader.<TcpOption>getClass(
             sb.toString(),
             getUnknownTcpOptionClass()
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends TcpOption> getUnknownTcpOptionClass() {
    return loader.<TcpOption>getClass(
             UNKNOWN_TCP_OPTION_KEY,
             UnknownTcpOption.class
           );
  }

  /**
   *
   * @param flag
   * @return
   */
  public Class<? extends IpV4InternetTimestampOptionData>
  getIpV4InternetTimestampDataClass(IpV4InternetTimestampOptionFlag flag) {
    StringBuilder sb = new StringBuilder(150);
    sb.append(IPV4_INTERNET_TIMESTAMP_DATA_CLASS_KEY_BASE)
      .append(flag.getClass().getName())
      .append(".")
      .append(flag.valueAsString());
    return loader.<IpV4InternetTimestampOptionData>getClass(
             sb.toString(),
             getUnknownIpV4InternetTimestampDataClass()
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV4InternetTimestampOptionData>
  getUnknownIpV4InternetTimestampDataClass() {
    return loader.<IpV4InternetTimestampOptionData>getClass(
             UNKNOWN_IPV4_INTERNET_TIMESTAMP_DATA_KEY,
             UnknownIpV4InternetTimestampData.class
           );
  }

  /**
   *
   * @param type
   * @return
   */
  public Class<? extends IpV6Option> getIpV6OptionClass(IpV6OptionType type) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(IPV6_OPTION_CLASS_KEY_BASE)
      .append(type.getClass().getName())
      .append(".")
      .append(type.valueAsString());
    return loader.<IpV6Option>getClass(
             sb.toString(),
             getUnknownIpV6OptionClass()
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV6Option> getUnknownIpV6OptionClass() {
    return loader.<IpV6Option>getClass(
             UNKNOWN_IPV6_OPTION_KEY,
             UnknownIpV6Option.class
           );
  }

  /**
   *
   * @param type
   * @return
   */
  public Class<? extends IpV6RoutingData> getIpV6RoutingDataClass(
    IpV6RoutingHeaderType type
  ) {
    StringBuilder sb = new StringBuilder(120);
    sb.append(IPV6_ROUTING_DATA_CLASS_KEY_BASE)
      .append(type.getClass().getName())
      .append(".")
      .append(type.valueAsString());
    return loader.<IpV6RoutingData>getClass(
             sb.toString(),
             getUnknownIpV6RoutingDataClass()
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV6RoutingData> getUnknownIpV6RoutingDataClass() {
    return loader.<IpV6RoutingData>getClass(
             UNKNOWN_IPV6_ROUTING_DATA_KEY,
             UnknownIpV6RoutingData.class
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV4TosFactory> getIpV4TosFactoryClass() {
    return loader.<IpV4TosFactory>getClass(
             IPV4_TOS_FACTORY_CLASS_KEY,
             PropertiesBasedIpV4TosFactory.class
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV4Tos> getIpV4TosClass() {
    return loader.<IpV4Tos>getClass(
             IPV4_TOS_CLASS_KEY,
             IpV4Rfc1349Tos.class
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV6TrafficClassFactory>
  getIpV6TrafficClassFactoryClass() {
    return loader.<IpV6TrafficClassFactory>getClass(
             IPV6_TRAFFIC_CLASS_FACTORY_CLASS_KEY,
             PropertiesBasedIpV6TrafficClassFactory.class
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV6TrafficClass> getIpV6TrafficClassClass() {
    return loader.<IpV6TrafficClass>getClass(
             IPV6_TRAFFIC_CLASS_CLASS_KEY,
             IpV6SimpleTrafficClass.class
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV6FlowLabelFactory>
  getIpV6FlowLabelFactoryClass() {
    return loader.<IpV6FlowLabelFactory>getClass(
             IPV6_FLOW_LABEL_FACTORY_CLASS_KEY,
             PropertiesBasedIpV6FlowLabelFactory.class
           );
  }

  /**
   *
   * @return
   */
  public Class<? extends IpV6FlowLabel> getIpV6FlowLabelClass() {
    return loader.<IpV6FlowLabel>getClass(
             IPV6_FLOW_LABEL_CLASS_KEY,
             IpV6SimpleFlowLabel.class
           );
  }

}
