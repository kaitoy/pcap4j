/*_##########################################################################
  _##
  _##  Copyright (C) 2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.GtpV1Packet.GtpV1ExtensionHeader;
import org.pcap4j.packet.GtpV1PduSessionContainerExtensionHeader;
import org.pcap4j.packet.IllegalGtpV1ExtensionHeader;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.UnknownGtpV1ExtensionHeader;
import org.pcap4j.packet.namednumber.GtpV1ExtensionHeaderType;

/**
 * @author Leo Ma
 * @since pcap4j 1.7.7
 */
public final class StaticGtpV1ExtensionHeaderFactory
    implements PacketFactory<GtpV1ExtensionHeader, GtpV1ExtensionHeaderType> {

  private static final StaticGtpV1ExtensionHeaderFactory INSTANCE =
      new StaticGtpV1ExtensionHeaderFactory();
  private final Map<GtpV1ExtensionHeaderType, Instantiater> instantiaters =
      new HashMap<GtpV1ExtensionHeaderType, Instantiater>();

  private StaticGtpV1ExtensionHeaderFactory() {
    instantiaters.put(
        GtpV1ExtensionHeaderType.PDU_SESSION_CONTAINER,
        new Instantiater() {
          @Override
          public GtpV1ExtensionHeader newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return GtpV1PduSessionContainerExtensionHeader.newInstance(rawData, offset, length);
          }

          @Override
          public Class<GtpV1PduSessionContainerExtensionHeader> getTargetClass() {
            return GtpV1PduSessionContainerExtensionHeader.class;
          }
        });
  };

  /** @return the singleton instance of StaticIpV4OptionFactory. */
  public static StaticGtpV1ExtensionHeaderFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public GtpV1ExtensionHeader newInstance(
      byte[] rawData, int offset, int length, GtpV1ExtensionHeaderType number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ").append(rawData).append(" number: ").append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData, offset, length);
      }
    } catch (IllegalRawDataException e) {
      return IllegalGtpV1ExtensionHeader.newInstance(rawData, offset, length);
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public GtpV1ExtensionHeader newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownGtpV1ExtensionHeader.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalGtpV1ExtensionHeader.newInstance(rawData, offset, length);
    }
  }

  @Override
  public Class<? extends GtpV1ExtensionHeader> getTargetClass(GtpV1ExtensionHeaderType number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends GtpV1ExtensionHeader> getTargetClass() {
    return UnknownGtpV1ExtensionHeader.class;
  }

  private static interface Instantiater {

    public GtpV1ExtensionHeader newInstance(byte[] rawData, int offset, int length)
        throws IllegalRawDataException;

    public Class<? extends GtpV1ExtensionHeader> getTargetClass();
  }
}
