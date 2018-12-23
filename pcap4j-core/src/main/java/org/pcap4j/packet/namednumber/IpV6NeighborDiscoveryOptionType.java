/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * IPv6 Neighbor Discovery Option Type
 *
 * @see <a
 *     href="http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xml#icmpv6-parameters-5">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IpV6NeighborDiscoveryOptionType
    extends NamedNumber<Byte, IpV6NeighborDiscoveryOptionType> {

  /** */
  private static final long serialVersionUID = -4894881455029294238L;

  /** Source Link-layer Address: 1 */
  public static final IpV6NeighborDiscoveryOptionType SOURCE_LINK_LAYER_ADDRESS =
      new IpV6NeighborDiscoveryOptionType((byte) 1, "Source Link-layer Address");

  /** Target Link-layer Address: 2 */
  public static final IpV6NeighborDiscoveryOptionType TARGET_LINK_LAYER_ADDRESS =
      new IpV6NeighborDiscoveryOptionType((byte) 2, "Target Link-layer Address");

  /** Prefix Information: 3 */
  public static final IpV6NeighborDiscoveryOptionType PREFIX_INFORMATION =
      new IpV6NeighborDiscoveryOptionType((byte) 3, "Prefix Information");

  /** Redirected Header: 4 */
  public static final IpV6NeighborDiscoveryOptionType REDIRECTED_HEADER =
      new IpV6NeighborDiscoveryOptionType((byte) 4, "Redirected Header");

  /** MTU: 5 */
  public static final IpV6NeighborDiscoveryOptionType MTU =
      new IpV6NeighborDiscoveryOptionType((byte) 5, "MTU");

  /** NBMA Shortcut Limit: 6 */
  public static final IpV6NeighborDiscoveryOptionType NBMA_SHORTCUT_LIMIT =
      new IpV6NeighborDiscoveryOptionType((byte) 6, "NBMA Shortcut Limit");

  /** Advertisement Interval: 7 */
  public static final IpV6NeighborDiscoveryOptionType ADVERTISEMENT_INTERVAL =
      new IpV6NeighborDiscoveryOptionType((byte) 7, "Advertisement Interval");

  /** Home Agent Information: 8 */
  public static final IpV6NeighborDiscoveryOptionType HOME_AGENT_INFORMATION =
      new IpV6NeighborDiscoveryOptionType((byte) 8, "Home Agent Information");

  /** Source Address List: 9 */
  public static final IpV6NeighborDiscoveryOptionType SOURCE_ADDRESS_LIST =
      new IpV6NeighborDiscoveryOptionType((byte) 9, "Source Address List");

  /** Target Address List: 10 */
  public static final IpV6NeighborDiscoveryOptionType TARGET_ADDRESS_LIST =
      new IpV6NeighborDiscoveryOptionType((byte) 10, "Target Address List");

  /** CGA: 11 */
  public static final IpV6NeighborDiscoveryOptionType CGA =
      new IpV6NeighborDiscoveryOptionType((byte) 11, "CGA");

  /** RSA Signature: 12 */
  public static final IpV6NeighborDiscoveryOptionType RSA_SIGNATURE =
      new IpV6NeighborDiscoveryOptionType((byte) 12, "RSA Signature");

  /** Timestamp: 13 */
  public static final IpV6NeighborDiscoveryOptionType TIMESTAMP =
      new IpV6NeighborDiscoveryOptionType((byte) 13, "Timestamp");

  /** Nonce: 14 */
  public static final IpV6NeighborDiscoveryOptionType NONCE =
      new IpV6NeighborDiscoveryOptionType((byte) 14, "Nonce");

  /** Trust Anchor: 15 */
  public static final IpV6NeighborDiscoveryOptionType TRUST_ANCHOR =
      new IpV6NeighborDiscoveryOptionType((byte) 15, "Trust Anchor");

  /** Certificate: 16 */
  public static final IpV6NeighborDiscoveryOptionType CERTIFICATE =
      new IpV6NeighborDiscoveryOptionType((byte) 16, "Certificate");

  /** IP Address/Prefix: 17 */
  public static final IpV6NeighborDiscoveryOptionType IP_ADDRESS_PREFIX =
      new IpV6NeighborDiscoveryOptionType((byte) 17, "IP Address/Prefix");

  /** New Router Prefix Information: 18 */
  public static final IpV6NeighborDiscoveryOptionType NEW_ROUTER_PREFIX_INFORMATION =
      new IpV6NeighborDiscoveryOptionType((byte) 18, "New Router Prefix Information");

  /** Link-layer Address: 19 */
  public static final IpV6NeighborDiscoveryOptionType LINK_LAYER_ADDRESS =
      new IpV6NeighborDiscoveryOptionType((byte) 19, "Link-layer Address");

  /** Neighbor Advertisement Acknowledgment: 20 */
  public static final IpV6NeighborDiscoveryOptionType NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT =
      new IpV6NeighborDiscoveryOptionType((byte) 20, "Neighbor Advertisement Acknowledgment");

  /** MAP: 23 */
  public static final IpV6NeighborDiscoveryOptionType MAP =
      new IpV6NeighborDiscoveryOptionType((byte) 23, "MAP");

  /** Route Information: 24 */
  public static final IpV6NeighborDiscoveryOptionType ROUTE_INFORMATION =
      new IpV6NeighborDiscoveryOptionType((byte) 24, "Route Information");

  /** Recursive DNS Server: 25 */
  public static final IpV6NeighborDiscoveryOptionType RECURSIVE_DNS_SERVER =
      new IpV6NeighborDiscoveryOptionType((byte) 25, "Recursive DNS Server");

  /** RA Flags Extension: 26 */
  public static final IpV6NeighborDiscoveryOptionType RA_FLAGS_EXTENSION =
      new IpV6NeighborDiscoveryOptionType((byte) 26, "RA Flags Extension");

  /** Handover Key Request: 27 */
  public static final IpV6NeighborDiscoveryOptionType HANDOVER_KEY_REQUEST =
      new IpV6NeighborDiscoveryOptionType((byte) 27, "Handover Key Request");

  /** Handover Key Reply: 28 */
  public static final IpV6NeighborDiscoveryOptionType HANDOVER_KEY_REPLY =
      new IpV6NeighborDiscoveryOptionType((byte) 28, "Handover Key Reply");

  /** Handover Assist Information: 29 */
  public static final IpV6NeighborDiscoveryOptionType HANDOVER_ASSIST_INFORMATION =
      new IpV6NeighborDiscoveryOptionType((byte) 29, "Handover Assist Information");

  /** Mobile Node Identifier: 30 */
  public static final IpV6NeighborDiscoveryOptionType MOBILE_NODE_IDENTIFIER =
      new IpV6NeighborDiscoveryOptionType((byte) 30, "Mobile Node Identifier");

  /** DNS Search List: 31 */
  public static final IpV6NeighborDiscoveryOptionType DNS_SEARCH_LIST =
      new IpV6NeighborDiscoveryOptionType((byte) 31, "DNS Search List");

  /** Proxy Signature (PS): 32 */
  public static final IpV6NeighborDiscoveryOptionType PROXY_SIGNATURE =
      new IpV6NeighborDiscoveryOptionType((byte) 32, "Proxy Signature");

  /** Address Registration: 33 */
  public static final IpV6NeighborDiscoveryOptionType ADDRESS_REGISTRATION =
      new IpV6NeighborDiscoveryOptionType((byte) 33, "Address Registration");

  /** 6LoWPAN Context: 34 */
  public static final IpV6NeighborDiscoveryOptionType SIX_LOWPAN_CONTEXT =
      new IpV6NeighborDiscoveryOptionType((byte) 34, "6LoWPAN Context");

  /** Authoritative Border Router: 35 */
  public static final IpV6NeighborDiscoveryOptionType AUTHORITATIVE_BORDER_ROUTER =
      new IpV6NeighborDiscoveryOptionType((byte) 35, "Authoritative Border Router");

  /** 6LoWPAN Capability Indication (6CIO): 36 */
  public static final IpV6NeighborDiscoveryOptionType SIX_CIO =
      new IpV6NeighborDiscoveryOptionType((byte) 36, "6CIO");

  /** CARD Request: 138 */
  public static final IpV6NeighborDiscoveryOptionType CARD_REQUEST =
      new IpV6NeighborDiscoveryOptionType((byte) 138, "CARD Request");

  /** CARD Reply: 139 */
  public static final IpV6NeighborDiscoveryOptionType CARD_REPLY =
      new IpV6NeighborDiscoveryOptionType((byte) 139, "CARD Reply");

  private static final Map<Byte, IpV6NeighborDiscoveryOptionType> registry =
      new HashMap<Byte, IpV6NeighborDiscoveryOptionType>();

  static {
    registry.put(SOURCE_LINK_LAYER_ADDRESS.value(), SOURCE_LINK_LAYER_ADDRESS);
    registry.put(TARGET_LINK_LAYER_ADDRESS.value(), TARGET_LINK_LAYER_ADDRESS);
    registry.put(PREFIX_INFORMATION.value(), PREFIX_INFORMATION);
    registry.put(REDIRECTED_HEADER.value(), REDIRECTED_HEADER);
    registry.put(MTU.value(), MTU);
    registry.put(NBMA_SHORTCUT_LIMIT.value(), NBMA_SHORTCUT_LIMIT);
    registry.put(ADVERTISEMENT_INTERVAL.value(), ADVERTISEMENT_INTERVAL);
    registry.put(HOME_AGENT_INFORMATION.value(), HOME_AGENT_INFORMATION);
    registry.put(SOURCE_ADDRESS_LIST.value(), SOURCE_ADDRESS_LIST);
    registry.put(TARGET_ADDRESS_LIST.value(), TARGET_ADDRESS_LIST);
    registry.put(CGA.value(), CGA);
    registry.put(RSA_SIGNATURE.value(), RSA_SIGNATURE);
    registry.put(TIMESTAMP.value(), TIMESTAMP);
    registry.put(NONCE.value(), NONCE);
    registry.put(TRUST_ANCHOR.value(), TRUST_ANCHOR);
    registry.put(CERTIFICATE.value(), CERTIFICATE);
    registry.put(IP_ADDRESS_PREFIX.value(), IP_ADDRESS_PREFIX);
    registry.put(NEW_ROUTER_PREFIX_INFORMATION.value(), NEW_ROUTER_PREFIX_INFORMATION);
    registry.put(LINK_LAYER_ADDRESS.value(), LINK_LAYER_ADDRESS);
    registry.put(
        NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT.value(), NEIGHBOR_ADVERTISEMENT_ACKNOWLEDGMENT);
    registry.put(MAP.value(), MAP);
    registry.put(ROUTE_INFORMATION.value(), ROUTE_INFORMATION);
    registry.put(RECURSIVE_DNS_SERVER.value(), RECURSIVE_DNS_SERVER);
    registry.put(RA_FLAGS_EXTENSION.value(), RA_FLAGS_EXTENSION);
    registry.put(HANDOVER_KEY_REQUEST.value(), HANDOVER_KEY_REQUEST);
    registry.put(HANDOVER_KEY_REPLY.value(), HANDOVER_KEY_REPLY);
    registry.put(HANDOVER_ASSIST_INFORMATION.value(), HANDOVER_ASSIST_INFORMATION);
    registry.put(MOBILE_NODE_IDENTIFIER.value(), MOBILE_NODE_IDENTIFIER);
    registry.put(DNS_SEARCH_LIST.value(), DNS_SEARCH_LIST);
    registry.put(PROXY_SIGNATURE.value(), PROXY_SIGNATURE);
    registry.put(ADDRESS_REGISTRATION.value(), ADDRESS_REGISTRATION);
    registry.put(SIX_LOWPAN_CONTEXT.value(), SIX_LOWPAN_CONTEXT);
    registry.put(AUTHORITATIVE_BORDER_ROUTER.value(), AUTHORITATIVE_BORDER_ROUTER);
    registry.put(SIX_CIO.value(), SIX_CIO);
    registry.put(CARD_REQUEST.value(), CARD_REQUEST);
    registry.put(CARD_REPLY.value(), CARD_REPLY);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV6NeighborDiscoveryOptionType(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IpV6NeighborDiscoveryOptionType object.
   */
  public static IpV6NeighborDiscoveryOptionType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV6NeighborDiscoveryOptionType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a IpV6NeighborDiscoveryOptionType object.
   */
  public static IpV6NeighborDiscoveryOptionType register(IpV6NeighborDiscoveryOptionType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public int compareTo(IpV6NeighborDiscoveryOptionType o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
