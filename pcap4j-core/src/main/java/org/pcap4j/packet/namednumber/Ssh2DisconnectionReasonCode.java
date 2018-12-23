/*_##########################################################################
  _##
  _##  Copyright (C) 2014-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * SSH2 Disconnection Reason Code
 *
 * @see <a
 *     href="https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-3">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class Ssh2DisconnectionReasonCode
    extends NamedNumber<Integer, Ssh2DisconnectionReasonCode> {

  /** */
  private static final long serialVersionUID = -8900248269268898171L;

  /** SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: 1 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT =
      new Ssh2DisconnectionReasonCode(1, "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT");

  /** SSH_DISCONNECT_PROTOCOL_ERROR: 2 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_PROTOCOL_ERROR =
      new Ssh2DisconnectionReasonCode(2, "SSH_DISCONNECT_PROTOCOL_ERROR");

  /** SSH_DISCONNECT_KEY_EXCHANGE_FAILED: 3 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_KEY_EXCHANGE_FAILED =
      new Ssh2DisconnectionReasonCode(3, "SSH_DISCONNECT_KEY_EXCHANGE_FAILED");

  /** SSH_DISCONNECT_RESERVED: 4 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_RESERVED =
      new Ssh2DisconnectionReasonCode(4, "SSH_DISCONNECT_RESERVED");

  /** SSH_DISCONNECT_MAC_ERROR: 5 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_MAC_ERROR =
      new Ssh2DisconnectionReasonCode(5, "SSH_DISCONNECT_MAC_ERROR");

  /** SSH_DISCONNECT_COMPRESSION_ERROR: 6 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_COMPRESSION_ERROR =
      new Ssh2DisconnectionReasonCode(6, "SSH_DISCONNECT_COMPRESSION_ERROR");

  /** SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: 7 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_SERVICE_NOT_AVAILABLE =
      new Ssh2DisconnectionReasonCode(7, "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE");

  /** SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: 8 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED =
      new Ssh2DisconnectionReasonCode(8, "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED");

  /** SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: 9 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE =
      new Ssh2DisconnectionReasonCode(9, "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE");

  /** SSH_DISCONNECT_CONNECTION_LOST: 10 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_CONNECTION_LOST =
      new Ssh2DisconnectionReasonCode(10, "SSH_DISCONNECT_CONNECTION_LOST");

  /** SSH_DISCONNECT_BY_APPLICATION: 11 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_BY_APPLICATION =
      new Ssh2DisconnectionReasonCode(11, "SSH_DISCONNECT_BY_APPLICATION");

  /** SSH_DISCONNECT_TOO_MANY_CONNECTIONS: 12 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_TOO_MANY_CONNECTIONS =
      new Ssh2DisconnectionReasonCode(12, "SSH_DISCONNECT_TOO_MANY_CONNECTIONS");

  /** SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: 13 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_AUTH_CANCELLED_BY_USER =
      new Ssh2DisconnectionReasonCode(13, "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER");

  /** SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: 14 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE =
      new Ssh2DisconnectionReasonCode(14, "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE");

  /** SSH_DISCONNECT_ILLEGAL_USER_NAME: 15 */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_ILLEGAL_USER_NAME =
      new Ssh2DisconnectionReasonCode(15, "SSH_DISCONNECT_ILLEGAL_USER_NAME");

  private static final Map<Integer, Ssh2DisconnectionReasonCode> registry =
      new HashMap<Integer, Ssh2DisconnectionReasonCode>();

  static {
    registry.put(
        SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT.value(),
        SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT);
    registry.put(SSH_DISCONNECT_PROTOCOL_ERROR.value(), SSH_DISCONNECT_PROTOCOL_ERROR);
    registry.put(SSH_DISCONNECT_KEY_EXCHANGE_FAILED.value(), SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
    registry.put(SSH_DISCONNECT_RESERVED.value(), SSH_DISCONNECT_RESERVED);
    registry.put(SSH_DISCONNECT_MAC_ERROR.value(), SSH_DISCONNECT_MAC_ERROR);
    registry.put(SSH_DISCONNECT_COMPRESSION_ERROR.value(), SSH_DISCONNECT_COMPRESSION_ERROR);
    registry.put(
        SSH_DISCONNECT_SERVICE_NOT_AVAILABLE.value(), SSH_DISCONNECT_SERVICE_NOT_AVAILABLE);
    registry.put(
        SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED.value(),
        SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
    registry.put(
        SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE.value(), SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
    registry.put(SSH_DISCONNECT_CONNECTION_LOST.value(), SSH_DISCONNECT_CONNECTION_LOST);
    registry.put(SSH_DISCONNECT_BY_APPLICATION.value(), SSH_DISCONNECT_BY_APPLICATION);
    registry.put(SSH_DISCONNECT_TOO_MANY_CONNECTIONS.value(), SSH_DISCONNECT_TOO_MANY_CONNECTIONS);
    registry.put(
        SSH_DISCONNECT_AUTH_CANCELLED_BY_USER.value(), SSH_DISCONNECT_AUTH_CANCELLED_BY_USER);
    registry.put(
        SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE.value(),
        SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
    registry.put(SSH_DISCONNECT_ILLEGAL_USER_NAME.value(), SSH_DISCONNECT_ILLEGAL_USER_NAME);
  }

  /**
   * @param value value
   * @param name name
   */
  public Ssh2DisconnectionReasonCode(Integer value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a Ssh2DisconnectionReasonCode object.
   */
  public static Ssh2DisconnectionReasonCode getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Ssh2DisconnectionReasonCode(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a Ssh2DisconnectionReasonCode object.
   */
  public static Ssh2DisconnectionReasonCode register(Ssh2DisconnectionReasonCode number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFFFFFFL);
  }

  @Override
  public int compareTo(Ssh2DisconnectionReasonCode o) {
    return value().compareTo(o.value());
  }
}
