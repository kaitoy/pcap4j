/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2DisconnectionReasonCode
extends NamedNumber<Integer, Ssh2DisconnectionReasonCode> {

  // https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-3

  /**
   *
   */
  private static final long serialVersionUID = -8900248269268898171L;

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
    = new Ssh2DisconnectionReasonCode(1, "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_PROTOCOL_ERROR
    = new Ssh2DisconnectionReasonCode(2, "SSH_DISCONNECT_PROTOCOL_ERROR");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_KEY_EXCHANGE_FAILED
    = new Ssh2DisconnectionReasonCode(3, "SSH_DISCONNECT_KEY_EXCHANGE_FAILED");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_RESERVED
    = new Ssh2DisconnectionReasonCode(4, "SSH_DISCONNECT_RESERVED");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_MAC_ERROR
    = new Ssh2DisconnectionReasonCode(5, "SSH_DISCONNECT_MAC_ERROR");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_COMPRESSION_ERROR
    = new Ssh2DisconnectionReasonCode(6, "SSH_DISCONNECT_COMPRESSION_ERROR");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_SERVICE_NOT_AVAILABLE
    = new Ssh2DisconnectionReasonCode(7, "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
    = new Ssh2DisconnectionReasonCode(8, "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE
    = new Ssh2DisconnectionReasonCode(9, "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_CONNECTION_LOST
    = new Ssh2DisconnectionReasonCode(10, "SSH_DISCONNECT_CONNECTION_LOST");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_BY_APPLICATION
    = new Ssh2DisconnectionReasonCode(11, "SSH_DISCONNECT_BY_APPLICATION");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_TOO_MANY_CONNECTIONS
    = new Ssh2DisconnectionReasonCode(12, "SSH_DISCONNECT_TOO_MANY_CONNECTIONS");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_AUTH_CANCELLED_BY_USER
    = new Ssh2DisconnectionReasonCode(13, "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
    = new Ssh2DisconnectionReasonCode(14, "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE");

  /**
   *
   */
  public static final Ssh2DisconnectionReasonCode SSH_DISCONNECT_ILLEGAL_USER_NAME
    = new Ssh2DisconnectionReasonCode(15, "SSH_DISCONNECT_ILLEGAL_USER_NAME");

  private static final Map<Integer, Ssh2DisconnectionReasonCode> registry
    = new HashMap<Integer, Ssh2DisconnectionReasonCode>();

  static {
    for (Field field: Ssh2DisconnectionReasonCode.class.getFields()) {
      if (Ssh2DisconnectionReasonCode.class.isAssignableFrom(field.getType())) {
        try {
          Ssh2DisconnectionReasonCode f = (Ssh2DisconnectionReasonCode)field.get(null);
          registry.put(f.value(), f);
        } catch (IllegalArgumentException e) {
          throw new AssertionError(e);
        } catch (IllegalAccessException e) {
          throw new AssertionError(e);
        } catch (NullPointerException e) {
          continue;
        }
      }
    }
  }

  /**
   *
   * @param value
   * @param name
   */
  public Ssh2DisconnectionReasonCode(Integer value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a Ssh2DisconnectionReasonCode object.
   */
  public static Ssh2DisconnectionReasonCode getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new Ssh2DisconnectionReasonCode(value, "unknown");
    }
  }

  /**
   *
   * @param number
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