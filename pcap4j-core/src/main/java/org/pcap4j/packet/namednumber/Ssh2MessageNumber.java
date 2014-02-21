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
public final class Ssh2MessageNumber extends NamedNumber<Byte> {

  // https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-1
  // http://www.rfc-editor.org/errata_search.php?rfc=4253

  /**
   *
   */
  private static final long serialVersionUID = -8900248269268898171L;

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_DISCONNECT
    = new Ssh2MessageNumber((byte)1, "SSH_MSG_DISCONNECT");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_IGNORE
    = new Ssh2MessageNumber((byte)2, "SSH_MSG_IGNORE");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_UNIMPLEMENTED
    = new Ssh2MessageNumber((byte)3, "SSH_MSG_UNIMPLEMENTED");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_DEBUG
    = new Ssh2MessageNumber((byte)4, "SSH_MSG_DEBUG");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_SERVICE_REQUEST
    = new Ssh2MessageNumber((byte)5, "SSH_MSG_SERVICE_REQUEST");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_SERVICE_ACCEPT
    = new Ssh2MessageNumber((byte)6, "SSH_MSG_SERVICE_ACCEPT");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_KEXINIT
    = new Ssh2MessageNumber((byte)20, "SSH_MSG_KEXINIT");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_NEWKEYS
    = new Ssh2MessageNumber((byte)21, "SSH_MSG_NEWKEYS");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_KEXDH_INIT
    = new Ssh2MessageNumber((byte)30, "SSH_MSG_KEXDH_INIT");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_KEXDH_REPLY
    = new Ssh2MessageNumber((byte)31, "SSH_MSG_KEXDH_REPLY");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_REQUEST
    = new Ssh2MessageNumber((byte)50, "SSH_MSG_USERAUTH_REQUEST");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_FAILURE
    = new Ssh2MessageNumber((byte)51, "SSH_MSG_USERAUTH_FAILURE");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_SUCCESS
    = new Ssh2MessageNumber((byte)52, "SSH_MSG_USERAUTH_SUCCESS");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_BANNER
    = new Ssh2MessageNumber((byte)53, "SSH_MSG_USERAUTH_BANNER");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_INFO_REQUEST
    = new Ssh2MessageNumber((byte)60, "SSH_MSG_USERAUTH_INFO_REQUEST");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_INFO_RESPONSE
    = new Ssh2MessageNumber((byte)61, "SSH_MSG_USERAUTH_INFO_RESPONSE");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_GLOBAL_REQUEST
    = new Ssh2MessageNumber((byte)80, "SSH_MSG_GLOBAL_REQUEST");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_REQUEST_SUCCESS
    = new Ssh2MessageNumber((byte)81, "SSH_MSG_REQUEST_SUCCESS");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_REQUEST_FAILURE
    = new Ssh2MessageNumber((byte)82, "SSH_MSG_REQUEST_FAILURE");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_OPEN
    = new Ssh2MessageNumber((byte)90, "SSH_MSG_CHANNEL_OPEN");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    = new Ssh2MessageNumber((byte)91, "SSH_MSG_CHANNEL_OPEN_CONFIRMATION");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_OPEN_FAILURE
    = new Ssh2MessageNumber((byte)92, "SSH_MSG_CHANNEL_OPEN_FAILURE");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_WINDOW_ADJUST
    = new Ssh2MessageNumber((byte)93, "SSH_MSG_CHANNEL_WINDOW_ADJUST");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_DATA
    = new Ssh2MessageNumber((byte)94, "SSH_MSG_CHANNEL_DATA");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_EXTENDED_DATA
    = new Ssh2MessageNumber((byte)95, "SSH_MSG_CHANNEL_EXTENDED_DATA");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_EOF
    = new Ssh2MessageNumber((byte)96, "SSH_MSG_CHANNEL_EOF");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_CLOSE
    = new Ssh2MessageNumber((byte)97, "SSH_MSG_CHANNEL_CLOSE");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_REQUEST
    = new Ssh2MessageNumber((byte)98, "SSH_MSG_CHANNEL_REQUEST");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_SUCCESS
    = new Ssh2MessageNumber((byte)99, "SSH_MSG_CHANNEL_SUCCESS");

  /**
   *
   */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_FAILURE
    = new Ssh2MessageNumber((byte)100, "SSH_MSG_CHANNEL_FAILURE");

  private static final Map<Byte, Ssh2MessageNumber> registry
    = new HashMap<Byte, Ssh2MessageNumber>();

  static {
    for (Field field: Ssh2MessageNumber.class.getFields()) {
      if (Ssh2MessageNumber.class.isAssignableFrom(field.getType())) {
        try {
          Ssh2MessageNumber f = (Ssh2MessageNumber)field.get(null);
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
  public Ssh2MessageNumber(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a Ssh2MessageNumber object.
   */
  public static Ssh2MessageNumber getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new Ssh2MessageNumber(value, "unknown");
    }
  }

  /**
   *
   * @param number
   * @return a Ssh2MessageNumber object.
   */
  public static Ssh2MessageNumber register(Ssh2MessageNumber number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

}