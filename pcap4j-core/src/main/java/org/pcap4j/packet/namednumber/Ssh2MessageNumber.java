/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * SSH2 Message Number
 *
 * @see <a
 *     href="https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-1">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2MessageNumber extends NamedNumber<Byte, Ssh2MessageNumber> {

  /** */
  private static final long serialVersionUID = -8900248269268898171L;

  /** SSH_MSG_DISCONNECT: 1 */
  public static final Ssh2MessageNumber SSH_MSG_DISCONNECT =
      new Ssh2MessageNumber((byte) 1, "SSH_MSG_DISCONNECT");

  /** SSH_MSG_IGNORE: 2 */
  public static final Ssh2MessageNumber SSH_MSG_IGNORE =
      new Ssh2MessageNumber((byte) 2, "SSH_MSG_IGNORE");

  /** SSH_MSG_UNIMPLEMENTED: 3 */
  public static final Ssh2MessageNumber SSH_MSG_UNIMPLEMENTED =
      new Ssh2MessageNumber((byte) 3, "SSH_MSG_UNIMPLEMENTED");

  /** SSH_MSG_DEBUG: 4 */
  public static final Ssh2MessageNumber SSH_MSG_DEBUG =
      new Ssh2MessageNumber((byte) 4, "SSH_MSG_DEBUG");

  /** SSH_MSG_SERVICE_REQUEST: 5 */
  public static final Ssh2MessageNumber SSH_MSG_SERVICE_REQUEST =
      new Ssh2MessageNumber((byte) 5, "SSH_MSG_SERVICE_REQUEST");

  /** SSH_MSG_SERVICE_ACCEPT: 6 */
  public static final Ssh2MessageNumber SSH_MSG_SERVICE_ACCEPT =
      new Ssh2MessageNumber((byte) 6, "SSH_MSG_SERVICE_ACCEPT");

  /** SSH_MSG_KEXINIT: 20 */
  public static final Ssh2MessageNumber SSH_MSG_KEXINIT =
      new Ssh2MessageNumber((byte) 20, "SSH_MSG_KEXINIT");

  /** SSH_MSG_NEWKEYS: 21 */
  public static final Ssh2MessageNumber SSH_MSG_NEWKEYS =
      new Ssh2MessageNumber((byte) 21, "SSH_MSG_NEWKEYS");

  /** SSH_MSG_KEXDH_INIT: 30 */
  public static final Ssh2MessageNumber SSH_MSG_KEXDH_INIT =
      new Ssh2MessageNumber((byte) 30, "SSH_MSG_KEXDH_INIT");

  /** SSH_MSG_KEXDH_REPLY: 31 */
  public static final Ssh2MessageNumber SSH_MSG_KEXDH_REPLY =
      new Ssh2MessageNumber((byte) 31, "SSH_MSG_KEXDH_REPLY");

  /** SSH_MSG_USERAUTH_REQUEST: 50 */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_REQUEST =
      new Ssh2MessageNumber((byte) 50, "SSH_MSG_USERAUTH_REQUEST");

  /** SSH_MSG_USERAUTH_FAILURE: 51 */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_FAILURE =
      new Ssh2MessageNumber((byte) 51, "SSH_MSG_USERAUTH_FAILURE");

  /** SSH_MSG_USERAUTH_SUCCESS: 52 */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_SUCCESS =
      new Ssh2MessageNumber((byte) 52, "SSH_MSG_USERAUTH_SUCCESS");

  /** SSH_MSG_USERAUTH_BANNER: 53 */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_BANNER =
      new Ssh2MessageNumber((byte) 53, "SSH_MSG_USERAUTH_BANNER");

  /** SSH_MSG_USERAUTH_INFO_REQUEST: 60 */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_INFO_REQUEST =
      new Ssh2MessageNumber((byte) 60, "SSH_MSG_USERAUTH_INFO_REQUEST");

  /** SSH_MSG_USERAUTH_INFO_RESPONSE: 61 */
  public static final Ssh2MessageNumber SSH_MSG_USERAUTH_INFO_RESPONSE =
      new Ssh2MessageNumber((byte) 61, "SSH_MSG_USERAUTH_INFO_RESPONSE");

  /** SSH_MSG_GLOBAL_REQUEST: 80 */
  public static final Ssh2MessageNumber SSH_MSG_GLOBAL_REQUEST =
      new Ssh2MessageNumber((byte) 80, "SSH_MSG_GLOBAL_REQUEST");

  /** SSH_MSG_REQUEST_SUCCESS: 81 */
  public static final Ssh2MessageNumber SSH_MSG_REQUEST_SUCCESS =
      new Ssh2MessageNumber((byte) 81, "SSH_MSG_REQUEST_SUCCESS");

  /** SSH_MSG_REQUEST_FAILURE: 82 */
  public static final Ssh2MessageNumber SSH_MSG_REQUEST_FAILURE =
      new Ssh2MessageNumber((byte) 82, "SSH_MSG_REQUEST_FAILURE");

  /** SSH_MSG_CHANNEL_OPEN: 90 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_OPEN =
      new Ssh2MessageNumber((byte) 90, "SSH_MSG_CHANNEL_OPEN");

  /** SSH_MSG_CHANNEL_OPEN_CONFIRMATION: 91 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_OPEN_CONFIRMATION =
      new Ssh2MessageNumber((byte) 91, "SSH_MSG_CHANNEL_OPEN_CONFIRMATION");

  /** SSH_MSG_CHANNEL_OPEN_FAILURE: 92 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_OPEN_FAILURE =
      new Ssh2MessageNumber((byte) 92, "SSH_MSG_CHANNEL_OPEN_FAILURE");

  /** SSH_MSG_CHANNEL_WINDOW_ADJUST: 93 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_WINDOW_ADJUST =
      new Ssh2MessageNumber((byte) 93, "SSH_MSG_CHANNEL_WINDOW_ADJUST");

  /** SSH_MSG_CHANNEL_DATA: 94 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_DATA =
      new Ssh2MessageNumber((byte) 94, "SSH_MSG_CHANNEL_DATA");

  /** SSH_MSG_CHANNEL_EXTENDED_DATA: 95 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_EXTENDED_DATA =
      new Ssh2MessageNumber((byte) 95, "SSH_MSG_CHANNEL_EXTENDED_DATA");

  /** SSH_MSG_CHANNEL_EOF: 96 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_EOF =
      new Ssh2MessageNumber((byte) 96, "SSH_MSG_CHANNEL_EOF");

  /** SSH_MSG_CHANNEL_CLOSE: 97 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_CLOSE =
      new Ssh2MessageNumber((byte) 97, "SSH_MSG_CHANNEL_CLOSE");

  /** SSH_MSG_CHANNEL_REQUEST: 98 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_REQUEST =
      new Ssh2MessageNumber((byte) 98, "SSH_MSG_CHANNEL_REQUEST");

  /** SSH_MSG_CHANNEL_SUCCESS: 99 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_SUCCESS =
      new Ssh2MessageNumber((byte) 99, "SSH_MSG_CHANNEL_SUCCESS");

  /** SSH_MSG_CHANNEL_FAILURE: 100 */
  public static final Ssh2MessageNumber SSH_MSG_CHANNEL_FAILURE =
      new Ssh2MessageNumber((byte) 100, "SSH_MSG_CHANNEL_FAILURE");

  private static final Map<Byte, Ssh2MessageNumber> registry =
      new HashMap<Byte, Ssh2MessageNumber>();

  static {
    registry.put(SSH_MSG_DISCONNECT.value(), SSH_MSG_DISCONNECT);
    registry.put(SSH_MSG_IGNORE.value(), SSH_MSG_IGNORE);
    registry.put(SSH_MSG_UNIMPLEMENTED.value(), SSH_MSG_UNIMPLEMENTED);
    registry.put(SSH_MSG_DEBUG.value(), SSH_MSG_DEBUG);
    registry.put(SSH_MSG_SERVICE_REQUEST.value(), SSH_MSG_SERVICE_REQUEST);
    registry.put(SSH_MSG_SERVICE_ACCEPT.value(), SSH_MSG_SERVICE_ACCEPT);
    registry.put(SSH_MSG_KEXINIT.value(), SSH_MSG_KEXINIT);
    registry.put(SSH_MSG_NEWKEYS.value(), SSH_MSG_NEWKEYS);
    registry.put(SSH_MSG_USERAUTH_REQUEST.value(), SSH_MSG_USERAUTH_REQUEST);
    registry.put(SSH_MSG_USERAUTH_FAILURE.value(), SSH_MSG_USERAUTH_FAILURE);
    registry.put(SSH_MSG_USERAUTH_SUCCESS.value(), SSH_MSG_USERAUTH_SUCCESS);
    registry.put(SSH_MSG_USERAUTH_BANNER.value(), SSH_MSG_USERAUTH_BANNER);
    registry.put(SSH_MSG_USERAUTH_INFO_REQUEST.value(), SSH_MSG_USERAUTH_INFO_REQUEST);
    registry.put(SSH_MSG_USERAUTH_INFO_RESPONSE.value(), SSH_MSG_USERAUTH_INFO_RESPONSE);
    registry.put(SSH_MSG_GLOBAL_REQUEST.value(), SSH_MSG_GLOBAL_REQUEST);
    registry.put(SSH_MSG_REQUEST_SUCCESS.value(), SSH_MSG_REQUEST_SUCCESS);
    registry.put(SSH_MSG_REQUEST_FAILURE.value(), SSH_MSG_REQUEST_FAILURE);
    registry.put(SSH_MSG_CHANNEL_OPEN.value(), SSH_MSG_CHANNEL_OPEN);
    registry.put(SSH_MSG_CHANNEL_OPEN_CONFIRMATION.value(), SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    registry.put(SSH_MSG_CHANNEL_OPEN_FAILURE.value(), SSH_MSG_CHANNEL_OPEN_FAILURE);
    registry.put(SSH_MSG_CHANNEL_WINDOW_ADJUST.value(), SSH_MSG_CHANNEL_WINDOW_ADJUST);
    registry.put(SSH_MSG_CHANNEL_DATA.value(), SSH_MSG_CHANNEL_DATA);
    registry.put(SSH_MSG_CHANNEL_EXTENDED_DATA.value(), SSH_MSG_CHANNEL_EXTENDED_DATA);
    registry.put(SSH_MSG_CHANNEL_EOF.value(), SSH_MSG_CHANNEL_EOF);
    registry.put(SSH_MSG_CHANNEL_CLOSE.value(), SSH_MSG_CHANNEL_CLOSE);
    registry.put(SSH_MSG_CHANNEL_REQUEST.value(), SSH_MSG_CHANNEL_REQUEST);
    registry.put(SSH_MSG_CHANNEL_SUCCESS.value(), SSH_MSG_CHANNEL_SUCCESS);
    registry.put(SSH_MSG_CHANNEL_FAILURE.value(), SSH_MSG_CHANNEL_FAILURE);
  }

  /**
   * @param value value
   * @param name name
   */
  public Ssh2MessageNumber(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a Ssh2MessageNumber object.
   */
  public static Ssh2MessageNumber getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Ssh2MessageNumber(value, "unknown");
    }
  }

  /**
   * @param number number
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
  public int compareTo(Ssh2MessageNumber o) {
    return value().compareTo(o.value());
  }
}
