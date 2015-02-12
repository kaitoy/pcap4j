/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * ARP Operation Code
 *
 * @see <a href="http://www.iana.org/assignments/arp-parameters/arp-parameters.xml#arp-parameters-1">IANA Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class ArpOperation extends NamedNumber<Short, ArpOperation> {

  /**
   *
   */
  private static final long serialVersionUID = 5558693543482950163L;
  /**
   * REQUEST: 1
   */
  public static final ArpOperation REQUEST
    = new ArpOperation((short)1, "REQUEST");

  /**
   * REPLY: 2
   */
  public static final ArpOperation REPLY
    = new ArpOperation((short)2, "REPLY");

  /**
   * request Reverse: 3
   */
  public static final ArpOperation REQUEST_REVERSE
    = new ArpOperation((short)3, "request Reverse");

  /**
   * reply Reverse: 4
   */
  public static final ArpOperation REPLY_REVERSE
    = new ArpOperation((short)4, "reply Reverse");

  /**
   * DRARP-Request: 5
   */
  public static final ArpOperation DRARP_REQUEST
    = new ArpOperation((short)5, "DRARP-Request");

  /**
   * DRARP-Reply: 6
   */
  public static final ArpOperation DRARP_REPLY
    = new ArpOperation((short)6, "DRARP-Reply");

  /**
   * DRARP-Error: 7
   */
  public static final ArpOperation DRARP_ERROR
    = new ArpOperation((short)7, "DRARP-Error");

  /**
   * InARP-Request: 8
   */
  public static final ArpOperation INARP_REQUEST
    = new ArpOperation((short)8, "InARP-Request");

  /**
   * InARP-Reply: 9
   */
  public static final ArpOperation INARP_REPLY
    = new ArpOperation((short)9, "InARP-Reply");

  /**
   * ARP-NAK: 10
   */
  public static final ArpOperation ARP_NAK
    = new ArpOperation((short)10, "ARP-NAK");

  /**
   * MARS-Request: 11
   */
  public static final ArpOperation MARS_REQUEST
    = new ArpOperation((short)11, "MARS-Request");

  /**
   * MARS-Multi: 12
   */
  public static final ArpOperation MARS_MULTI
    = new ArpOperation((short)12, "MARS-Multi");

  /**
   * MARS-MServ: 13
   */
  public static final ArpOperation MARS_MSERV
    = new ArpOperation((short)13, "MARS-MServ");

  /**
   * MARS-Join: 14
   */
  public static final ArpOperation MARS_JOIN
    = new ArpOperation((short)14, "MARS-Join");

  /**
   * MARS-Leave: 15
   */
  public static final ArpOperation MARS_LEAVE
    = new ArpOperation((short)15, "MARS-Leave");

  /**
   * MARS-NAK: 16
   */
  public static final ArpOperation MARS_NAK
    = new ArpOperation((short)16, "MARS-NAK");

  /**
   * MARS-Unserv: 17
   */
  public static final ArpOperation MARS_UNSERV
    = new ArpOperation((short)17, "MARS-Unserv");

  /**
   * MARS-SJoin: 18
   */
  public static final ArpOperation MARS_SJOIN
    = new ArpOperation((short)18, "MARS-SJoin");

  /**
   * MARS-SLeave: 19
   */
  public static final ArpOperation MARS_SLEAVE
    = new ArpOperation((short)19, "MARS-SLeave");

  /**
   * MARS-Grouplist-Request: 20
   */
  public static final ArpOperation MARS_GROUPLIST_REQUEST
    = new ArpOperation((short)20, "MARS-Grouplist-Request");

  /**
   * MARS-Grouplist-Reply: 21
   */
  public static final ArpOperation MARS_GROUPLIST_REPLY
    = new ArpOperation((short)21, "MARS-Grouplist-Reply");

  /**
   * MARS-Redirect-Map: 22
   */
  public static final ArpOperation MARS_REDIRECT_MAP
    = new ArpOperation((short)22, "MARS-Redirect-Map");

  /**
   * MAPOS-UNARP: 23
   */
  public static final ArpOperation MAPOS_UNARP
    = new ArpOperation((short)23, "MAPOS-UNARP");

  /**
   * OP_EXP1: 24
   */
  public static final ArpOperation OP_EXP1
    = new ArpOperation((short)24, "OP_EXP1");

  /**
   * OP_EXP2: 25
   */
  public static final ArpOperation OP_EXP2
    = new ArpOperation((short)25, "OP_EXP2");

  private static final Map<Short, ArpOperation> registry
    = new HashMap<Short, ArpOperation>();

  static {
    registry.put((short)1, REQUEST);
    registry.put((short)2, REPLY);
    registry.put((short)3, REQUEST_REVERSE);
    registry.put((short)4, REPLY_REVERSE);
    registry.put((short)5, DRARP_REQUEST);
    registry.put((short)6, DRARP_REPLY);
    registry.put((short)7, DRARP_ERROR);
    registry.put((short)8, INARP_REQUEST);
    registry.put((short)9, INARP_REPLY);
    registry.put((short)10, ARP_NAK);
    registry.put((short)11, MARS_REQUEST);
    registry.put((short)12, MARS_MULTI);
    registry.put((short)13, MARS_MSERV);
    registry.put((short)14, MARS_JOIN);
    registry.put((short)15, MARS_LEAVE);
    registry.put((short)16, MARS_NAK);
    registry.put((short)17, MARS_UNSERV);
    registry.put((short)18, MARS_SJOIN);
    registry.put((short)19, MARS_SLEAVE);
    registry.put((short)20, MARS_GROUPLIST_REQUEST);
    registry.put((short)21, MARS_GROUPLIST_REPLY);
    registry.put((short)22, MARS_REDIRECT_MAP);
    registry.put((short)23, MAPOS_UNARP);
    registry.put((short)24, OP_EXP1);
    registry.put((short)25, OP_EXP2);
  }

  /**
   *
   * @param value
   * @param name
   */
  public ArpOperation(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a ArpOperation object.
   */
  public static ArpOperation getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new ArpOperation(value, "unknown");
    }
  }

  /**
   *
   * @param operation
   * @return a ArpOperation object.
   */
  public static ArpOperation register(ArpOperation operation) {
    return registry.put(operation.value(), operation);
  }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(ArpOperation o) {
    return value().compareTo(o.value());
  }

}