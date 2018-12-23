/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public enum RadiotapFecType {

  /** BCC */
  BCC(0),

  /** LDPC */
  LDPC(1);

  private final int value;

  private RadiotapFecType(int value) {
    this.value = value;
  }

  /** @return value */
  public int getValue() {
    return value;
  }
}
