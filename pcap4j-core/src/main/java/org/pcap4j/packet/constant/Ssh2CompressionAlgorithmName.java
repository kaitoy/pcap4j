/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.constant;

/**
 * Compression Algorithm Name
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-20
 *
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2CompressionAlgorithmName {

  private Ssh2CompressionAlgorithmName() {
    throw new AssertionError();
  }

  /** */
  public static final String NONE = "none";

  /** */
  public static final String ZLIB = "zlib";
}
