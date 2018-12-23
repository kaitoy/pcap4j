/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.constant;

/**
 * Key Exchange Algorithm Names
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-16
 *
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2KexAlgorithmName {

  private Ssh2KexAlgorithmName() {
    throw new AssertionError();
  }

  /** */
  public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1 =
      "diffie-hellman-group-exchange-sha1";

  /** */
  public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256 =
      "diffie-hellman-group-exchange-sha256";

  /** */
  public static final String DIFFIE_HELLMAN_GROUP1_SHA1 = "diffie-hellman-group1-sha1";

  /** */
  public static final String DIFFIE_HELLMAN_GROUP14_SHA1 = "diffie-hellman-group14-sha1";

  /** */
  public static final String ECDH_SHA2_PREFIX = "ecdh-sha2-";

  /** */
  public static final String ECMQV_SHA2 = "ecmqv-sha2";

  /** */
  public static final String GSS_GROUP1_SHA1_PREFIX = "gss-group1-sha1-";

  /** */
  public static final String GSS_GROUP14_SHA1_PREFIX = "gss-group14-sha1-";

  /** */
  public static final String GSS_GEX_SHA1_PREFIX = "gss-gex-sha1-";

  /** */
  public static final String GSS_PREFIX = "gss-";

  /** */
  public static final String RSA1024_SHA1 = "rsa1024-sha1";

  /** */
  public static final String RSA2048_SHA256 = "rsa2048-sha256";
}
