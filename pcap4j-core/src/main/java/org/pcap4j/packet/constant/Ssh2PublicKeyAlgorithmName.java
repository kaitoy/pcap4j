/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.constant;

/**
 * Public Key Algorithm Name
 * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19
 *
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2PublicKeyAlgorithmName {

  private Ssh2PublicKeyAlgorithmName() {
    throw new AssertionError();
  }

  /** */
  public static final String SSH_DSS = "ssh-dss";

  /** */
  public static final String SSH_RSA = "ssh-rsa";

  /** */
  public static final String SPKI_SIGN_RSA = "spki-sign-rsa";

  /** */
  public static final String SPKI_SIGN_DSS = "spki-sign-dss";

  /** */
  public static final String PGP_SIGN_RSA = "pgp-sign-rsa";

  /** */
  public static final String PGP_SIGN_DSS = "pgp-sign-dss";

  /** */
  public static final String NULL = "null";

  /** */
  public static final String ECDSA_SHA2_PREFIX = "ecdsa-sha2-";

  /** */
  public static final String X509V3_SSH_DSS = "x509v3-ssh-dss";

  /** */
  public static final String X509V3_SSH_RSA = "x509v3-ssh-rsa";

  /** */
  public static final String X509V3_RSA2048_SHA256 = "x509v3-rsa2048-sha256";

  /** */
  public static final String X509V3_ECDSA_SHA2_PREFIX = "x509v3-ecdsa-sha2-";
}
