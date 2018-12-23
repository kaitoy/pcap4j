/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.List;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Supported Rates element
 *
 * <pre style="white-space: pre;">
 *       1         1          0-8
 * +----------+----------+-----------------
 * |Element ID|  Length  | Supported Rates
 * +----------+----------+-----------------
 * Element ID: 1
 * </pre>
 *
 * The Supported Rates element specifies up to eight rates in the OperationalRateSet parameter, as
 * described in the MLME-JOIN.request and MLME-START.request primitives, and zero or more BSS
 * membership selectors. The Information field is encoded as 1 to 8 octets, where each octet
 * describes a single Supported Rate or BSS membership selector. Within Beacon, Probe Response,
 * Association Response, Reassociation Response, Mesh Peering Open, and Mesh Peering Confirm
 * management frames, each Supported Rate contained in the BSSBasicRateSet parameter is encoded as
 * an octet with the MSB (bit 7) set to 1, and bits 6 to 0 are set to the data rate, if necessary
 * rounded up to the next 500kb/s, in units of 500 kb/s. Rates not contained in the BSSBasicRateSet
 * parameter are encoded with the MSB set to 0, and bits 6 to 0 are set to the appropriate value.
 * The MSB of each Supported Rate octet in other management frame types is ignored by receiving
 * STAs. Within Beacon, Probe Response, Association Response, Reassociation Response, Mesh Peering
 * Open, and Mesh Peering Confirm management frames, each BSS membership selector contained in the
 * BSSMembershipSelectorSet parameter is encoded as an octet with the MSB (bit 7) set to 1, and bits
 * 6 to 0 are set to the encoded value for the selector. A BSS membership selector that has the MSB
 * (bit 7) set to 1 in the Supported Rates element is defined to be basic.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11SupportedRatesElement extends Dot11AbstractSupportedRatesElement {

  /** */
  private static final long serialVersionUID = -27225920570715871L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11SupportedRatesElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11SupportedRatesElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11SupportedRatesElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11SupportedRatesElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.SUPPORTED_RATES);
  }

  /** @param builder builder */
  private Dot11SupportedRatesElement(Builder builder) {
    super(builder);
  }

  /** @return a new Builder object populated with this object's fields. */
  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String getElementName() {
    return "Supported Rates";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11AbstractSupportedRatesElement.Builder {

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(Dot11InformationElementId.SUPPORTED_RATES.value()));
    }

    /** @param elem a Dot11SupportedRatesElement object. */
    private Builder(Dot11SupportedRatesElement elem) {
      super(elem);
    }

    /**
     * @param ratesAndBssMembershipSelectors ratesAndBssMembershipSelectors
     * @return this Builder object for method chaining.
     */
    @Override
    public Builder ratesAndBssMembershipSelectors(List<Datum> ratesAndBssMembershipSelectors) {
      super.ratesAndBssMembershipSelectors(ratesAndBssMembershipSelectors);
      return this;
    }

    @Override
    public Builder length(byte length) {
      super.length(length);
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      super.correctLengthAtBuild(correctLengthAtBuild);
      return this;
    }

    @Override
    public Dot11SupportedRatesElement build() {
      preBuild();
      return new Dot11SupportedRatesElement(this);
    }
  }
}
