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
 * IEEE802.11 Extended Supported Rates element
 *
 * <pre style="white-space: pre;">
 *       1         1               1-255
 * +----------+----------+-------------------------
 * |Element ID|  Length  | Extended Supported Rates
 * +----------+----------+-------------------------
 * Element ID: 50
 * </pre>
 *
 * The Extended Supported Rates element specifies the rates in the OperationalRateSet parameter and
 * zero or more BSS membership selector values that are not carried in the Supported Rates element.
 * The Information field is encoded as 1 to 255 octets where each octet describes a single supported
 * rate or BSS membership selector. Within Beacon, Probe Response, Association Response,
 * Reassociation Response, Mesh Peering Open, and Mesh Peering Confirm management frames, each
 * supported rate contained in the BSSBasicRateSet parameter is encoded as an octet with the MSB
 * (bit 7) set to 1 and bits 6 to 0 are set to the appropriate value. Rates not contained in the
 * BSSBasicRateSet parameter are encoded with the MSB set to 0, and bits 6 to 0 are set to the
 * appropriate value from the valid range. The MSB of each octet in the Extended Supported Rate
 * element in other management frame types is ignored by receiving STAs. Within Beacon, Probe
 * Response, Association Response, Reassociation Response, Mesh Peering Open, and Mesh Peering
 * Confirm management frames, each BSS membership selector contained in the BSSMembershipSelectorSet
 * parameter is encoded as an octet with the MSB (bit 7) set to 1, and bits 6 to 0 are set to the
 * encoded value for the selector.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11ExtendedSupportedRatesElement extends Dot11AbstractSupportedRatesElement {

  /** */
  private static final long serialVersionUID = 8779245835470631343L;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11ExtendedSupportedRatesElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11ExtendedSupportedRatesElement newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11ExtendedSupportedRatesElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11ExtendedSupportedRatesElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.EXTENDED_SUPPORTED_RATES);
  }

  /** @param builder builder */
  private Dot11ExtendedSupportedRatesElement(Builder builder) {
    super(builder);
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public String getElementName() {
    return "Extended Supported Rates";
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11AbstractSupportedRatesElement.Builder {

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(
              Dot11InformationElementId.EXTENDED_SUPPORTED_RATES.value()));
    }

    /** @param elem a Dot11ExtendedSupportedRatesElement object. */
    private Builder(Dot11ExtendedSupportedRatesElement elem) {
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
    public Dot11ExtendedSupportedRatesElement build() {
      preBuild();
      return new Dot11ExtendedSupportedRatesElement(this);
    }
  }
}
