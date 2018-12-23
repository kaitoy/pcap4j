/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.Dot11BssMembershipSelector;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;

/**
 * IEEE802.11 abstract Supported Rates element
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public abstract class Dot11AbstractSupportedRatesElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = -1751480012950433980L;

  private final List<Rate> rates;
  private final List<BssMembershipSelector> bssMembershipSelectors;
  private final List<Datum> ratesAndBssMembershipSelectors;

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param id id
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  protected Dot11AbstractSupportedRatesElement(
      byte[] rawData, int offset, int length, Dot11InformationElementId id)
      throws IllegalRawDataException {
    super(rawData, offset, length, id);

    this.rates = new ArrayList<Rate>();
    this.bssMembershipSelectors = new ArrayList<BssMembershipSelector>();
    this.ratesAndBssMembershipSelectors = new ArrayList<Datum>();
    int infoLen = getLengthAsInt();
    for (int i = 0; i < infoLen; i++) {
      byte next = rawData[offset + 2 + i];
      boolean basic = (next & 0x80) != 0;
      byte val = (byte) (next & 0x7F);
      if (Dot11BssMembershipSelector.isRegistered(val)) {
        BssMembershipSelector sel =
            new BssMembershipSelector(basic, Dot11BssMembershipSelector.getInstance(val));
        bssMembershipSelectors.add(sel);
        ratesAndBssMembershipSelectors.add(sel);
      } else {
        Rate rate = new Rate(basic, val);
        rates.add(rate);
        ratesAndBssMembershipSelectors.add(rate);
      }
    }
  }

  /** @param builder builder */
  protected Dot11AbstractSupportedRatesElement(Builder builder) {
    super(builder);

    if (builder.ratesAndBssMembershipSelectors.size() > 255) {
      throw new IllegalArgumentException(
          "Too long ratesAndBssMembershipSelectors: " + builder.ratesAndBssMembershipSelectors);
    }

    this.rates = new ArrayList<Rate>();
    this.bssMembershipSelectors = new ArrayList<BssMembershipSelector>();
    for (Datum obj : builder.ratesAndBssMembershipSelectors) {
      if (obj instanceof Rate) {
        rates.add((Rate) obj);
      } else if (obj instanceof BssMembershipSelector) {
        bssMembershipSelectors.add((BssMembershipSelector) obj);
      } else {
        throw new IllegalArgumentException(
            "An illegal object in builder.ratesAndBssMembershipSelectors: " + obj);
      }
    }
    this.ratesAndBssMembershipSelectors =
        new ArrayList<Datum>(builder.ratesAndBssMembershipSelectors);
  }

  /** @return rates */
  public List<Rate> getRates() {
    return new ArrayList<Rate>(rates);
  }

  /** @return bssMembershipSelectors */
  public List<BssMembershipSelector> getBssMembershipSelectors() {
    return new ArrayList<BssMembershipSelector>(bssMembershipSelectors);
  }

  @Override
  public int length() {
    return 2 + ratesAndBssMembershipSelectors.size();
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    int i = 2;
    for (Datum datum : ratesAndBssMembershipSelectors) {
      rawData[i] = datum.getRawData();
      i++;
    }
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public abstract Builder getBuilder();

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + ratesAndBssMembershipSelectors.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11AbstractSupportedRatesElement other = (Dot11AbstractSupportedRatesElement) obj;
    if (!ratesAndBssMembershipSelectors.equals(other.ratesAndBssMembershipSelectors)) return false;
    return true;
  }

  @Override
  public String toString() {
    return toString("");
  }

  /**
   * @param indent indent
   * @return the string representation of this object.
   */
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent).append(getElementName()).append(":").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    for (Datum datum : ratesAndBssMembershipSelectors) {
      sb.append(indent).append("  ").append(datum).append(ls);
    }

    return sb.toString();
  }

  /** @return element name */
  protected abstract String getElementName();

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public interface Datum extends Serializable {

    /** @return the raw data. */
    public byte getRawData();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Rate implements Datum {

    /** */
    private static final long serialVersionUID = -3227287901080960330L;

    private final boolean basic;
    private final byte rate;

    /**
     * @param basic basic
     * @param rate rate
     */
    public Rate(boolean basic, byte rate) {
      if (rate < 0) {
        throw new IllegalArgumentException(
            "The rate must be between 0 to 127 but is actually: " + rate);
      }
      this.basic = basic;
      this.rate = rate;
    }

    /** @return true if this is a basic rate; false otherwise. */
    public boolean isBasic() {
      return basic;
    }

    /** @return rate */
    public byte getRate() {
      return rate;
    }

    /** @return rate in Mbit/sec. */
    public double getRateInMbitPerSec() {
      return rate * 0.5;
    }

    @Override
    public byte getRawData() {
      return (byte) (basic ? (0x80 | rate) : rate);
    }

    @Override
    public String toString() {
      StringBuilder sb =
          new StringBuilder(50)
              .append("Supported Rate: ")
              .append(getRateInMbitPerSec())
              .append(" Mbit/sec")
              .append(basic ? " (basic)" : " (non-basic)");
      return sb.toString();
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + (basic ? 1231 : 1237);
      result = prime * result + rate;
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (getClass() != obj.getClass()) return false;
      Rate other = (Rate) obj;
      if (basic != other.basic) return false;
      if (rate != other.rate) return false;
      return true;
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class BssMembershipSelector implements Datum {

    /** */
    private static final long serialVersionUID = 5749787247631286263L;

    private final boolean basic;
    private final Dot11BssMembershipSelector selector;

    /**
     * @param basic basic
     * @param selector selector
     */
    public BssMembershipSelector(boolean basic, Dot11BssMembershipSelector selector) {
      if (selector == null) {
        throw new NullPointerException("selector is null.");
      }
      this.basic = basic;
      this.selector = selector;
    }

    /** @return true if this is a basic rate; false otherwise. */
    public boolean isBasic() {
      return basic;
    }

    /** @return selector */
    public Dot11BssMembershipSelector getSelector() {
      return selector;
    }

    @Override
    public byte getRawData() {
      byte sel = selector.value();
      return (byte) (basic ? (0x80 | sel) : sel);
    }

    @Override
    public String toString() {
      StringBuilder sb =
          new StringBuilder(50)
              .append("BSS Membership Selector: ")
              .append(selector)
              .append(basic ? " (basic)" : " (non-basic)");
      return sb.toString();
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + (basic ? 1231 : 1237);
      result = prime * result + selector.hashCode();
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (getClass() != obj.getClass()) return false;
      BssMembershipSelector other = (BssMembershipSelector) obj;
      if (basic != other.basic) return false;
      if (!selector.equals(other.selector)) return false;
      return true;
    }
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public abstract static class Builder extends Dot11InformationElement.Builder {

    private List<Datum> ratesAndBssMembershipSelectors;

    /** */
    public Builder() {}

    /** @param elem element. */
    protected Builder(Dot11AbstractSupportedRatesElement elem) {
      super(elem);
      this.ratesAndBssMembershipSelectors = elem.ratesAndBssMembershipSelectors;
    }

    /**
     * @param ratesAndBssMembershipSelectors ratesAndBssMembershipSelectors
     * @return this Builder object for method chaining.
     */
    public Builder ratesAndBssMembershipSelectors(List<Datum> ratesAndBssMembershipSelectors) {
      this.ratesAndBssMembershipSelectors = ratesAndBssMembershipSelectors;
      return this;
    }

    /** Call me before build(). */
    protected void preBuild() {
      if (ratesAndBssMembershipSelectors == null) {
        throw new NullPointerException("ratesAndBssMembershipSelectors is null.");
      }
      if (getCorrectLengthAtBuild()) {
        length((byte) ratesAndBssMembershipSelectors.size());
      }
    }
  }
}
