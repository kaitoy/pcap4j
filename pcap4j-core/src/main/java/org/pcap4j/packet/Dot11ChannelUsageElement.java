/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.packet.namednumber.Dot11ChannelUsageMode;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Channel Usage element
 *
 * <pre style="white-space: pre;">
 *       1         1           1           2n
 * +----------+----------+----------+---------------
 * |Element ID|  Length  |Usage Mode|Channel Entry
 * +----------+----------+----------+---------------
 * Element ID: 97
 * </pre>
 *
 * The Channel Usage element defines the channel usage information for noninfrastructure networks or
 * an off channel TDLS direct link.
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11ChannelUsageElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = -6935079967608347323L;

  private final Dot11ChannelUsageMode usageMode;
  private final List<Dot11ChannelEntry> channelEntries;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11ChannelUsageElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11ChannelUsageElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11ChannelUsageElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11ChannelUsageElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.CHANNEL_USAGE);

    int infoLen = getLengthAsInt();
    if (infoLen < 1) {
      throw new IllegalRawDataException(
          "The length must be more than 0 but is actually: " + infoLen);
    }
    if (((infoLen - 1) % 2) != 0) {
      throw new IllegalRawDataException("The ((length - 1) % 2) must be 0. length: " + infoLen);
    }

    this.usageMode = Dot11ChannelUsageMode.getInstance(rawData[offset + 2]);
    infoLen--;

    this.channelEntries = new ArrayList<Dot11ChannelEntry>((infoLen - 1) / 2);
    for (int i = offset + 3; infoLen > 0; infoLen -= 2, i += 2) {
      channelEntries.add(new Dot11ChannelEntry(rawData[i], rawData[i + 1]));
    }
  }

  /** @param builder builder */
  private Dot11ChannelUsageElement(Builder builder) {
    super(builder);

    if (builder.channelEntries.size() > 127) {
      throw new IllegalArgumentException("Too long channelEntries: " + builder.channelEntries);
    }

    this.usageMode = builder.usageMode;
    if (builder.channelEntries == null) {
      this.channelEntries = Collections.emptyList();
    } else {
      this.channelEntries = new ArrayList<Dot11ChannelEntry>(builder.channelEntries);
    }
  }

  /** @return usageMode */
  public Dot11ChannelUsageMode getUsageMode() {
    return usageMode;
  }

  /** @return channelEntries */
  public ArrayList<Dot11ChannelEntry> getChannelEntries() {
    return new ArrayList<Dot11ChannelEntry>(channelEntries);
  }

  @Override
  public int length() {
    return 3 + channelEntries.size() * 2;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    rawData[2] = usageMode.value();

    Iterator<Dot11ChannelEntry> iter = channelEntries.iterator();
    for (int i = 3; iter.hasNext(); i += 2) {
      Dot11ChannelEntry next = iter.next();
      rawData[i] = next.getOperatingClass();
      rawData[i + 1] = next.getChannel();
    }

    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + channelEntries.hashCode();
    result = prime * result + usageMode.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11ChannelUsageElement other = (Dot11ChannelUsageElement) obj;
    if (!channelEntries.equals(other.channelEntries)) return false;
    if (!usageMode.equals(other.usageMode)) return false;
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

    sb.append(indent).append("Channel Usage:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    sb.append(indent).append("  Usage Mode: ").append(usageMode).append(ls);
    for (Dot11ChannelEntry ce : channelEntries) {
      sb.append(indent).append("  Channel Entry: ").append(ce).append(ls);
    }

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private Dot11ChannelUsageMode usageMode;
    private List<Dot11ChannelEntry> channelEntries;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(Dot11InformationElementId.CHANNEL_USAGE.value()));
    }

    /** @param elem a Dot11ChannelUsageElement object. */
    private Builder(Dot11ChannelUsageElement elem) {
      super(elem);
      this.usageMode = elem.usageMode;
      this.channelEntries = elem.channelEntries;
    }

    /**
     * @param usageMode usageMode
     * @return this Builder object for method chaining.
     */
    public Builder usageMode(Dot11ChannelUsageMode usageMode) {
      this.usageMode = usageMode;
      return this;
    }

    /**
     * @param channelEntries channelEntries
     * @return this Builder object for method chaining.
     */
    public Builder channelEntries(List<Dot11ChannelEntry> channelEntries) {
      this.channelEntries = channelEntries;
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
    public Dot11ChannelUsageElement build() {
      if (usageMode == null) {
        throw new NullPointerException("usageMode is null.");
      }
      if (getCorrectLengthAtBuild()) {
        length((byte) (channelEntries.size() * 2 + 1));
      }
      return new Dot11ChannelUsageElement(this);
    }
  }
}
