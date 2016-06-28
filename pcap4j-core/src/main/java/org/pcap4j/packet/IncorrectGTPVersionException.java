package org.pcap4j.packet;

/**
* @author waveform
*/

public class IncorrectGTPVersionException extends Exception
{
	
	public IncorrectGTPVersionException()
	{
		super();
	}
	public IncorrectGTPVersionException(String message)
	{
		super(message);
	}
	public IncorrectGTPVersionException(String message , Throwable cause)
	{
		super(message,cause);
	}
	public IncorrectGTPVersionException(Throwable cause)
	{
		super(cause);
	}
}
