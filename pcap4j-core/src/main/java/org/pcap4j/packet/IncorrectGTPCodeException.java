package org.pcap4j.packet;

/**
* @author waveform
*/

public class IncorrectGTPCodeException extends Exception
{
	
	public IncorrectGTPCodeException()
	{
		super();
	}
	public IncorrectGTPCodeException(String message)
	{
		super(message);
	}
	public IncorrectGTPCodeException(String message , Throwable cause)
	{
		super(message,cause);
	}
	public IncorrectGTPCodeException(Throwable cause)
	{
		super(cause);
	}
}
