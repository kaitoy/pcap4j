package org.pcap4j.packet;

/**
* @author waveform
*/

public class IncorrectMSGTypeException extends Exception
{
	
	public IncorrectMSGTypeException()
	{
		super();
	}
	public IncorrectMSGTypeException(String message)
	{
		super(message);
	}
	public IncorrectMSGTypeException(String message , Throwable cause)
	{
		super(message,cause);
	}
	public IncorrectMSGTypeException(Throwable cause)
	{
		super(cause);
	}
}
