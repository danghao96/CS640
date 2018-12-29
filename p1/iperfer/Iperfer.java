import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

public class Iperfer {

	/*
	*  The client mode for Iperfer
	*  Params: (String) hostname, (int) port number, (long) time in second
	*  Return: void
	*/
	public static void clientMode(String h, int p, long t) {
        String dataBlock ="0";
        for(int i = 0; i < 999; i++){
        	dataBlock += '0';
        }
        try (
                Socket echoSocket = new Socket(h, p);
                PrintWriter out =
                    new PrintWriter(echoSocket.getOutputStream(), true);
            ) {
                long startTime = System.currentTimeMillis();
                long elapsedTime = 0L;
                int count = 0;
                while (elapsedTime < t * 1000) {
                    out.println(dataBlock);
                    count++;
                    elapsedTime = System.currentTimeMillis() - startTime;
                }
                double rate = (count * 8) / 1000.0 / t;
                System.out.println("sent=" + count + " KB rate=" + rate + " Mbps");
            } catch (UnknownHostException e) {
                System.err.println("Don't know about host " + h);
                System.exit(1);
            } catch (IOException e) {
                System.err.println("Couldn't get I/O for the connection to " + h);
                System.exit(1);
            }
	}
	
	/*
	*  The server mode for Iperfer
	*  Params: (int) port number
	*  Return: void
	*/
	public static void serverMode(int p) {
        try (
            ServerSocket serverSocket = new ServerSocket(p);
            Socket clientSocket = serverSocket.accept();                   
            BufferedReader in = new BufferedReader(
                new InputStreamReader(clientSocket.getInputStream()));
        ) {
            String inputLine;
            int count = 0;
            long startTime = 0;
            long elapsedTime = 0;
            while ((inputLine = in.readLine()) != null) {
            	if(count == 0){
            		startTime = System.currentTimeMillis();
            	}
            	count++;
                elapsedTime = System.currentTimeMillis() - startTime;
            }
            double rate = (count * 8) / 1000.0 / (elapsedTime / 1000.0);
            System.out.println("received=" + count + " KB rate=" + rate + " Mbps");
            
        } catch (IOException e) {
            System.out.println("Exception caught when trying to listen on port "
                + p + " or listening for a connection");
            System.out.println(e.getMessage());
        }
	}
	
	public static void main(String[] args) {
		// Makesure there is at least one argument that indicate the mode
		if(args.length <= 0){
			System.out.println("Error: missing or additional arguments");
			System.exit(1);
		}

		if(args[0].equals("-c")) {
			// Validate the argument for client mode
			if(args.length != 7) {
				System.out.println("Error: missing or additional arguments");
				System.exit(1);
			}
			if(!args[1].equals("-h") || !args[3].equals("-p") || !args[5].equals("-t")) {
				System.out.println("Error: missing or additional arguments");
				System.exit(1);
			}

			String hostname = null;
			int port = 0;
			long time = 0;
			
			try {
				hostname = args[2];
				port = Integer.parseInt(args[4]);
				time = Integer.parseInt(args[6]);
			} catch (NumberFormatException e) {
				System.out.println("Error: invalie argument value");
				System.exit(1);
			}
			if(!hostname.contains(".")){
				System.out.println("Error: hostname must be valid hostname or IP address");
				System.exit(1);
			}
			if(port < 1024 || port > 65535) {
				System.out.println("Error: port number must be in the range 1024 to 65535");
				System.exit(1);
			}
			if(time <= 0){
				System.out.println("Error: time must be greater then 0");
				System.exit(1);
			}

			// call clientMode to run in client mode
			clientMode(hostname, port, time);
		}
		else if(args[0].equals("-s")) {
			// Validate the argument for server mode
			if(args.length != 3) {
				System.out.println("Error: missing or additional arguments");
				System.exit(1);
			}
			if(!args[1].equals("-p")) {
				System.out.println("Error: missing or additional arguments");
				System.exit(1);
			}
			
			int port = 0;
			try {
				port = Integer.parseInt(args[2]);
			} catch (NumberFormatException e) {
				System.out.println("Error: integer value expected in port value");
				System.exit(1);
			}
			if(port < 1024 || port > 65535) {
				System.out.println("Error: port number must be in the range 1024 to 65535");
				System.exit(1);
			}
			
			// call clientMode to run in client mode
			serverMode(port);
		} else {
			// if the first flag is neither -s nor -c, report error and exit
			System.out.println("Error: the Iperfer must run with either -s or -c flag");
			System.exit(1);
		}
	}
}
