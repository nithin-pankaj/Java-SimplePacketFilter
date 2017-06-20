package core;

import java.util.ArrayList;
import java.util.List;


import org.jnetpcap.Pcap; //libcap
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

public class JnetPcapFirewall {
	
	public static void main(String[] args) { 
		
		List<PcapIf> nicDevices = new ArrayList<PcapIf>(); // List for collecting Device Network Interfaces 
        StringBuilder genericErrBuffer = new StringBuilder(); // For Capturing Generic Error Messages
        
        /* Collecting the list of Network Devices in the system */
        int r = Pcap.findAllDevs(nicDevices, genericErrBuffer);  
        if (r == Pcap.NOT_OK || nicDevices.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", genericErrBuffer  
                .toString());  
            return;  
        }
        /* Fetching completed */
        
        /* Displaying the devices */
        System.out.println("Network devices:");  
        
        int devices = 0;  
        for (PcapIf device : nicDevices) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", devices++, device.getName(), description);  
        } 
        
		/*
		 * 
		 * At this point we have atleast one device in 'nicDevices' array
		 * Selecting a default device to inspect packets
		 * Selecting the second device, since this one is my default NIC (Choose whichever is appropriate for you)
		 * 
		 */
		
        PcapIf device = nicDevices.get(1);
        
        System.out  
        .printf("\nSelected '%s' NIC as default device:\n",  
            (device.getDescription() != null) ? device.getDescription()  
                : device.getName()); 
        
        /*
         * 
         * Opening the selected device to listen for Packets
         * 
         */
        
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        Pcap pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, genericErrBuffer);  
        
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + genericErrBuffer.toString());  
            return;  
        }
        
        /*
         * 
         * Following block ('PcapBpfProgram') is used to set a filter for packet listening
         * you can use a configuration file to read out the filtering expression
         * By default i'm only allowing https connections and filtering out all other packets (non-https)
         * plus, i have commented certain filters. If you want to test any other filters, uncomment that expression and comment out others
         */
        
        PcapBpfProgram program = new PcapBpfProgram(); 
        //String expression = "src host not 10.206.157.24"; //Filter based on source ip address
        //String expression = "dst host not 10.206.157.24"; //Filter based on dest ip address
        //String expression = "ip proto tcp"; //based on protocol
        //String expression = "tcp port 443"; // port based
        String expression = "tcp port https"; // Only allow http packets
        //String expression = "tcp port http"; // Only allow http packets
        //String expression = "host 10.206.157.24"; // Only allow packets arriving from SAP servers 10.206.159.155
        //String expression = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"; //Allow packets taht contain data
        int optimize = 0;         // 0 = false 
        int netmask = 0xFFFFFF00; // 255.255.255.0 
         
        if (pcap.compile(program, expression, optimize, netmask) != Pcap.OK) { 
         System.err.println(pcap.getErr()); 
         return; 
        } 
         
        if (pcap.setFilter(program) != Pcap.OK) { 
         System.err.println(pcap.getErr()); 
         return;   
        } 
         
        System.out.println("Current Filter : " + expression + "\n");
        
        /* Applied Filter! */
        
        /*
         * 
         * Following block is a packet handler function
         * We are using the libcap fucntion to receive and read packets
         * 
         */
        //we can also use PcapPacketHandler
        pcap.loop(20, new JPacketHandler<StringBuilder>() { 
        	   final Ip4 ip = new Ip4();
        	   final Tcp tcp = new Tcp(); 
        	   Icmp icmp = new Icmp(); // Need an instance so we can check on sub header 
        	   Icmp.DestinationUnreachable unreach = new Icmp.DestinationUnreachable(); 
        	 
        	   /*
        	    * Same thing for our http header 
        	    */ 
        	   final Http http = new Http(); 

        	   public void nextPacket(JPacket packet, StringBuilder errbuf) { 
        		
        		try {
					Thread.sleep(3000); //Adding a delay of 3 secs
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
        		
        		if (packet.hasHeader(ip)){
        			byte[] dIP = new byte[4], sIP = new byte[4];
        			packet.getHeader(ip); 
        			dIP = packet.getHeader(ip).destination();
                    sIP = packet.getHeader(ip).source();
                    String sourceIP = FormatUtils.ip(sIP);
                    String destinationIP = FormatUtils.ip(dIP);
                    System.out.printf("Source IP=%s%n",sourceIP);
                    System.out.printf("Destination Ip=%s%n",destinationIP);
        		}
        		 

        	    if (packet.hasHeader(tcp)) { 
        	    	 byte[] dIP = new byte[4], sIP = new byte[4];
            	     packet.getHeader(tcp); 
            	     dIP = packet.getHeader(ip).destination();
                     sIP = packet.getHeader(ip).source();
                     String sourceIP = FormatUtils.ip(sIP);
                     String destinationIP = FormatUtils.ip(dIP);
                     System.out.printf("tcp.ip_src=%s%n",sourceIP);
                     System.out.printf("tcp.ip_dest=%s%n",destinationIP);
            	     System.out.printf("tcp:destination port=%d%n", tcp.destination()); 
            	     System.out.printf("tcp.source port=%d%n", tcp.source()); 
            	     System.out.printf("tcp.acknowledgement=%x%n", tcp.ack()); 	
        	     System.out.printf("tcp header::%s%n", tcp.toString()); 
        	    } 

        	    if (packet.hasHeader(tcp) && packet.hasHeader(http)) { 

        	 
        	     System.out.printf("http header::%s%n", http); 

        	 
        	    } 
        	    
        	    if (packet.hasHeader(icmp) && icmp.hasSubHeader(unreach)) { 
        	    	 
        	    	   System.out.printf("type=%d, code=%d, crc=0x%x reserved=%d\n", 
        	    	       icmp.type(), icmp.code(), icmp.checksum(), unreach.reserved()); 
        	    } 
        	 
        	    System.out.printf("frame #%d%n", packet.getFrameNumber()); 
        	   } 
        	 
        	  }, genericErrBuffer); 
       
	}

}
