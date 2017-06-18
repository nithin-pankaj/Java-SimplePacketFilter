package core;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
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
        
        int i = 0;  
        for (PcapIf device : nicDevices) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
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
         * 
         */
        
        PcapBpfProgram program = new PcapBpfProgram(); 
        String expression = "tcp port http"; 
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
        
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            final Ip4 ip = new Ip4();
            Tcp tcp = new Tcp();
            public void nextPacket(PcapPacket packet, String user) {
            	try {
					Thread.sleep(2000); // Setting a delay of 2 seconds
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            	//Inspecting the packet headers
                if(packet.hasHeader(Ip4.ID) && packet.hasHeader(Tcp.ID) ){
                    packet.getHeader(ip);
                    byte[] dIP = new byte[4], sIP = new byte[4];
                    dIP = packet.getHeader(ip).destination();
                    sIP = packet.getHeader(ip).source();
                    String tcpSrc = "" + packet.getHeader(tcp).destination();//Get the source port
                    String tcpDest = "" + packet.getHeader(tcp).destination();//Get the destination port
                    String sourceIP = FormatUtils.ip(sIP);
                    String destinationIP = FormatUtils.ip(dIP);

                    System.out.printf("tcp.ip_src=%s%n",sourceIP);
                    System.out.printf("tcp.ip_dest=%s%n",destinationIP);
                    System.out.printf("tcp.ip_src_port=%s%n",tcpSrc);
                    System.out.printf("tcp.ip_dest_port=%s%n",tcpDest);
                    System.out.println("-------------------------------------");
                }

            }
        }; 
        
        /*
         * 
         * Calling the packet reading loop
         * This loop is configured to collect 10 packets (can be changed)
         * 
         */
        
          pcap.loop(20, jpacketHandler, "");
          
          /* Done, and closing the pcap object */
          pcap.close(); 
	}

}
