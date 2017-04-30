import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle.ComponentPlacement;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.ArpPacket;
public class NetworkSquzz {
	boolean start = true;
	JComboBox<String> comboBox = new JComboBox<String>();
	DefaultComboBoxModel<String> def=new DefaultComboBoxModel<String>();
	private JFrame frmNetworksquzz;
	int count;
	JLabel lblReceive = new JLabel("Receive:");
	JTextArea textArea = new JTextArea();
	public static String bytesToHex(byte[] bytes) {
	    final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	PacketListener packetget=new PacketListener(){
		@Override
		public void gotPacket(Packet arg0) {
			// TODO Auto-generated method stub
			if(arg0 != null){
				IpV4Packet ipv4=arg0.get(IpV4Packet.class);
				IpV4Packet.IpV4Header ipv4header=ipv4.getHeader();
			    if(arg0.contains(TcpPacket.class)){
				   TcpPacket tcp=arg0.get(TcpPacket.class);
				   TcpPacket.TcpHeader tcpheader=tcp.getHeader();
				   textArea.append("TCP "+ipv4header.getSrcAddr().getHostAddress()+":"+tcpheader.getSrcPort().valueAsString()+
						   " -> "+ipv4header.getDstAddr().getHostAddress()+":"+tcpheader.getDstPort().valueAsString()+" Data: "+
						   bytesToHex(tcp.getRawData())+"\r\n");
			    }else if(arg0.contains(UdpPacket.class)){
			    	UdpPacket udp=arg0.get(UdpPacket.class);
					UdpPacket.UdpHeader udpheader=udp.getHeader();
					textArea.append("UDP "+ipv4header.getSrcAddr().getHostAddress()+":"+udpheader.getSrcPort().valueAsString()+
						   " -> "+ipv4header.getDstAddr().getHostAddress()+":"+udpheader.getDstPort().valueAsString()+" Data: "+
						   bytesToHex(udp.getRawData())+"\r\n");
			    }else if(arg0.contains(EthernetPacket.class)){
			    	EthernetPacket eth=arg0.get(EthernetPacket.class);
			    	EthernetPacket.EthernetHeader ethheader=eth.getHeader();
					textArea.append("ETH "+ethheader.getSrcAddr().toString()+
						   " -> "+ethheader.getDstAddr().toString()+" Data: "+
						   bytesToHex(eth.getRawData())+"\r\n");
			    }else if(arg0.contains(ArpPacket.class)){
			    	ArpPacket arp=arg0.get(ArpPacket.class);
			        ArpPacket.ArpHeader arpheader=arp.getHeader();
					textArea.append("ARP "+arpheader.getSrcProtocolAddr().getHostAddress()+":"+arpheader.getSrcHardwareAddr().toString()+
						   " -> "+arpheader.getDstProtocolAddr().getHostAddress()+":"+arpheader.getDstHardwareAddr().toString()+" Data: "+
						   bytesToHex(arp.getRawData())+"\r\n");
			    }
			}
		}
	};
    Runnable pcaps=new Runnable(){
		@Override
		public void run() {
			// TODO Auto-generated method stub
			while(start!=true){
				try{
					PcapNetworkInterface pcapnet=Pcaps.getDevByName(comboBox.getSelectedItem().toString());
					PcapHandle pcaphand=pcapnet.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 0);
					count = count + 1;
					lblReceive.setText("Receive: "+count);
					pcaphand.loop(10, packetget);
					Thread.sleep(100);
				}catch(Exception e){}
			}
		}
    };
    
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					NetworkSquzz window = new NetworkSquzz();
					window.frmNetworksquzz.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
    public void networkshow(){
       try{
    	  def.removeAllElements();
    	  List<PcapNetworkInterface> pcapnetwork=Pcaps.findAllDevs();
    	  for(int i=0;i<pcapnetwork.size();i++){
    		  def.addElement(pcapnetwork.get(i).getName());
    	  }
    	  comboBox.setModel(def);
       }catch(Exception e){}
    }
	/**
	 * Create the application.
	 */
	public NetworkSquzz() {
		initialize();
		networkshow();
	}
    Thread th;
	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmNetworksquzz = new JFrame();
		frmNetworksquzz.setTitle("NetworkSquzz");
		frmNetworksquzz.setBounds(100, 100, 1058, 704);
		frmNetworksquzz.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JLabel lblAdapter = new JLabel("Adapter:");
		lblAdapter.setFont(new Font("Arial", Font.PLAIN, 14));
		
		JButton btnReload = new JButton("Reload");
		btnReload.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				networkshow();
			}
		});
		
		JButton btnStart = new JButton("Start");
		btnStart.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(start == true){
					btnStart.setText("Stop");
					start = false;
					th=new Thread(pcaps);
					th.start();
				}else{
					btnStart.setText("Start");
					th.interrupt();
					count = 0;
					lblReceive.setText("Receive: ");
					start = true;
				}
			}
		});
		
		JScrollPane scrollPane = new JScrollPane();
		
		JButton btnClear = new JButton("Clear");
		btnClear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				textArea.setText("");
			}
		});
		
		lblReceive.setFont(new Font("Arial", Font.PLAIN, 14));
		GroupLayout groupLayout = new GroupLayout(frmNetworksquzz.getContentPane());
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(scrollPane, GroupLayout.DEFAULT_SIZE, 1022, Short.MAX_VALUE)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(lblAdapter)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(comboBox, GroupLayout.PREFERRED_SIZE, 675, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(btnReload, GroupLayout.PREFERRED_SIZE, 96, GroupLayout.PREFERRED_SIZE)
							.addGap(18)
							.addComponent(btnClear)
							.addGap(18)
							.addComponent(btnStart, GroupLayout.DEFAULT_SIZE, 94, Short.MAX_VALUE))
						.addComponent(lblReceive))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(21)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblAdapter)
						.addComponent(comboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(btnStart)
						.addComponent(btnReload)
						.addComponent(btnClear))
					.addPreferredGap(ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addComponent(lblReceive)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, 565, GroupLayout.PREFERRED_SIZE)
					.addContainerGap())
		);
		textArea.setEditable(false);
		textArea.setFont(new Font("Monospaced", Font.PLAIN, 16));
		
		scrollPane.setViewportView(textArea);
		frmNetworksquzz.getContentPane().setLayout(groupLayout);
	}
}
