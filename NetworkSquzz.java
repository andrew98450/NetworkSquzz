import java.awt.EventQueue;
import java.awt.Font;
import java.awt.Rectangle;
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
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.table.DefaultTableModel;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.ArpPacket;
public class NetworkSquzz {
	boolean start = true;
	JComboBox<String> comboBox = new JComboBox<String>();
	DefaultComboBoxModel<String> def=new DefaultComboBoxModel<String>();
	DefaultTableModel deftable=new DefaultTableModel();
	private JFrame frmNetworksquzz;
	JScrollPane scrollPane = new JScrollPane();
	int count,count2;
	JLabel lblReceive = new JLabel("Receive:");
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
				count2 = count2 + 1;
			    if(arg0.contains(TcpPacket.class)){
				   TcpPacket tcp=arg0.get(TcpPacket.class);
				   TcpPacket.TcpHeader tcpheader=tcp.getHeader();
				   String[] row={String.valueOf(count2),"TCP",ipv4header.getSrcAddr().getHostAddress()+":"+tcpheader.getSrcPort().valueAsString()
						   ,ipv4header.getDstAddr().getHostAddress()+":"+tcpheader.getDstPort().valueAsString(),
						   bytesToHex(tcp.getRawData())};
				   deftable.addRow(row);
			    }else if(arg0.contains(UdpPacket.class)){
			    	UdpPacket udp=arg0.get(UdpPacket.class);
					UdpPacket.UdpHeader udpheader=udp.getHeader();
					String[] row={String.valueOf(count2),"UDP",ipv4header.getSrcAddr().getHostAddress()+":"+udpheader.getSrcPort().valueAsString()
							   ,ipv4header.getDstAddr().getHostAddress()+":"+udpheader.getDstPort().valueAsString(),
							   bytesToHex(udp.getRawData())};
				    deftable.addRow(row);
			    }else if(arg0.contains(ArpPacket.class)){
				    	ArpPacket arp=arg0.get(ArpPacket.class);
				        ArpPacket.ArpHeader arpheader=arp.getHeader();
				    	String[] row={String.valueOf(count2),"ARP",arpheader.getSrcHardwareAddr().toString()
								   ,arpheader.getDstHardwareAddr().toString(),
								   bytesToHex(arp.getRawData())};
					    deftable.addRow(row);
			    }else if(arg0.contains(EthernetPacket.class)){
			    	EthernetPacket eth=arg0.get(EthernetPacket.class);
			    	EthernetPacket.EthernetHeader ethheader=eth.getHeader();
			    	String[] row={String.valueOf(count2),"ETH",ethheader.getSrcAddr().toString()
						   ,ethheader.getDstAddr().toString(),
						   bytesToHex(eth.getRawData())};
				    deftable.addRow(row);
			    } 
			    int rowCount=table.getRowCount();
			    table.getSelectionModel().setSelectionInterval(rowCount-1,rowCount-1);
			    Rectangle rect=table.getCellRect(rowCount-1,0,true);
			    table.updateUI();
			    table.scrollRectToVisible(rect);
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
					lblReceive.setText("Receive: "+count);
					pcaphand.loop(10, packetget);
					count = count + 1;
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
    private JTable table;
	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmNetworksquzz = new JFrame();
		frmNetworksquzz.setTitle("NetworkSquzz");
		frmNetworksquzz.setBounds(100, 100, 1311, 704);
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
					th=new Thread(pcaps);
					th.start();
					start = false;
				}else{
					btnStart.setText("Start");
					th.interrupt();
					count = 0;
					start = true;
				}
			}
		});
		
		
		lblReceive.setFont(new Font("Arial", Font.PLAIN, 14));
		GroupLayout groupLayout = new GroupLayout(frmNetworksquzz.getContentPane());
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(scrollPane, GroupLayout.DEFAULT_SIZE, 1275, Short.MAX_VALUE)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(lblAdapter)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(comboBox, 0, 890, Short.MAX_VALUE)
							.addGap(18)
							.addComponent(btnReload, GroupLayout.PREFERRED_SIZE, 155, GroupLayout.PREFERRED_SIZE)
							.addGap(18)
							.addComponent(btnStart, GroupLayout.PREFERRED_SIZE, 136, GroupLayout.PREFERRED_SIZE))
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
						.addComponent(btnReload))
					.addPreferredGap(ComponentPlacement.RELATED, 19, Short.MAX_VALUE)
					.addComponent(lblReceive)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, 565, GroupLayout.PREFERRED_SIZE)
					.addContainerGap())
		);
		deftable.addColumn("No.");
		deftable.addColumn("Protocol");
		deftable.addColumn("Src");
		deftable.addColumn("Dst");
		deftable.addColumn("Data");
		table = new JTable();
		table.setModel(deftable);
		table.getColumnModel().getColumn(0).setPreferredWidth(10);
		table.getColumnModel().getColumn(1).setPreferredWidth(10);
		table.getColumnModel().getColumn(2).setPreferredWidth(50);
		table.getColumnModel().getColumn(3).setPreferredWidth(50);
		table.getColumnModel().getColumn(4).setPreferredWidth(400);
		table.setFillsViewportHeight(true);
		table.setSurrendersFocusOnKeystroke(true);
		table.setEnabled(false);
		scrollPane.setViewportView(table);
		frmNetworksquzz.getContentPane().setLayout(groupLayout);
	}
}
