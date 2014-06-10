Open vSwitch Extension for Hyper-V Vswitch
==============

**Brief description**

The following project defines a Hyper-V virtual switch forwarding extension, with the goal of providing the same set of tools available on Linux with a seamless
integration in the Hyper-V networking model, including fully interoperable GRE and VXLAN encapsulation.
--------------

**How to deploy manually**

Build the solution openvswitch\openvswitch.sln.

Copy over the generated openvswitch.cat, openvswitch.inf, openvswitch.sys.

Use the script found under Scripts\install.cmd to install the driver.

Remember to have testsigning enabled (http://msdn.microsoft.com/en-us/library/windows/hardware/ff553484%28v=vs.85%29.aspx).

Also to uninstall the driver use Scripts\uninstall.cmd.

Further documentation in how to setup an environment can be found under:
http://www.cloudbase.it/open-vswitch-on-hyper-v/

**Documentation for Hyper-V and NDIS that we recommend**
--------------

Excluding Packet Delivery to Extensible Switch Destination Ports: http://msdn.microsoft.com/en-us/library/windows/hardware/hh582255(v=vs.85).aspx

Managing the Hyper-V Extensible Switch Forwarding Context: http://msdn.microsoft.com/en-us/library/windows/hardware/hh582265(v=vs.85).aspx

**Datapath**

Packet Management Guidelines for the Extensible Switch Data Path: http://msdn.microsoft.com/en-us/library/windows/hardware/hh582270(v=vs.85).aspx

Packet Flow through the Extensible Switch Data Path: http://msdn.microsoft.com/en-us/library/windows/hardware/hh582269(v=vs.85).aspx

Forwarding Packets to Hyper-V Extensible Switch Ports: http://msdn.microsoft.com/en-us/library/windows/hardware/hh598152(v=vs.85).aspx

**Send and Receive Operations**

Cloning or Duplicating Packet Traffic: http://msdn.microsoft.com/en-us/library/windows/hardware/hh582254(v=vs.85).aspx

Forwarding Packets to Hyper-V Extensible Switch Ports: http://msdn.microsoft.com/en-us/library/windows/hardware/hh598152(v=vs.85).aspx

Originating Packet Traffic: http://msdn.microsoft.com/en-us/library/windows/hardware/hh598285(v=vs.85).aspx

**Ethernet Send and Receive Operations**

Sending Ethernet Frames: http://msdn.microsoft.com/en-us/library/windows/hardware/ff570756(v=vs.85).aspx

Indicating Received Ethernet Frames: http://msdn.microsoft.com/en-us/library/windows/hardware/ff554851(v=vs.85).aspx


Receiving Network Data: http://msdn.microsoft.com/en-us/library/windows/hardware/ff570452(v=vs.85).aspx

Retreat and Advance Operations: http://msdn.microsoft.com/en-us/library/windows/hardware/ff570696(v=vs.85).aspx

**NET_BUFFER_LIST STRUCTURE**

Fragmented NET_BUFFER_LIST Structures: http://msdn.microsoft.com/en-us/library/windows/hardware/ff550038(v=vs.85).aspx

**MDLs**

Using MDLs: http://msdn.microsoft.com/en-us/library/windows/hardware/ff565421(v=vs.85).aspx

**Filter Module Send and Receive Operations**

Filter Driver Buffer Management: http://msdn.microsoft.com/en-us/library/windows/hardware/ff549977(v=vs.85).aspx

Sending Data from a Filter Driver: http://msdn.microsoft.com/en-us/library/windows/hardware/ff570751(v=vs.85).aspx

Canceling a Send Request in a Filter Driver: http://msdn.microsoft.com/en-us/library/windows/hardware/ff544862(v=vs.85).aspx

Receiving Data in a Filter Driver: http://msdn.microsoft.com/en-us/library/windows/hardware/ff570448(v=vs.85).aspx

GSO (generic segmentation offload) -- LSO (Large segment offload): http://en.wikipedia.org/wiki/Generic_segmentation_offload

Offloading the Segmentation of Large TCP Packets: http://msdn.microsoft.com/en-us/library/windows/hardware/ff568840(v=vs.85).aspx

NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO structure: http://msdn.microsoft.com/en-us/library/windows/hardware/ff567882(v=vs.85).aspx

NDIS_NET_BUFFER_LIST_INFO enumeration: http://msdn.microsoft.com/en-us/library/windows/hardware/ff566569(v=vs.85).aspx

Accessing TCP/IP Offload NET_BUFFER_LIST Information: http://msdn.microsoft.com/en-us/library/windows/hardware/ff543696(v=vs.85).aspx

IP Helper Reference: http://msdn.microsoft.com/en-us/library/windows/hardware/ff557019(v=vs.85).aspx

IP Helper Functions: http://msdn.microsoft.com/en-us/library/windows/hardware/ff557018%28v=vs.85%29.aspx

Overview of Hyper-V Extensible Switch Network Adapters http://msdn.microsoft.com/en-us/library/windows/hardware/hh598286(v=vs.85).aspx

NICS AND PORT STATES Hyper-V Extensible Switch Port and Network Adapter States: http://msdn.microsoft.com/en-us/library/windows/hardware/hh598182%28v=vs.85%29.aspx