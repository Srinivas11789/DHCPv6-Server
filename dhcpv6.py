############# Module Imports 

from socket import *
import struct
import re
############# Raw Socket Creation for IPV6
ETH_P_ALL=0x0003
s=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))

############# Extreme Socket Options

try:                           
    f = open('/proc/self/ns_id', 'w')
    f.write('2\n')                   
    f.close()                        
except:                              
    s.setsockopt(SOL_SOCKET, EXTREME_SO_VRID, 2)
	
############# Server Binding to Socket

s.bind(("v2_F424E", 0))

############# Packet Constrcutors for Headers, ICMP and DHCP - Packing Data

def string_pack(str_pack = []):
      out_pack = ""
      for i in str_pack:
          i = bytes(i)
          i = struct.pack('!B',int(i,16))
          out_pack = out_pack + i
      return out_pack

############# Packet Receiver

while 1:
      data, addr = s.recvfrom(65535)
      payload = []
      for i in list(data):
	        i= i.encode("hex")
                payload.append(i)
      print payload
      
############# Router Solicit Handle - Only Receive and Decode
      
      if (payload[0] + payload[1]) == "3333":
	          print "Ip Multicast Packet Received"
	          if payload[24] == "3a":
                      print "ICMP for IPv6 Received"
                      if payload[58] == "85":
                                      print "Router Solicit Received"
                                      Destination_Mac = payload[0]+payload[1]+payload[2]+payload[3]+payload[4]+payload[5]
                                      Source_Mac = payload[6]+payload[7]+payload[8]+payload[9]+payload[10]+payload[11]
                                      Source_Ip = payload[25]
                                      for n in range(26,42):
                                                      Source_Ip = Source_Ip+payload[n]
                                      Destination_Ip = payload[42]
                                      for n in range(43,58):
                                                     Destination_Ip = Destination_Ip+payload[n]
                                      link_layer = payload[68]
                                      for n in range(69,74):
                                                     link_layer = link_layer+payload[n]
                                      print "-> Source IP - %s" % (Source_Ip)
                                      print "-> Destin IP - %s" % (Destination_Ip)
                                      print "-> Source MAC - %s" % (Source_Mac)
                                      print "-> Destin MAC - %s" % (Destination_Mac)
                                      print "-> LinkLayer - %s" % (link_layer)
                                      
############# Router Advertisement Contructor and Sender - ICMPv6
                                      ### Headers Contruct
                                      version = "6"
                                      payload_len = 64 
                                      hop =  255
                                      icmp_type = 58
                                      mymac_pack = s.getsockname()[4]
                                      mymac =  s.getsockname()[4].encode("hex")
                                      m = re.findall('..',mymac)
                                      linklocal = re.findall('..',"fe80000000000000020496fffe"+mymac[6:8]+mymac[8:11]+mymac[11:13])
                                      ra_dest_packed = re.findall('..',"ff020000000000000000000000000001")
                                      ether_head = struct.pack('!BBBBBB',int(bytes(payload[0]),16),int(bytes(payload[1]),16),int(bytes(payload[2]),16),int(bytes(payload[3]),16),int(bytes(payload[4]),16),int(bytes("01"),16))+string_pack(m)+data[16]+data[17]
                                      print ether_head
                                      #ip_header = struct.pack('<Q',version)+struct.pack('!B',payload_len)+struct.pack('!BB',icmp_type,hop)+string_pack(linklocal)+string_pack(ra_dest_packed)
                                      ip_header = struct.pack('!BB',int(bytes("60"),16),0)+struct.pack('!BB',0,0)+struct.pack('!H',payload_len)+struct.pack('!BB',icmp_type,hop)+string_pack(linklocal)+string_pack(ra_dest_packed)
                                      ### ICMP Packet Construct with Router Advertisement Information for Stateful Addressing
                                      ra_type = 134
                                      curr_hop = 64
                                      ### Flag Logic
##                                         o  M - Managed Address Configuration Flag [RFC4861] = 1
##                                         o  O - Other Configuration Flag [RFC4861] = 1
##                                         o  H - Mobile IPv6 Home Agent Flag [RFC3775] = 0
##                                         o  Prf - Router Selection Preferences [RFC4191] = 11 Low Pref
##                                         o  P - Neighbor Discovery Proxy Flag [RFC4389] = 0
##                                         o  R - Reserved = 0
                                     ## Flag = 216 # 11011000
                                      Flag = 128 # 10000000
                                      rout_life = 1800
                                      icmp_opt1 = struct.pack('!BB',1,1)+string_pack(m)
                                      # Source link layer add(1) + Length(1) + Source MAC address
                                      icmp_opt2 = struct.pack('!BBHl',5,1,0,1500) # MTU - type(5) + Length(1) + MTU Size(1500)
                                      opt3_flag = 192 # Binary 11000000
                                      ### Flag Logic
##                                      On Link Flag = 1
##                                      Autonomous address-config = 1
##                                      Router Address Flag = 0
##                                      Reserved = 00000
                                      va_life = 86400
                                      pref_life = 43200
                                      ### Checksum Calculation
                                      
                                      icmp_opt3 = struct.pack('!BBBBIIIQQ',3,4,0,opt3_flag,va_life,pref_life,0,0,0) # Prefix Info - type(3) + Length(4) + Flag(192) + Valid Life + Preferred Life + Reserved + Prefix
                                      icmp_packet = struct.pack('<H',ra_type)+struct.pack('!H',53847)+struct.pack('!B',curr_hop)+struct.pack('!B',Flag)+struct.pack('!Hll',rout_life,0,0)+icmp_opt1+icmp_opt2+icmp_opt3
                                      s.send(ether_head+ip_header+icmp_packet)
                                      continue
                                      #s.send('\x33\x33\x00\x00\x00\x01\x00\x04\x96\x98\x95\x01\x81\x00\x0f\xfd\x86\xdd\x60\x00\x00\x00\x00\x40\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x04\x96\xff\xfe\x98\x95\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x86\x00\xd1\xff\x40\xd8\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x04\x96\x98\x95\x01\x05\x01\x00\x00\x00\x00\x05\xdc\x03\x04\x00\xc0\x00\x01\x51\x80\x00\x00\xa8\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
##                                      opt1_linkaddr = type+length+link_addr
##                                      opt2_mtu = type+length+Reserved+mtu
##                                      opt2_prefix = type+length+prefix+flags+va_life+pre_life+reserved+pre_addr
##                                      icmp_packet = icmp_packet + opt1_linkaddr + opt2_mtu + opt2_prefix
##                                      ra_packet = ip_header + icmpv6_adv_header + icmp_packet
                                      

                                      
                  elif payload[66] == "01":
                          print "DHCP Solicit Received"      
                          Destination_Mac = payload[0]+payload[1]+payload[2]+payload[3]+payload[4]+payload[5]
                          Source_Mac = payload[6]+payload[7]+payload[8]+payload[9]+payload[10]+payload[11]
                          Source_Ip = payload[26]
                          for n in range(27,42):
                                          Source_Ip = Source_Ip+payload[n]
                          Destination_Ip = payload[42]
                          for n in range(43,58):
                                         Destination_Ip = Destination_Ip+payload[n]
                          link_layer = payload[68]
                          for n in range(69,74):
                                         link_layer = link_layer+payload[n]
                          print "-> Source IP - %s" % (Source_Ip)
                          print "-> Destin IP - %s" % (Destination_Ip)
                          print "-> Source MAC - %s" % (Source_Mac)
                          print "-> Destin MAC - %s" % (Destination_Mac)
                          print "-> LinkLayer - %s" % (link_layer)
                          transaction_id = payload[67]+payload[68]+payload[69]
                          print "-> Transaction ID is %s" % (transaction_id)
                          client_id =payload[70]
                          for i in range(71,90):
                              client_id = client_id + payload[i]
                          print "The Client Identifier is %s" % (client_id)
                          Iana = payload[96]
                          for i in range(97,112):
                              Iana = Iana + payload[i]
                          print "The Identity Association for Non Temporary Address %s" % (Iana)
                          mymac =  s.getsockname()[4].encode("hex")
                          linklocal = re.findall('..',"fe80000000000000020496fffe"+mymac[6:8]+mymac[8:11]+mymac[11:13])
                          #linklocal = re.findall('..',"20010000000000000000000000000001")
                          da_dest_packed = re.findall('..',Source_Ip)
                          m = re.findall('..',mymac)
                          dm = re.findall('..',Source_Mac)
                          payload_len = 94
                          udp_type = 17
                          hop = 64
                          #s.send('\x33\x33\x00\x00\x00\x01\x00\x04\x96\x98\x95\x01\x81\x00\x0f\xfd\x86\xdd\x60\x00\x00\x00\x00\x40\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x04\x96\xff\xfe\x98\x95\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x86\x00\xd1\xff\x40\xd8\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x04\x96\x98\x95\x01\x05\x01\x00\x00\x00\x00\x05\xdc\x03\x04\x00\xc0\x00\x01\x51\x80\x00\x00\xa8\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                          da_eth_head = string_pack(dm)+string_pack(m)+data[16]+data[17]
                          da_ip_head = struct.pack('!BB',int(bytes("60"),16),0)+struct.pack('!BB',0,0)+struct.pack('!H',payload_len)+struct.pack('!BB',udp_type,hop)+string_pack(linklocal)+string_pack(da_dest_packed)
                          dhcp_type = 2
                          # Server_id = 2 + Length = 14 + DUID ( Link layer Address + Time ) = Hardware = 1(eth) + DUID Time = 1e9ea533 + link layer address
                          DUID_Time = "1e9ea533"
                          server_id = struct.pack('!H',2)+struct.pack('!H',14)+struct.pack('!H',1)+struct.pack('!H',1)+string_pack(re.findall('..',DUID_Time))+string_pack(m)
                          # Identity Assoiation for Non Temporary address = option = 3 + length = 40 + iaid + t1 + t2 +
                          #iaid = ['0e','00','00','04']
                          iaid = [ payload[100], payload[101], payload[102], payload[103] ]
                          # IA Address = option = 5 + length 24 + Ipv6_addr + pref_life + valid_Life
                          ip6_ad = re.findall('..',"20010000000000000000000000000003")
                          ia_addr = struct.pack('!H',5)+struct.pack('!H',24)+string_pack(ip6_ad)+struct.pack('!II',100,300)
                          iana = struct.pack('!H',3)+struct.pack('!H',40)+string_pack(iaid)+struct.pack('!I',0)+struct.pack('!I',0)+ia_addr
                          da_payload = struct.pack('!B',dhcp_type)+string_pack(re.findall('..',transaction_id))+iana+string_pack(re.findall('..',client_id))+server_id
                          # Check Sum Calculation
                          da_unpack = []
                          da_dec = re.findall('..',da_payload)
                          for i in list(da_dec):
	                         i= i.encode("hex")
                                 da_unpack.append(i)
                          print da_unpack
                          csum = int(da_unpack[0],16)
                          for i in range(1,len(da_unpack)):
                              csum = csum + int(da_unpack[i],16)
                          print csum
                          # UDP Header 
                          csum = csum + 547 +546 + payload_len
                          print csum
                          # Pseudo Header
                          csum = csum + payload_len + udp_type
                          linklo = re.findall('....',"fe80000000000000020496fffe"+mymac[6:8]+mymac[8:11]+mymac[11:13])
                          print linklo
                          dest = re.findall('....',Source_Ip)
                          print dest
                          ip_sum = 0
                          for i in linklo:
                              ip_sum = ip_sum + int(i,16) 
                          print ip_sum
                          for i in dest:
                              ip_sum = ip_sum + int(i,16)
                          print ip_sum
                          csum = csum + ip_sum
                          print csum
                          csum = hex(csum)[2:]
                          print csum
                          csum = re.findall('.',str(csum))
                          print csum
                          if len(csum) > 4:
                              carry = csum[0]
                              other = csum[1]+csum[2]+csum[3]+csum[4]
                              checksum = int(other,16) + int(carry,16)
                          else:
                              checksum = csum[0]+csum[1]+csum[2]+csum[3]
                              checksum = int(checksum,16)
                          print checksum
                          checksum = checksum ^ 65535
                          print checksum
                          da_udp_head = struct.pack('!HHH',547,546,payload_len)+struct.pack('!H',checksum)
                          s.send(da_eth_head+da_ip_head+da_udp_head+da_payload)
                          print "Advertisement Sent !!!!!!"
                  elif payload[66] == "03":
                      print "DHCP Request Received !!!!!!!!!!!"
                      Destination_Mac = payload[0]+payload[1]+payload[2]+payload[3]+payload[4]+payload[5]
                      Source_Mac = payload[6]+payload[7]+payload[8]+payload[9]+payload[10]+payload[11]
                      Source_Ip = payload[26]
                      for n in range(27,42):
                                      Source_Ip = Source_Ip+payload[n]
                      Destination_Ip = payload[42]
                      for n in range(43,58):
                                     Destination_Ip = Destination_Ip+payload[n]
                      link_layer = payload[68]
                      for n in range(69,74):
                                     link_layer = link_layer+payload[n]
                      print "-> Source IP - %s" % (Source_Ip)
                      print "-> Destin IP - %s" % (Destination_Ip)
                      print "-> Source MAC - %s" % (Source_Mac)
                      print "-> Destin MAC - %s" % (Destination_Mac)
                      print "-> LinkLayer - %s" % (link_layer)
                      transaction_id = payload[67]+payload[68]+payload[69]
                      print "-> Transaction ID is %s" % (transaction_id)
                      client_id =payload[70]
                      for i in range(71,90):
                          client_id = client_id + payload[i]
                      print "The Client Identifier is %s" % (client_id)
                      server_id = payload[91]
                      for i in range(92,104):
                          server_id = server_id + payload[i]
                      print "The Server Identifier is %s" % (server_id)
                      mymac =  s.getsockname()[4].encode("hex")
                      linklocal = re.findall('..',"fe80000000000000020496fffe"+mymac[6:8]+mymac[8:11]+mymac[11:13])
                      #linklocal = re.findall('..',"20010000000000000000000000000001")
                      da_dest_packed = re.findall('..',Source_Ip)
                      m = re.findall('..',mymac)
                      dm = re.findall('..',Source_Mac)
                      payload_len = 94
                      udp_type = 17
                      hop = 64
                      #s.send('\x33\x33\x00\x00\x00\x01\x00\x04\x96\x98\x95\x01\x81\x00\x0f\xfd\x86\xdd\x60\x00\x00\x00\x00\x40\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x02\x04\x96\xff\xfe\x98\x95\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x86\x00\xd1\xff\x40\xd8\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x04\x96\x98\x95\x01\x05\x01\x00\x00\x00\x00\x05\xdc\x03\x04\x00\xc0\x00\x01\x51\x80\x00\x00\xa8\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                      da_eth_head = string_pack(dm)+string_pack(m)+data[16]+data[17]
                      da_ip_head = struct.pack('!BB',int(bytes("60"),16),0)+struct.pack('!BB',0,0)+struct.pack('!H',payload_len)+struct.pack('!BB',udp_type,hop)+string_pack(linklocal)+string_pack(da_dest_packed)
                      dhcp_type = 7
                      # Server_id = 2 + Length = 14 + DUID ( Link layer Address + Time ) = Hardware = 1(eth) + DUID Time = 1e9ea533 + link layer address
                      DUID_Time = "1e9ea533"
                      server_id = struct.pack('!H',2)+struct.pack('!H',14)+struct.pack('!H',1)+struct.pack('!H',1)+string_pack(re.findall('..',DUID_Time))+string_pack(m)
                      # Identity Assoiation for Non Temporary address = option = 3 + length = 40 + iaid + t1 + t2 +
                      #iaid = ['0e','00','00','04']
                      iaid = [ payload[100], payload[101], payload[102], payload[103] ]
                      # IA Address = option = 5 + length 24 + Ipv6_addr + pref_life + valid_Life
                      ip6_ad = re.findall('..',"20010000000000000000000000000003")
                      ia_addr = struct.pack('!H',5)+struct.pack('!H',24)+string_pack(ip6_ad)+struct.pack('!II',100,300)
                      iana = struct.pack('!H',3)+struct.pack('!H',40)+string_pack(iaid)+struct.pack('!I',0)+struct.pack('!I',0)+ia_addr
                      da_payload = struct.pack('!B',dhcp_type)+string_pack(re.findall('..',transaction_id))+iana+string_pack(re.findall('..',client_id))+server_id
                      # Check Sum Calculation
                      da_unpack = []
                      da_dec = re.findall('..',da_payload)
                      for i in list(da_dec):
                             i= i.encode("hex")
                             da_unpack.append(i)
                      print da_unpack
                      csum = int(da_unpack[0],16)
                      for i in range(1,len(da_unpack)):
                          csum = csum + int(da_unpack[i],16)
                      print csum
                      # UDP Header 
                      csum = csum + 547 +546 + payload_len
                      print csum
                      # Pseudo Header
                      csum = csum + payload_len + udp_type
                      linklo = re.findall('....',"fe80000000000000020496fffe"+mymac[6:8]+mymac[8:11]+mymac[11:13])
                      print linklo
                      dest = re.findall('....',Source_Ip)
                      print dest
                      ip_sum = 0
                      for i in linklo:
                          ip_sum = ip_sum + int(i,16) 
                      print ip_sum
                      for i in dest:
                          ip_sum = ip_sum + int(i,16)
                      print ip_sum
                      csum = csum + ip_sum
                      print csum
                      csum = hex(csum)[2:]
                      print csum
                      csum = re.findall('.',str(csum))
                      print csum
                      if len(csum) > 4:
                          carry = csum[0]
                          other = csum[1]+csum[2]+csum[3]+csum[4]
                          checksum = int(other,16) + int(carry,16)
                      else:
                          checksum = csum[0]+csum[1]+csum[2]+csum[3]
                          checksum = int(checksum,16)
                      print checksum
                      checksum = checksum ^ 65535
                      print checksum
                      da_udp_head = struct.pack('!HHH',547,546,payload_len)+struct.pack('!H',checksum)
                      s.send(da_eth_head+da_ip_head+da_udp_head+da_payload)
                      print "Reply Sent !!!!!!"
                      
                       
                          
                  else:
                      print "Not DHCPv6 Packet"
                          






























                           
                           
                                      

                                      

