-module(parse_ip).
-export([ip_proto_info/1, print_ip_proto_info/1, speed_ip_proto_info/1, print_speed_ip_proto_info/1]).

-define(Protocol_ICMP, 1).
-define(Protocol_TCP, 6).
-define(Protocol_UDP, 17).

get_ip_content(File_name) ->
  {ok, File_content} = file:read_file(File_name),
  {ok, _, _, _, {data, Data}} = parse_ethernet:ethernet_proto_info(File_content),
  Data.

speed_ip_proto_info(File_name) ->
  ip_proto_info(get_ip_content(File_name)).

print_speed_ip_proto_info(File_name) ->
  print_ip_proto_info(get_ip_content(File_name)).

ip_proto_info(IP_content) ->
  <<Version:4, Header_Length:4, TOS:8, Total_Length:16,
    Identification:16, Flags:3, Fragment_Offset:13,
    TTL:8, Protocol:8, Header_Checksum: 16, IP_address/binary>> = IP_content,
  {SrcIP, S_IP_content} = split_binary(IP_address, 4),
  {DstIP, Temp_data} = split_binary(S_IP_content, 4),

  {_Info_Header_Checksum, _} = split_binary(IP_content, 20),
  {Data, _} = split_binary(Temp_data, (Total_Length - 20)),
  {ok, _, Protocol_Val} = protocol_type(Protocol),
  {ok, _, Check_Res, Check_Val} = parse_helper:checksum(_Info_Header_Checksum),

  {ok, {
      version, Version,
      header_length, Header_Length,
      tos, TOS,
      total_length, Total_Length
    }, {
      id, Identification,
      flags, Flags,
      fragment_offset, Fragment_Offset
    }, {
          {ttl, TTL},
          {proto, Protocol, proto_val, Protocol_Val},
          {raw_check_val, Header_Checksum, check_res, Check_Res, check_val, Check_Val}
    }, {
      src, element(2, ip_address(SrcIP)), SrcIP,
      dst, element(2, ip_address(DstIP)), DstIP
    }, {data, Data}
  }.

ip_address(IP) ->
  <<IP1:8, IP2:8, IP3:8, IP4:8>> = IP,
  {ok, io_lib:format("~w.~w.~w.~w", [IP1, IP2, IP3, IP4])}.


print_ip_proto_info(IP_content) ->
  {ok, {version, Version, header_length, Header_Length, tos, TOS, total_length, Total_Length },
      {id, Identification, flags, Flags, fragment_offset, Fragment_Offset },
      {{ttl, TTL}, {proto, Protocol, proto_val, Protocol_Val}, {raw_check_val, Header_Checksum, check_res, Check_Res, check_val, Check_Val} },
      { src, SouceIP, dst, DestinationIP}, {data, Data}
  } = ip_proto_info(IP_content),

  io:format("IP(internet protocol)~n"),
  io:format("\tVerson: ~p [4 bits]~n", [Version]),
  io:format("\tHeader length: ~w [20 bytes] [4 bits]~n", [Header_Length]),
  io:format("\tTOS: ~w [0x~2.16.0x] [8 bits]~n", [TOS, TOS, ""]),
  io:format("\tTotal length ~w bytes [16 bits]~n", [Total_Length]),
  io:format("\tIdentification: ~w [0x~4.16.0x] [16 bits]~n", [Identification, Identification, ""]),
  io:format("\tFlags: ~w [0x~2.16.0x] [3 bits]~n", [Flags, Flags, ""]),
  io:format("\tFragment offset: ~w [0x~4.16.0x] [13 bits]~n", [Fragment_Offset, Fragment_Offset, ""]),
  io:format("\tTTL: ~w [0x~2.16.0x] [8 bits]~n", [TTL, TTL, ""]),
  io:format("\tProtocol: ~w [~s] [8 bits]~n", [Protocol, Protocol_Val]),
  io:format("\tHeader checksum: ~4.16.0x [0x~.16.0x][~s] [16 bits]~n",
            [Header_Checksum, "", Check_Res, "", Check_Val]),
  io:format("\tSource: ~s [32 bits]~n", [SouceIP]),
  io:format("\tDestination: ~s [32 bits]~n", [DestinationIP]),
  io:format("Data: ~w~n", [Data]).

protocol_type(P) ->
  case P of
    ?Protocol_ICMP -> {ok, P, "ICMP"};
    ?Protocol_TCP -> {ok, P, "TCP"};
    ?Protocol_UDP -> {ok, P, "UDP"}
  end.
