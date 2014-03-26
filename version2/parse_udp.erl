-module(parse_udp).
-export([udp_proto_info/3, print_udp_proto_info/3, speed_udp_proto_info/1, print_speed_udp_proto_info/1]).

get_udp_content(File_name) ->
  {ok, File_content} = file:read_file(File_name),
  {ok, _, _, _, {data, IP_content}} = parse_ethernet:ethernet_proto_info(File_content),
  {ok, _, _, _, {src, _, Src_ip, dst, _, Dst_ip}, {data, UDP_content}} = parse_ip:ip_proto_info(IP_content),
  {UDP_content, Src_ip, Dst_ip}.

speed_udp_proto_info(File_name) ->
  {UDP, S, D} = get_udp_content(File_name),
  udp_proto_info(UDP, S, D).

print_speed_udp_proto_info(File_name) ->
  {UDP, S, D} = get_udp_content(File_name),
  print_udp_proto_info(UDP, S, D).

udp_proto_info(UDP_content, Src_ip, Dst_ip) ->
  <<Src_port:16, Dst_port:16, Length:16, Checksum:16, Data/binary>> = UDP_content,
  {_, Length_info} = split_binary(UDP_content, 4),
  {L, _} = split_binary(Length_info, 2),
  Info = binary_to_list(Src_ip) ++ binary_to_list(Dst_ip) ++ binary_to_list(L) ++ [0] ++ [16#11] ++ binary_to_list(UDP_content),
  S = << <<X>> || X <- Info >>,

  {ok, _, Check_Res, Check_Val} = checksum(S),
  {ok,
   {src_port, Src_port},
   {dst_port, Dst_port},
   {length, Length},
   {raw_check_val, Checksum, check_res, Check_Res, check_val, Check_Val},
   {data, Data}
  }.

print_udp_proto_info(UDP_content, Src_ip, Dst_ip) ->
  {ok, {src_port, Src_port}, {dst_port, Dst_port},
   {length, Length},
   {raw_check_val, Checksum, check_res, Check_Res, check_val, Check_Val},
   {data, Data}
  } = udp_proto_info(UDP_content, Src_ip, Dst_ip),

  io:format("UDP(user datagram protocol)~n"),
  io:format("\tSource port: ~p [2 bytes]~n", [Src_port]),
  io:format("\tDestination port: ~p [2 bytes]~n", [Dst_port]),
  io:format("\tLength: ~w [0x~4.16.0x] [2 bits]~n", [Length, Length, ""]),
  io:format("\tChecksum: 0x~4.16.0x [0x~4.16.0x][~s] [16 bits]~n",
            [Checksum, "", Check_Res, "", Check_Val]),
  io:format("Data: ~w~n", [Data]).

checksum(0) -> {ok, 0, 0, "do not check"};
checksum(N) -> parse_helper:checksum(N).
