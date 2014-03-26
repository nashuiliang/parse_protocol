-module(parse_icmp).
-export([icmp_protocol_info/1, print_icmp_protocol_info/1]).
-import(parse_ip, [ip_protocol_info/1, header_checksum/1]).

-define(ICMP_Filename, "icmp_xiaoyintong.tcpdump").
-define(ICMP_Reply_Filename, "icmp_xiaoyintong_reply.tcpdump").
-define(Protocol_ICMP, 1).

icmp_protocol_info(File_name) ->
  Data = ip_protocol_info(File_name),
  {_, {proto, Proto, _, _}, _} = element(4, Data),
  {data, Content} = element(tuple_size(Data), Data),
  parse_icmp_protocol(Proto, Content).

parse_icmp_protocol(Protocol, _) when Protocol /= ?Protocol_ICMP -> throw({error, "Not ICMP Protocol"});
parse_icmp_protocol(_, Content) ->
  <<Type:8, Code:8, Checksum:16,
    Identifier:16, Sequence_Number:16,
    Data/binary>> = Content,
  {ok, _, Check_Res, Check_Val} = header_checksum(Content),

  {ok,
    {type, Type, type_val, icmp_type(Type)},
    {code, Code},
    {raw_check_val, Checksum, check_res, Check_Res, check_val, Check_Val},
    {id, Identifier}, {seq, Sequence_Number},
    {data, Data}
  }.

print_icmp_protocol_info(File_name) ->
  {ok, {type, Type, type_val, Type_Val}, {code, Code},
    {raw_check_val, Checksum, check_res, Check_Res, check_val, Check_Val},
    {id, Identifier}, {seq, Sequence_Number}, {data, Data}
  } = icmp_protocol_info(File_name),

  io:format("ICMP(internet control message protocol)~n"),
  io:format("\tType: ~w [~s] [8 bits]~n", [Type, Type_Val]),
  io:format("\tCode: ~w [8 bits]~n", [Code]),

  io:format("\tChecksum: 0x~4.16.0x [0x~4.16.0x] [~s] [16 bits]~n",
            [Checksum, "", Check_Res, "", Check_Val]),
  io:format("\tIdentifier: ~w [16 bits]~n", [Identifier]),
  io:format("\tSequence number: ~w [16 bits]~n", [Sequence_Number]),
  icmp_input_data(Data).

icmp_input_data(Data) ->
  io:format("\tData: "),
  icmp_input_data(Data, 0, size(Data)).

icmp_input_data(Data, N, Size) when N =:= (Size - 1) ->
  {_, <<Val:8>>} = split_binary(Data, N),
  io:format("~.16X~n", [Val, ""]);
icmp_input_data(Data, N, Size) ->
  {_, <<Val:8, _/binary>>} = split_binary(Data, N),
  io:format("~.16X", [Val, ""]),
  icmp_input_data(Data, N + 1, Size).

icmp_type(T) ->
  case T of
    8 -> "echo message";
    0 -> "echo replay message"
  end.
