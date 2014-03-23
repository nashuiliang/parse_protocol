-module(parse_tcpdump).
-export([get_raw_ethernet/1]).

-define(Ethernet_Start_Pos, 40).

get_raw_ethernet(Tcpdump_file) ->
  {ok, File_content} = file:read_file(Tcpdump_file),
  parse_tcpdump(File_content).

parse_tcpdump(Con) when size(Con) =< ?Ethernet_Start_Pos -> {error, "Not Tcpdump File"};
parse_tcpdump(File_content) ->
  {Tcpdump_info, Ethernet_info} =
    split_binary(File_content, ?Ethernet_Start_Pos),
  {ok, File_content, Tcpdump_info, Ethernet_info}.
