# TLSextend
A Wireshark postdissector in Lua to extend the TLS dissector

I wrote this Lua post-dissector to answer the following question:

> "I see I can filter "tls.handshake.type == 1" for Client Hello and "tls.handshake.type == 2" 
> for server hello. I have server side capture and I want to filter all the TCP stream which 
> has "Client Hello" but no "Server Hello" response back.
> 
> Any filter i can use?"

See: https://ask.wireshark.org/question/26618/filter-tls-with-no-server-hello/

As the dissection engine is packet based and not session based, some postprocessing needs to be done
to create such a filter. One way is to use the embedded Lua scripting engine.

When using this script with 'tshark', don't forget to enable 2-pass processing with the '-2' command line option:

```
$ tshark -2 -X lua_script:TLSextend.lua -r ~/OneDrive\ -\ SYN-bit/Wireshark/pcap/misc/tls-test.pcapng -Y TLSextend.state==1
   81   2.385957   10.0.0.110 → 77.111.240.149 TCP 78 64493 → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 TSval=439291567 TSecr=0 SACK_PERM=1
   82   2.414441 77.111.240.149 → 10.0.0.110   TCP 74 443 → 64493 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 TSval=1179502997 TSecr=439291567 WS=2048
   83   2.414653   10.0.0.110 → 77.111.240.149 TCP 66 64493 → 443 [ACK] Seq=1 Ack=1 Win=131712 Len=0 TSval=439291595 TSecr=1179502997
   84   2.430020   10.0.0.110 → 77.111.240.149 TLSv1 299 Client Hello
   85   2.458315 77.111.240.149 → 10.0.0.110   TCP 66 443 → 64493 [ACK] Seq=1 Ack=234 Win=67584 Len=0 TSval=1179503041 TSecr=439291610
$ 
```
