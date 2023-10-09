# OVERVIEW
I am using Cisco's [ConfD Basic](https://www.tail-f.com/confd-basic/), which only supports NETCONF over SSH subsystem.  

However, there is a requirement for me to run NETCONF over TLS 1.3 which is still in a [draft](https://datatracker.ietf.org/doc/draft-ietf-netconf-over-tls13/) phase. 

ConfD Basic's existing implementation allows NETCONF communication via TCP, but with a unique prerequisite: a specific initialization string must be transmitted before the NETCONF server responds with a hello message.


```
19.5.2. Internal TCP Transport

The server can also be configured to accept plain TCP traffic. This can be useful during development, for debugging purposes, but it can also be used to plug in any other transport protocol. The way this works is that some other daemon terminates the transport and authenticates the user. Then it connects to the NETCONF server over TCP (preferably over the loopback interface for security reasons) and relays the XML traffic to NETCONF.

In this case, the transport daemon will have to authenticate the user, and then tell the NETCONF server about it. This should be done as a header sent over the TCP socket before any other bytes are sent. There are two supported variants of this, only differing in encoding of the username. The first with the username in plain text, where the header looks like this:

[username;source;proto;uid;gid;subgids;homedir;group-list;]\n

and the second with the username base64-encoded, where the header looks like this:

b64[b64username;source;proto;uid;gid;subgids;homedir;group-list;]\n
```
 
This proxy solution seamlessly fowards the required initialization string and all subsequent data between the ConfD NETCONF server and the NETCONF client(s). Consequently, NETCONF clients can authenticate using certificates alone. 


Alternatively, an additional approach under consideration involves exploring the subsystem source code provided by ConfD. This approach necessitates careful redirection of I/O operations, employing sockets and file descriptors to meet the specified requirements.

While I'm certain this could be achieved with some combination of bash pipes and socat, stunnel or other common Unix utilities, this proxy server solution is the one I have been able to get to work. 


# ALTERNATIVES
 * YumaPro SDK basic offers NETCONF over SSH subsystem
 * YumaPro SDK offers NETCONF over SSH and TLS
 * https://github.com/choppsv1/netconf
    * Doesn't appear to do YANG data validation
    * Would have to write in TLS support myself

