# Stegotorus User Guide

## Overview

Stegotorus is providing a transparent proxy to transport the traffic from a 
client software (such as a browser) to its server software. 

Note that if you want need to setup proxy server which takes the traffic which is 
distant to any server/IP and deliver it to its destination, Stegotorus can not 
do that by itself. You need to use a HTTP or socks proxy (such as Tor or SSH)
in combination with Stegotorus.

          +-------------------+             +-------------------+
          | Stegotorus Client |-------------| Stegotorus Server |
          +-------------------+             +-------------------+
                   |                                  |
           +-----------------+               +-----------------+
           | Client Software |               | Server Software |
           +-----------------+               +-----------------+
           
In this document we adapt the common proxy terminalogy as follows:

**Downstream** Traffic: referes to the traffic between Stegotorus Client and 
Server.
**Upstream** Traffic: referes to the traffic between Stegotorus Server and the
server software or between Stegotorus Client and the client software.

## Configuration

Stegotorus can be configured either from commandline or using a configuration 
file. The command line settings override the configuration files.

### Command Line Synopsis

    stegotorus [STEGOTORUS OPTIONS] 
           protocol_name protocol_mode [PROTOCOL OPTIONS] 
           upstream-address:upstream-port
           [steg_mod_name downstream-address:downstream-port [STEG_MOD OPTIONS]]
           [steg_mod_name downstream-address:downstream-port [STEG_MOD OPTIONS]]
           ...
           [protocol_name ...]

For example the following command starts a stegotorus configured by the 
configuration specified in "conf.d/chop-nosteg-rr-client.yaml" file:

    $ ./stegotorus --config-file=conf.d/chop-nosteg-rr-client.yaml

That is a Stegotorus client using chop protocol to communicate to the 
specified Stegotorus server using ephemeral connections with no extra encoding. 

The following command starts a Stegotorus server expecting clients communicating
by Chop protocol using http_apache steg module using 66.135.46.119 HTTP server 
content as for its cover content:

    $ ./stegotorus --log-min-severity=debug --timestamp-logs chop server --passphrase "correct passphrase" --trace-packets --disable-retransmit --cover-server 66.135.46.119:80 127.0.0.1:5001 http_apache 127.0.0.1:5000 --cover-list apache_payload/funnycatpix.csv"
    
### Configuration file format

Stegotorus comes with the pre set of configuration samples resides in the

![Stegotorus Configuration Folder](./conf.d/)

The configuration file is standard YAML format, follows similar logic as the 
command line format:
    
    stegotorus-option-1: value
    stegotorus-option-2: value
    ...
    protocols:
      - name: "protocol1"
        mode: server/client/socks
        up-address: x.y.z.w:port
        porotocol-option-1: value
        porotocol-option-2: value
        ...
        stegs:
          - name: steg-mode-1
            down-address: a.b.c.d:port
            steg-mod-option-1: value
            steg-mod-option-2: value
      - name: "protocol2"
        ...

For example, the following configuration file which configures Stegotorus
as a client communicating with chop protocol with nosteg-rr encoding:

/home/klaymen/doc/code/stegotorus/conf.d/chop-nosteg-rr-server.yaml

![./conf.d/chop-nosteg-rr-server.yaml](./conf.d/chop-nosteg-rr-server.yaml)

    ####################################
    # process options
    ####################################
    log-min-severity:  debug
    timestamp-logs: true
    
    ####################################
    # protocol specification for client
    ####################################
    protocols:
      - name: "chop"
        mode: server
        up-address: 127.0.0.1:5001
        disable-retransmit: true
        stegs:
          - name: nosteg_rr
            down-address: 127.0.0.1:5000

And the following is a more complicated example which configure Stegotorus on
server mode serves requested traffic while apparantly serving the 
content of http://www.funnycatpix.com/ website:

![./conf.d/chop-http-apache-server-st-bridge.yaml](./conf.d/chop-http-apache-server-st-bridge.yaml)

    ####################################
    # processg options
    ####################################
    log-min-severity:  debug
    timestamp-logs: true
    
    ####################################
    # protocol specification for server 
    ####################################
    protocols:
      - name: "chop"
        mode: server
        passphrase: "correct passphrase"
        trace-packets: true
        disable-retransmit: true
        cover-server: 66.135.46.119:80 #funny cat pix
        up-address: st-bridge.somedomain.org:5001
        stegs:
          - name: "http_apache"
            down-address: 127.0.0.1:5000
            cover-list: "apache_payload/funnycatpix.csv"


In the following sections we descibe each item and its possible values in the 
Stegotorus configuration

### Stegotorus Options

* *--config-file*=<file>  Loads the stegotorus configuration from the specified 
  <file>.
  
* *--log-min-severity* can take one of the four values: error, warn, info, debug.
  and controls the amoung of logs which Stegtorus generates.

* *--timestamp-logs* adds timestamp to each line of the log.

* *--log-file*=<file> Writes the log into <file> instead of stderr.

* *daemon* runs Stegotorus as a background daemon currently only supported in 
  linux.

### Protocol Name

There are currently two protocols that are supported 

* *null*: null protocol is mainly a test protocol. It does not manipulate 
          the traffic in anyway and it upstream traffic and send it with no 
          manipulation on the downstream channel. Conversely, 

* *chop*: the chopper protocol is main protocol of the Stegotorus. Chopper
          *chops* the networks into small chunks and manage the task of 
          transmitting each packets by the help of Steg module encoders.
  
### General Protocol Options
* *mode*: indicates if the Stegotorus is acting as a proxy server responding
          to other stegotorus clients or as a proxy client responding to other 
          client software. Choosing *socks* mode turns Stegotorus into a 
          socks client.
          
* *up-address* which should be specified in x.y.z.w:port format specifices 
          the upstream destination. In client mode
          specifies the address to which Stegotorus should listen. In the server
          mode it is the address to which Stegotorus is required to froward
          the traffic.

#### Null
Null protocol is mainly developped for testing purposes. It is basically
acts as a transparent proxy. Upon receiving a connection from the client
side, it makes a connection to the server side and forward the traffic 
back and forth between the client and server without altering the traffic
in anyway.

Null protocol has no protocol specific options.

#### Chop

Chop implements a protocol similar to TCP/IP over the network transport layer
by breaking the network flow in to chunks and managing the responsibility of
transmiting the traffic chunk by chunk.

Each chunk should be small enough so it can be encoded by the steg module. 
Furthermore, chopper choose the size of each chunk size from a random 
distribution to make it hard for the Stegotorus traffic to be distinguished
by the packet size.

Chop makes sure that each chunk makes it to the other side of the downstream. 
If for any reason, such as censor manipulation or network condition, a chunk 
does not arrives to its destination, chunk will retransmit it, until it receives
the acknowledgement that the chunk is received intactly.

To ensure transmission reliablity by providing redundant channels, Chopper is 
able to transmit the network flow through multiple downstreams. At the time
of transmission chop would send each chunk through any available streams. 

Chop encrypts each chunck to provide additional security to the user. Each chunk
is encrypted using AES in GCM mode which provides both confidentiality and 
integrity. The unique symmetric encryption key is negotiated at the handshake 
of each downstream connection.

As a measure against active probing attack, if a cover server is provided and 
the client doesn't handshake using pre-shared server phassphrase, Stegotorus 
turns into a transparent proxy forwarding the clients communication directly to
 the cover server and viceversa.
  
Following are the specific options controling to Chop protocol behavoir:

* *--passphrase*=string
  Specifies the passphrase which is used to generate a symmetric key which is
  used to encrypt the client handshake and authenticate the client to the server. 
  
* *--enable-encryption*, *--disable-encryption*: enables or disable encrypting
  transmitted traffic. It is enabled by default.
  
* *--minimum-noise-to-signal*=<number> defines the minimum number of bytes of 
  cover traffic the chopper needs to serve in order serve a byte of user traffic.
  this ensure a minimum defficulty on statistical traffic analysis to distinguish
  Stegotorus traffic from the cover traffic. The default value is 0. 
  
* *--enable-retransmit*, *--disable-retransmit*: enables or disables the 
  retransmit mechanism of the chopper. Note that both client and server should 
  agree on disabling or enabling this option. It is enabled by default.
  
* *--cover-server*=<x.y.z.w:port> Specifies a cover server. If a cover server
  is specified, if the client connection fails authentication, chop turns
  into a transparent proxy forward the traffic with no modification. Content
  served by the cover server might be use by steg modules as cover content
  as for example in case of *http_apache* steg module.
  
* *--trace-packets* enabling printing the traffic content in debug log. It is 
  only for debug reason and is disabled by default.
  
### Chop Steg modules

Steg modules provide various encoding to demorph the content of the traffic
observed in the traffic. All steg modules should specifies the downstream 
address. It is the paramater immediately after the steg module name 
specified in the command line, or it should be specified by down-address 
property in the config file:

* *down-address* which should be specified in x.y.z.w:port format specifices 
          the downstream destination. In client mode it specifies the address 
          of the Stegotorus server. In the server mode it specfies the IP address
          and port on which the Stegotorus server should listen.

Here are the list of implemented Steg modules:

#### nosteg

This does not apply any encoding on the data. When the only the property of Chop
are desired (randomized packet size, encryption, active probing resitance, 
re-transmit). Not that the client connections are persistant and if the adversary
dropping connections it can disturbe the operation of Chop using nosteg Steg 
mod.

#### nosteg_rr

This module is similar to nosteg module, except it only transmit one chunk over
each connection. It can sheild the client from connection drop and provide
it with persistant connection when network condition or adversary  only allows for
ephemeral connction.

#### http

http steg module encode the user's traffic in content usually transmited in HTTP 
protocol and communicate them over HTTP protocol. http steg module encodes chopped
data into  prevoiusly recorded or fakely generated HTTP traffic. Following is the
option related to this steg module:

* *--steg-mod*=<filetype> it dictates files with which extension can be used to
  encode chop traffic inside it. The option can be used more than once to specifies
  multiple file extensions. The supported extensions are currently: 
     
    html, htm, php, jsp, asp, JS, js, PDF, pdf, SWF, swf, PNG, png, JPG, jpg, GIF, gif

### http_apache
The http_apache module is a variance of http steg module which uses an actual HTTP client (currently curl) and HTTP server to generate the requests and responses in which eventually encode the chop traffic. In this way it generates less distinguished behavoir compared to actual HTTP traffic.

In addition to steg_mod option of http steg module, http_apache also support the followig option:

* *--cover-list*=<file> Points the files which stores the list of the cover files on the server. At the start up Stegetorus syncs the content of the file with the server. 

## Test Deployment 
Here we describe a simple setup to test Stegotorus locally (running both
client and server on the same machine) on a GNU/Linux system. Setting up 
Stegotorus on different machine to communicate is substantially the same
except for the use of actual stegotorus server IP for "down-address" for
both client and server instead of 127.0.0.1 local IP.

In addition to Stegotorus You need the following progarms:

    openssh-server
    firefox

We are going to setup the following configuration on the localhost to test
Stegotorus:

                  5000                              5000
          +-------------------+             +-------------------+
          | Stegotorus Client |-------------| Stegotorus Server |
          +-------------------+             +-------------------+
                   |                                  |
           +-----------------+               +-----------------+
           | Client Software |               | Server Software |
           +-----------------+               +-----------------+
                 4999                                5001

        Setting up obfsproxies:

### Setup a local socks server:

1. Make sure that the openssh server is running on your system:

        $ systemctl start ssh
        $ systemctl status ssh
    
2. In a terminal tab, ask OpenSSH server to start a local socks proxy on port 
   5001:
   
        $ ssh -ND 5001 localhost
        user@localhost's password: 
   
   the command asks for your password and will get stuck there. That is the 
   expected behavoir and means your local socks server is listening on port
   5001. 

### Setup Stegotorus server:
Here for simplicity we start a server supporting nosteg_rr encoding as it 
does not depends on external covers.

In another terminal:

    $ cd /path/to/stegotorus/
    $ ./stegotorus --log-min-severity=debug --timestamp-logs chop server --passphrase "correct passphrase" --trace-packets --disable-retransmit 127.0.0.1:5001 nosteg_rr 127.0.0.1:5000

### Setup Stegotorus client
The client should follow the same setting as the server so they can successfully communicate:

In another terminal:

    $ cd /path/to/stegotorus/
    $ ./stegotorus --log-min-severity=debug --timestamp-logs chop client --passphrase "correct passphrase" --trace-packets --disable-retransmit 127.0.0.1:4999 nosteg_rr 127.0.0.1:5000

### Set the browser proxy settings
Set [modify your browser's settings][Firefox proxy] to point to:

  - Set the Socks host to be `localhost` and port `4999`
    
Now you should be able to browse and observe that your traffic is passing through Stegotorus.

### Speed Test
If you have 

* curl 

installed. You can test the difference in the speed when your traffic passes 
through Stegotorus by running the following command in a terminal:

    $ curl -x socks4://127.0.0.1:4999 http://speedtest.wdc01.softlayer.com/downloads/test500.zip -o /dev/null

### Using an existing website to provide content for Stegotorus

Here we explain the senario that the owner of  http://mybenignwebsite.com/ would like to provide 
cover and help Stegotorus user out. Suppose:
- mybenignwebsite.com is running on server with IP address 1.2.3.4.
- We are going to run stegotorus on a server with IP address 5.6.7.8.

1. Assuming that OpenSSH server is install on 5.6.7.8 server, run a local Socks
   server on 5.6.7.8
   
        $ ssh -ND 5001 localhost
        
2. Write a configuration file, `/path/to/stegotorus/conf/stegotorus.conf` as follows:

    ####################################
    # protocol specification for server 
    ####################################
    protocols:
      - name: "chop"
        mode: server
        passphrase: "correct passphrase"
        disable-retransmit: true
        cover-server: 1.2.3.4:80
        up-address: 127.0.0.1:5001
        stegs:
          - name: "http_apache"
            down-address: 5.6.7.8:80

3. Run Stegotorus server on 5.6.7.8:
 
        ./stegotorus --config-file=/path/to/stegotorus/conf/stegotorus.conf

4. Change the DNS record for mybenignwebsite.com to point 5.6.7.8.

In this way, users who do not use Stegotorus will be served the actual content
of mybenignwebsite.com. On the other hand, users who uses stegotorus and have
the `correct passphrase` are served by the Socks server on 127.0.0.1:5001 and
there data will be encode in mybenignwebsite.com HTTP contnet.

