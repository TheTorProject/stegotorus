# Stegotorus User Guide

## Overview

Stegotorus provides a transparent proxy to transport the traffic from the client software (such as a browser) to its server software. 

Note that if you need to set up a proxy server that takes the traffic which is distant to *any* server/IP and delivers it to its destination, Stegotorus cannot do that by itself. You need to use an HTTP or socks proxy (such as Tor or SSH) in a combination with Stegotorus.

          +-------------------+             +-------------------+
          | Stegotorus Client |-------------| Stegotorus Server |
          +-------------------+             +-------------------+
                   |                                  |
           +-----------------+               +-----------------+
           | Client Software |               | Server Software |
           +-----------------+               +-----------------+
           
In this document, we adopt the common proxy terminology as follows:

**Downstream Traffic** refers to the traffic between Stegotorus Client and Server.

**Upstream Traffic** refers to the traffic between Stegotorus Server and the server software or between Stegotorus Client and the client software.

## Configuration

Stegotorus can be configured either from the command line or by using a configuration file. The command line settings override the configuration files.

### Command Line Synopsis

    stegotorus [STEGOTORUS OPTIONS] 
           protocol_name protocol_mode [PROTOCOL OPTIONS] 
           upstream-address:upstream-port
           [steg_mod_name downstream-address:downstream-port [STEG_MOD OPTIONS]]
           [steg_mod_name downstream-address:downstream-port [STEG_MOD OPTIONS]]
           ...
           [protocol_name ...]

For example, the following command starts a Stegotorus configured by the configuration specified in "conf.d/chop-nosteg-rr-client.yaml" file:

    $ ./stegotorus --config-file=conf.d/chop-nosteg-rr-client.yaml

That is a Stegotorus client using the chop protocol to communicate to the specified Stegotorus server using ephemeral connections with no extra encoding. 

The following command starts a Stegotorus server expecting that clients communicating by Chop protocol are using the http_apache steg module using 66.135.46.119 HTTP server content as for its cover content:

    $ ./stegotorus --log-min-severity=debug --timestamp-logs chop server --passphrase "correct passphrase" --trace-packets --disable-retransmit --cover-server 66.135.46.119:80 127.0.0.1:5001 http_apache 127.0.0.1:5000 --cover-list apache_payload/funnycatpix.csv"
    
### Configuration file format

Stegotorus comes with the preset of configuration samples residing in the [Stegotorus Configuration Folder](./conf.d/)

The configuration file has a standard YAML format and follows similar logic to the command line format:
    
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

For example, the following configuration file which configures Stegotorus as a client communicating with chop protocol with nosteg-rr encoding: 

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

Here is a more complicated example on how to configure Stegotorus in server mode that serves requested traffic while apparently serving the content of http://www.funnycatpix.com/ website:

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


In the following sections, we describe each item and its possible values in the Stegotorus configuration.

### Stegotorus Options

* *--config-file*=<file> loads the Stegotorus configuration from the specified <file>.
  
* *--log-min-severity* can take one of the four values: error, warn, info, debug, and controls the number of logs generated by Stegtorus.

* *--timestamp-logs* adds a timestamp to each line of the log.

* *--log-file*=<file> writes the log into <file> instead of stderr.

* *daemon* runs Stegotorus as a background daemon currently only supported in GNU/Linux OS.

### Protocol Name

Currently, Stegotorus supports two protocols, namely *null* and *chop*.

* *null*: The null protocol represents mainly a test protocol. It does not manipulate the traffic; it takes the upstream traffic and sends it with no manipulation to the downstream channel.

* *chop*: The chop protocol, or the chopper, represents the primary protocol of Stegotorus. The chopper "chops" the network traffic into small chunks and manages the task of transmitting each packet by the help of the Steg module encoders.
  
### General Protocol Options

* *mode*: indicates whether the Stegotorus is acting as a proxy server responding to other Stegotorus clients or as a proxy client responding to other clients software. Choosing the *socks* mode turns Stegotorus into a socks client.
          
* *up-address* which should show in in x.y.z.w:port format specifies the upstream destination. In the client mode, *up-address* specifies the address to which Stegotorus should listen. In the server mode, it indicates the address to which Stegotorus is required to forward the traffic.

#### Null

The *null* protocol is developped for testing purposes. It esentially acts as a transparent proxy. Upon receiving a connection from the client side, it makes a connection to the server and forwards the traffic back and forth between the client and server without altering the traffic in any way. The *null* protocol has no protocol-specific options.

#### Chop

The *chop* implements a protocol similar to TCP/IP over the network transport layer by breaking the network flow into chunks and managing the responsibility of transmitting the traffic piece by piece. Each chunk should be small enough so the Steg module can encode it.

Furthermore, the chopper chooses the size of each chunk size from a random distribution to make it hard for the Stegotorus traffic to be distinguished by the packet size. Chop makes sure that each chunk makes it to the other side of the downstream. If for whatever reason, were it a censor manipulation or a network condition, a chunk fails to arrive at its destination, the chunk will retransmit it until it receives the acknowledgement that the chunk is received intact.

To ensure transmission reliability by providing redundant channels, the Chopper can transmit the network flow through multiple downstreams. At the time of the transmission, chop would send each chunk through any available streams. 

Chop encrypts each chunk to offer additional security to the user. Each of these chunks is encrypted using AES in GCM mode, which guarantees both confidentiality and integrity. The unique symmetric encryption key is negotiated at the handshake of each downstream connection.

As a measure against an active probing attack, if a cover server is available and the client does not handshake using the pre-shared server passphrase, Stegotorus turns into a transparent proxy forwarding the client's communication directly to the cover server and vice versa.
  
Below are listed the specific options for controlling the *chop* protocol behaviour:

* *--passphrase*=string: Specifies the passphrase used to generate a symmetric key for encrypting the client's handshake and authenticate the client to the server. 
  
* *--enable-encryption*, *--disable-encryption*: Enables or disables the encryption of the transmitted traffic. It is enabled by default.
  
* *--minimum-noise-to-signal*=<number> defines the minimum number of bytes of the cover traffic that the chopper needs to serve in order serve a byte of user traffic. It ensures a minimum difficulty on the statistical traffic analysis to distinguish Stegotorus traffic from the cover traffic. The default value is 0. 
  
* *--enable-retransmit*, *--disable-retransmit*: enables or disables the retransmission mechanism of the chopper. Note that both client and server should agree on disabling or enabling this option. It is enabled by default.
  
* *--cover-server*=<x.y.z.w:port> Specifies a cover server. If a cover server is specified and if the client connection fails authentication, the chop turns into a transparent proxy forwarding the traffic with no modification. Content served by the cover server might be used by the Steg module as a cover content, for example in case of *http_apache* of the Steg module.
  
* *--trace-packets* enables printing the traffic content in debug log. It is only for debugging purposes and is disabled by default.
  
### Chop Steg modules

The Steg modules provide various encodings to demorph the content of the traffic observed in the traffic log. All Steg modules should specify the downstream address. This parameter should be listed immediately after the Steg module name in the command line, or determined by the down-address property in the config file, as follows:

* the *down-address* should be specified in a x.y.z.w:port format indicating the downstream destination. In client mode, it provides the address of the Stegotorus server. In the server mode, it specifies the IP address and the port on which the Stegotorus server should listen.

Here is the list of implemented Steg modules:

#### nosteg

This module does not apply encodings on the data. When the only properties of Chop are desired (e.g. randomized packet size, encryption, active probing resistance, re-transmission). If the client connections are not persistent and the adversary is dropping the connections, it can disturb the operation of Chop using nosteg Steg module.

#### nosteg_rr

This module is similar to the nosteg module, except for that it can only transmit one chunk over each connection. It can shield the client from a connection drop and ensure persistent connections when network conditions or adversaries only allow for ephemeral connection.

#### http

The http steg module encodes the user's traffic in content usually transmitted through HTTP protocol and communicates it over the HTTP protocol. The http steg module encodes the chopped data into previously recorded or fakely generated HTTP traffic chunks. 

Following is the option related to this Steg module:

* *--steg-mod*=<filetype> dictates files with which the extension can be used to encode chopped traffic inside it. The option can be used more than once to specify multiple file extensions. The supported extensions are currently: html, htm, php, jsp, asp, JS, js, PDF, pdf, SWF, swf, PNG, png, JPG, jpg, GIF, gif

### http_apache

The http_apache module is a variance of the http steg module which uses an actual HTTP client (currently curl) and an HTTP server to generate the requests and responses in which eventually encodes the chop traffic. In this way, it produces a less distinguished behavior compared to actual HTTP traffic.

In addition to the steg_mod option of the http steg module, http_apache also supports the following option:

* *--cover-list*=<file> Points to the files storing the list of the cover files on the server. At the startup Stegetorus syncs the content of the file with the server. 

## Test Deployment 

Here we offer a simple setup to test Stegotorus locally (running both client and server on the same machine) on a GNU/Linux system. Setting up Stegotorus on a different machine to communicate is substantially the same except for the use of actual Stegotorus server IP for "down-address" for both client and server instead of 127.0.0.1 as local IP.

In addition to Stegotorus, you need the following prograrms:

    openssh-server
    firefox

Let's set up the following configuration on the localhost to test Stegotorus:

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

### Setting up a local socks server

1. Make sure that the openssh server is running on your system:

        $ systemctl start ssh
        $ systemctl status ssh
    
2. In a terminal tab, ask the OpenSSH server to start a local socks proxy on port 5001:
   
        $ ssh -ND 5001 localhost
        user@localhost's password: 
   
   the command asks for your password and will get stuck there. That is the expected behavior and means your local socks server is listening on port 5001. 

### Setting up a Stegotorus server

Here, for simplicity, we start a server supporting nosteg_rr encoding as it does not depends on outer covers.

In another terminal, type:

    $ cd /path/to/stegotorus/
    $ ./stegotorus --log-min-severity=debug --timestamp-logs chop server --passphrase "correct passphrase" --trace-packets --disable-retransmit 127.0.0.1:5001 nosteg_rr 127.0.0.1:5000

### Setting up a Stegotorus client

The client should follow the same setting as the server so they can successfully communicate:

In another terminal, type:

    $ cd /path/to/stegotorus/
    $ ./stegotorus --log-min-severity=debug --timestamp-logs chop client --passphrase "correct passphrase" --trace-packets --disable-retransmit 127.0.0.1:4999 nosteg_rr 127.0.0.1:5000

### Setting up the browser proxy

Set [modify your browser's settings][Firefox proxy] to point to:

  - Set the Socks host to be `localhost` and port `4999`
    
Now you should be able to browse and observe that your traffic is passing through Stegotorus.

### Speed Test

You need to install:

* curl 

With curl, you can test the difference in the speed when your traffic passes through Stegotorus. Run the following command in a terminal:

    $ curl -x socks4://127.0.0.1:4999 http://speedtest.wdc01.softlayer.com/downloads/test500.zip -o /dev/null

### Using an existing website to provide content for Stegotorus

Let's explore the scenario where the owner of  http://mybenignwebsite.com/ likes to provide cover and help to Stegotorus users. Suppose that:

- `mybenignwebsite.com` is running on a server with an IP address 1.2.3.4.
- we run Stegotorus on a server with an IP address 5.6.7.8.

1. Assuming that OpenSSH server is installed on 5.6.7.8 server, run a local Socks server on 5.6.7.8
   
        $ ssh -ND 5001 localhost
        
2. Write a configuration file,`/path/to/stegotorus/conf/stegotorus.conf` as follows:

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

In this way, users who do not use Stegotorus will be served the actual content of mybenignwebsite.com. On the other hand, users of Stegotorus and having
the `correct passphrase` are served by the Socks server on 127.0.0.1:5001 and their data will be encoded in the mybenignwebsite.com HTTP contnet.

