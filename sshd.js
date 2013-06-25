var net           = require('net')
  , fs            = require('fs')
  , crypto        = require('crypto')
  , dh            = crypto.getDiffieHellman('modp2')
  , PacketReader  = require('./packetreader')
  , composePacket = require('./packetwriter')
  ;



/* this is an example.

   if you don't mind having logging going to the console, you don't have to override it.
 */

var DEFAULT_LOGGER = {
    'error'                : function(msg, props) { console.log(msg); console.trace(props.exception); }

  , warning                : function(msg, props) { console.log(msg); if (props) console.log(props);  }

  , notice                 : function(msg, props) { console.log(msg); if (props) console.log(props);  }

  , info                   : function(msg, props) { console.log(msg); if (props) console.log(props);  }

  , debug                  : function(msg, props) { console.log(msg); if (props) console.log(props);  }
};



/* this is an example. it will always SUCCEED authorization to the 'ssh-userauth' and 'ssh-connection' services,
    and FAIL otherwise.

   you MAY wish to define your own authorization rules in your module and pass a pointer to this module.


   here are the return values expected:

   success:   null || false || { failure: false }

   failure:   { failure: true, message: 'reason' }

 */

var DEFAULT_AUTHORIZER = {
    'ssh-userauth'         : function(service) {/* jshint unused: false */
                               return true;
                             }
  , 'ssh-connection'       : function(service) {/* jshint unused: false */
                               return true;
                             }
};



/* this is an example. it will always FAIL authentication.

   you MUST define your own authentication rules in your module and pass a pointer to this module.


   here are the return values expected:

   success:   null || false || { failure: false }

   failure:   { failure: true, choices: [ 'publickey', ... ] }

   more info: { failure: true, info: [ 'string1', ... ] }

   prompts:   { failure: true, prompts: [ { text: 'hello', lang: 'EN-US' } ] }
              or
              { failure: true, prompts: [ 'hello' ] }
 */

var DEFAULT_AUTHENTICATOR = {
    none                   : function(user, service, method, params) {/* jshint unused: false */
                               return { failure: true, choices: [ 'publickey', 'keyboard-interactive', 'password' ] };
                             }

  , 'keyboard-interactive' : function(user, service, method, params) {/* jshint unused: false */
                               return { failure: true, choices: [ 'publickey' ] };
                             }

  , password               : function(user, service, method, params) {/* jshint unused: false */
                               return { failure: true, choices: [ 'publickey' ] };
                             }

  , info                   : function(user, service, method, params) {/* jshint unused: false */
                               return { failure: true, choices: [ 'publickey' ] };
                             }

  , publickey              : function(user, service, method, params) {/* jshint unused: false */
                               return { failure: true, choices: [ 'publickey' ] };
                             }
};


/* this is an example. it will always FAIL.

   you MUST define your own channel creation rules in your module and pass a pointer to this module.

   
   when a CHANNEL_OPEN request is made, an 'open' event occurs, and the return value must be true or false.

   if a CHANNEL_REQUEST is made, a 'start' event occurs, and the return value must be true or false.
 */

var DEFAULT_CHANNELIZER = function(chan, event, params) {
  var env, handler, proc, service, type;

  params = params || {};

  switch(event) {
    case 'open':
      service = params.service;
      type = params.type;
      return true;

    case 'start':
      if (params.type === 'shell') params = { type: 'exec', program: 'nyancat' };
        handler = params.handler;
      switch (params.type) {
        case 'env':
          if (!env) env = {};
          env[params.name] = params.value;
          return true;

/*
        case 'exec':
          proc = require('child-process').spawn(params.program);
          proc.stdout.on('data', function(d) {
            handler(chan, 'data', d);
          }).setEncoding('utf8');
          proc.stderr.on('data', function(d) {
            handler(chan, 'extended', d);
          }).setEncoding('utf8');
          proc.on('exit', function(code, signal) {
            handler(chan, 'end', { code: code, signal: signal });
          });
          return true;

        case 'pty-req':
          break;
 */

        default:
          break;
      }
      return false;

    case 'eof':
    case 'close':
      if (!!proc) proc.stdin.end();
      break;

    case 'data':
      if (!!proc) proc.stdin.write(params);
      break;
  }
};

exports.sshd = function(options, authorizer, authenticator, channelizer) {
  var hostkey, hostPub, logger;

  options = options         || {};
  hostkey = options.hostkey || '/etc/ssh_host_rsa_key';
  hostPub = options.hostPub || (hostkey + '.pub');
  logger  = options.logger  || DEFAULT_LOGGER;
  channelizer = channelizer || DEFAULT_CHANNELIZER;

  hostkey = fs.readFileSync(hostkey).toString();
  hostPub = new Buffer(fs.readFileSync(hostPub).toString().split(' ')[1], 'base64');

  function signBuffer(buffer) {
    var signer = crypto.createSign('RSA-SHA1');

    signer.write(buffer);
    return composePacket(['ssh-rsa', signer.sign(hostkey)]);
  }

net.createServer(function (conn) {
  var macLen = 0, seqS = 0, seqC = 0, kex, hashIn = [], keyson = false, channels = {}, service = '';
  var session, cookie, deciph, cipher, macS, macC, user;

  var sendPay = function (payload) {
    var padLen = (16 - ((5 + payload.length) % 16)) + 16;
    var buffer = new Buffer(5 + payload.length + padLen);
    var asdff, mac;

    buffer.writeUInt32BE(payload.length + 1 + padLen, 0);
    buffer.writeUInt8(padLen, 4);
    payload.copy(buffer, 5);
    buffer.fill(0, 5 + payload.length);

    if (macLen) {
      asdff = new Buffer(4);
      asdff.writeUInt32BE(seqS, 0);
      mac = crypto.createHmac('md5', macS.slice(0, 16)); // TODO: net::ssh key_expander.rb
      mac.write(Buffer.concat([asdff,buffer]));
      mac = new Buffer(mac.digest());
    }

    logger.debug('write', { type: payload[0], length: payload.length, privacy: (!!cipher), authentication: (!!macLen) });
    if (cipher) buffer = cipher.update(buffer);
    if (macLen) buffer = Buffer.concat([buffer, mac]);
    conn.write(buffer);

    seqS += 1;
  };

  var sendPayload = function (ast) {
    sendPay(composePacket(ast));
  };

  var twentyPacket = function() {
    return [ { byte   : 20                            }
           , { raw    : cookie                        }
           , [ 'diffie-hellman-group-exchange-sha256' ] // kexAlgs
           , [ 'ssh-rsa'                              ] // hostKeyAlgs
           , [ 'aes256-ctr'                           ] // encAlgs
           , [ 'aes256-ctr'                           ] //   ..
           , [ 'hmac-md5'                             ] // macAlgs
           , [ 'hmac-md5'                             ] //   ..
           , [ 'none'                                 ] // cprAlgs
           , [ 'none'                                 ] //   ..
           , [                                        ] // langs
           , [                                        ] //   ..
           , false                                      // firstKexFollows
           , { uint32 : 0                             }
           ];
  };

  var getPacket = function (packet) {
    var type = packet.getType();
    var chan, channel, code, data, dhflags, e, i, method, msg, params, requestName, sha, wantDisplay, wantReply;

    var keyize = function (salt) {
      // TODO: dh.secret might need to be encoded for SSH
      sha = crypto.createHash('sha256');
      sha.write(Buffer.concat([ composePacket([{mpint: dh.secret}])
                              , new Buffer(session)
                              , new Buffer(salt)
                              , new Buffer(session)]));
      return sha;
    };

    var authorize = function (service) {
      var result;

      try {
        if (!!authorizer) {
          result = authorizer(service);
        } else if (!!DEFAULT_AUTHORIZER[service]) {
          result = (DEFAULT_AUTHORIZER[service])(service);
        } else {
          result = { failure: true };
        }
      } catch(ex) {
        result = { failure: true, message: ex.message };
      }

      if ((!result) || (!result.failure)) {
        return sendPayload([ { byte : 6 }                                           // SSH_MSG_SERVICE_ACCEPT
                           , service
                           ]);
      }
      sendPayload([ { byte : 1 }                                                    // SSH_MSG_SERVICE_DISCONNECT
                  , { byte : 0 }
                  , (!!result.message) ? result.message : 'unsupported service'
                  ]);
    };

    var authenticate = function (user, service, method, params) {
      var lang, message, result;

      try {
        if (!!authenticator) {
          result = authenticator(user, service, method, params);
        } else if (!!DEFAULT_AUTHENTICATOR[method]) {
          result = (DEFAULT_AUTHENTICATOR[method])(user, service, method, params);
        } else {
          result = { failure: true, choices: [ 'publickey', 'keyboard-interactive', 'password' ] };
        }
      } catch(ex) {
        result = { failure: true, prompts: [ ex.message ] };
      }

      if ((!result) || (!result.failure)) {
        return sendPayload([ { byte : 52 }]);                                       // SSH_MSG_USERAUTH_SUCCESS
      }

      if (!!result.choices) {
        return sendPayload([ { byte : 51 }                                          // SSH_MSG_USERAUTH_FAILURE
                           , result.choices
                           , false
                           ]);
      }

      if (!!result.info) {
        return sendPayload(result.info.splice(0, 0, { byte : 60 }));                // SSH_MSG_USERAUTH_INFO_REQUEST
      }

      if (!result.prompts) {
        return sendPayload([ { byte : 51 }                                          // SSH_MSG_USERAUTH_FAILURE
                           , []
                           , false
                           ]);
      }

      for (i = 0; i < result.prompts.length; i++) {
        message = result.prompts[i];
        if (typeof message === 'string') lang = 'en-US';
        else { lang = message.lang; message = message.text; }
        sendPayload([ { byte : 53 }                                                 // SSH_MSG_USERAUTH_BANNER
                    , message
                    , lang
                    ]);
      }
    };

    var channelize = function(chan, type, params) {
      var result;

      var handler = function(event, params) {
        var d, type;

        if (!channels[chan]) return;
        params = params || {};

        switch (event) {
          case 'data':
          case 'extended':
            d = params.data || '';
            type = (event === 'data') ? 94 : 95;                                    // SSH_MSG_CHANNEL_[EXTENDED_]DATA
            for ( d = d.replace(/\n/g, '\r\n'); d.length > 0; d = d.slice(50)) {
              sendPayload([ { byte   : type        }
                          , { uint32 : chan        }
                          , d.slice(0, 50)
                          ]);
            }
            break;

          case 'end':
            sendPayload([ { byte   : 98          }                                  // SSH_MSG_CHANNEL_REQUEST
                        , { uint32 : chan        }
                        , 'exit-status'
                        , false
                        , { uint32 : params.code }
                        ]);
            sendPayload([ { byte   : 97          }                                  // SSH_MSG_CHANNEL_CLOSE
                        , { uint32 : chan        }
                        ]);
            break;
        }
      };


      try {
        params.handler = handler;
        result = channelizer(chan, type, params);
      } catch(ex) {
        result = ex.message;
      }

      if (result) {
        channels[chan] = channelizer;

        return sendPayload([ { byte   : 91               }                          // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
                           , { uint32 : channel.sender   }
                           , { uint32 : channel.sender   }
                           , { uint32 : channel.initSize }
                           , { uint32 : channel.maxSize  }
                           ]);
      }
      sendPayload([ { byte   : 92   }                                               // SSH_MSG_CHANNEL_OPEN_FAILURE
                  , { uint32 : chan } ]);
    };


    logger.debug('read', { type: type, length: packet.payload.length });
    switch (type) {
// SSH_MSG_DISCONNECT
      case 1:
        code = packet.readUInt32();
        msg = packet.readString();
        logger.info('disconnect', { code: code, message: msg });
        break;

//   2 SSH_MSG_IGNORE
      case 2:
        packet.readString();
        break;

//   4 SSH_MSG_DEBUG
      case 4:
        wantDisplay = packet.readBool();
        data = { text: packet.readString()
               , lang: packet.readString()
               };
       if (wantDisplay) logger.info('debug', data); else logger.debug('debug', data);
        break;

// SSH_MSG_KEXINIT
      case 20:
        hashIn.push(packet.payload);
        hashIn.push(composePacket(twentyPacket()));
        hashIn.push(hostPub);

        kex = { cookie          :   packet.readBuffer(16)
              , kexAlgs         :   packet.readList()
              , hostKeyAlgs     :   packet.readList()
              , encAlgs         : [ packet.readList()
                                  , packet.readList()
                                  ]
              , macAlgs         : [ packet.readList()
                                  , packet.readList()
                                  ]
              , cprAlgs         : [ packet.readList()
                                  , packet.readList()
                                  ]
              , langs           : [ packet.readList()
                                  , packet.readList()
                                  ]
              , firstKexFollows :   packet.readBool()
              };
        logger.debug('kexinit', kex);
        break;

// SSH_MSG_KEX_DH_INIT (older 34)
      case 30:
        dhflags = { n : packet.readUInt32() };
        hashIn.push({ uint32 : dhflags.n });

        hashIn.push(            { mpint : dh.getPrime()   });
        hashIn.push(            { mpint : new Buffer([2]) });
        sendPay(composePacket([ { byte  : 31              }                         // SSH_MSG_KEX_DH_GEX_GROUP
                              , { mpint : dh.getPrime()   }
                              , { mpint : new Buffer([2]) }
                              ]));
        dh.generateKeys();
        break;

// SSH_MSG_KEX_DH_GEX_REQUEST
      case 34:
        dhflags = { min : packet.readUInt32()
                  , n   : packet.readUInt32()
                  , max : packet.readUInt32()
                  };
        hashIn.push({ uint32 : dhflags.min  });
        hashIn.push({ uint32 : dhflags.n    });
        hashIn.push({ uint32 : dhflags.max });

        hashIn.push(            { mpint : dh.getPrime()   });
        hashIn.push(            { mpint : new Buffer([2]) });
        sendPay(composePacket([ { byte  : 31              }                         // SSH_MSG_KEX_DH_GEX_GROUP
                              , { mpint : dh.getPrime()   }
                              , { mpint : new Buffer([2]) }
                              ]));
        dh.generateKeys();
        break;

// SSH_MSG_KEX_DH_GEX_INIT
      case 32:
        e = packet.readMpint();
        dh.secret = dh.computeSecret(e);

        hashIn.push({ mpint : e                 });
        hashIn.push({ mpint : dh.getPublicKey() });
        hashIn.push({ mpint : dh.secret         });

        sha = crypto.createHash('sha256');
        sha.write(composePacket(hashIn));
        session = sha.digest();
        sendPayload([ { byte    : 33                }
                      , hostPub
                      , { mpint : dh.getPublicKey() }
                      , signBuffer(session)
                      ]);
        break;

// SSH_MSG_NEWKEYS
      case 21:
        sendPayload([ { byte : 21 } ]);                                             // SSH_MSG_NEWKEYS
        keyson = true;

        deciph = crypto.createDecipheriv('aes-256-ctr', keyize('C').digest(), keyize('A').digest().slice(0, 16));
        cipher = crypto.createCipheriv  ('aes-256-ctr', keyize('D').digest(), keyize('B').digest().slice(0, 16));
        macC = keyize('E').digest();
        macS = keyize('F').digest();
        macLen = 16;
        break;

// SSH_MSG_SERVICE_REQUEST
      case 5:
        service = packet.readString();
        logger.debug('service', { service: service });

        authorize(service);
        break;

// SSH_MSG_USERAUTH_REQUEST
      case 50:
        user = packet.readString();
        service = packet.readString();
        method = packet.readString();
        switch (method) {
          case 'none':
            params = {};
            break;

          case 'keyboard-interactive':
            params = { lang       : packet.readString()
                     , submethods : packet.readString()
                     };
            break;

          case 'password':
            params = { signed     : packet.readBool()
                     , password   : packet.readString()
                     };
            break;

          case 'publickey':
            params = { signed     : packet.readBool()
                     , alg        : packet.readString()
                     , lob        : packet.readString()
                     };
            break;

          default:
            params = null;
            sendPayload([ { byte : 1 }                                              // SSH_MSG_SERVICE_DISCONNECT
                        , { byte : 0 }
                        , 'unsupported method'
                        ]);
            break;
        }
        logger.debug('userauth', { user: user, service: service, method: method, params: params });

        if (params) authenticate(user, service, method, params);
        break;

// SSH_MSG_USERAUTH_INFO_RESPONSE
      case 61:
        params = { count: packet.readUint32() };
        logger.debug('userauth', { user: user, service: service, method: 'info', params: params });

        authenticate(user, service, 'info', params);
        break;

// SSH_MSG_GLOBAL_REQUEST
      case 80:
        requestName = packet.readString();
        wantReply = packet.readBool();
        logger.debug('global', { requestName: requestName, wantReply: wantReply });

        if (requestName == 'keepalive@openssh.com') {
          sendPayload([ { byte : 81 } ]);                                           // SSH_MSG_REQUEST_SUCCESS
          break;
        }
        if (wantReply) sendPayload([ { byte : 82 } ]);                              // SSH_MSG_REQUEST_FAILURE
        break;

// SSH_MSG_CHANNEL_OPEN
      case 90:
        channel = { type     : packet.readString()
                  , sender   : packet.readUInt32()
                  , initSize : packet.readUInt32()
                  , maxSize  : packet.readUInt32()
                  }; // plus more
        logger.debug('channel open', channel);

        channel.service = service;
        channelize(channel.sender, 'open', channel);
        break;

// SSH_MSG_CHANNEL_EOF
      case 96:
        chan = packet.readUInt32();
        if (!!channels[chan]) (channels[chan])(chan, 'eof', null);
        break;

// SSH_MSG_CHANNEL_CLOSE
      case 97:
        chan = packet.readUInt32();
        if (!!channels[chan]) (channels[chan])(chan, 'close', null);
        break;

// SSH_MSG_CHANNEL_REQUEST
      case 98:
        chan = packet.readUInt32();
        type = packet.readString();
        wantReply = packet.readBool();
        // plus more

        switch (type) {
          case 'env':
            params = { name    : packet.readString()
                     , value   : packet.readString()
                     };
            break;

          case 'exec':
            params = { program : packet.readString() };
            break;

          case 'pty-req':
            params = { term    : packet.readString()
                     , widthC  : packet.readUInt32()
                     , heightC : packet.readUInt32()
                     , widthP  : packet.readUInt32()
                     , heightP : packet.readUInt32()
                     , modes   : packet.readString()
                     };
            break;

          case 'shell':
            params = {};
            break;

          default:
            params = null;
            break;
        }
        logger.info('channel', { chan: chan, type: type, wantReply: wantReply, params: params });

        if ((!!params) && (!!channels[chan]) && ((channels[chan])(chan, 'start', params))) {
          sendPayload([ { byte : 99 }                                               // SSH_MSG_CHANNEL_SUCCESS
                      , { uint32: chan } ]);
          break;
        }
        if (wantReply) {
          sendPayload([ { byte   : 100  }                                           // SSH_MSG_CHANNEL_FAILURE
                      , { uint32 : chan } ]);
        }
        break;

// SSH_MSG_CHANNEL_WINDOW_ADJUST
      case 93:
        packet.readUInt32();    // ignored for now....
        packet.readUInt32();    // ignored for now....
        break;

// SSH_MSG_CHANNEL_DATA
      case 94:
        chan = packet.readUInt32();
        data = packet.readString();
        if (!!channels[chan]) (channels[chan])(chan, 'data', data);
        break;

// SSH_MSG_CHANNEL_DATA
      case 95:
        chan = packet.readUInt32();
        type = packet.readUInt32();    // ignored for now....
        data = packet.readString();
        if (!!channels[chan]) (channels[chan])(chan, 'data', data);
        break;

//   0 SSH_MSG_UNKNOWN
//   3 SSH_MSG_UNIMPLEMENTED
//  32 SSH_MSG_KEX_DH_GEX_INIT
//  33 SSH_MSG_KEX_DH_GEX_REPLY
// 100 SSH_MSG_CHANNEL_FAILURE
      default:
        logger.warning('packet', { type: type, payload: packet.payload.toString() });
        sendPayload([ { byte : 1 }                                                  // SSH_MSG_SERVICE_DISCONNECT
                    , { byte : 0 }
                    , 'unsupported packet'
                    ]);
        break;
    }
  };

  logger.info('opened', { localAddress  : conn.localAddress
                        , localPort     : conn.localPort
                        , remoteAddress : conn.remoteAddress
                        , remotePort    : conn.remotePort
                        });

  var header = 'SSH-2.0-sshd.js_0.0.1 Experimental, low-security SSHd implemented in NodeJS';
  crypto.randomBytes(16, function (err, rand) {
    logger.debug('server', { header: header });
    conn.write(header + '\r\n');

    cookie = rand;
    sendPay(composePacket(twentyPacket()));
  });

  conn.on('data', function (data) {
    if (data.toString('utf-8', 0, 4) === 'SSH-') {
      var eof = data.toString().indexOf('\n');

      logger.debug('client', { header: data.toString('utf-8', 8, eof - 1) });
      hashIn.push(data.toString('utf8', 0, eof - 1));
      hashIn.push(header);
      data = data.slice(eof + 1);
    }

    while (data.length >= 4) {
      var packet = new PacketReader(data, macLen, deciph, macC, seqC);
      getPacket(packet);
      seqC += 1;
      data = data.slice(packet.totLen);
    }
  }).on('error', function (err) {
    logger.warning('error', { exception: err });
  }).on('close', function (err) {
    var chan;

    logger.warning('close', { exception: err });

    for (chan in channels) if (channels.hasOwnProperty(chan)) (channels[chan])(chan, 'close', err);
    channels = {};
  });
}).listen(options.portno || 22); };
