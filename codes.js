// at present, not used, maintained...

var SSH_MSG =        { UNKNOWN                        :   0

//   1-49 transport layer

//   1-19 transport layer generic
                     , DISCONNECT                     :   1    // uint32 SSH_DISCONNECT_xxx, string description, string language
                     , IGNORE                         :   2    // string
                     , UNIMPLEMENTED                  :   3    // -*-
                     , DEBUG                          :   4    // boolean mustDisplay, string message, string language
                     , SERVICE_REQUEST                :   5    // string serviceName
                     , SERVICE_ACCEPT                 :   6    // string serviceName

//  20-29 algorithm negotiation
                     , KEXINIT                        :  20    // cf., RFC-4253
                     , NEWKEYS                        :  21    //   ..

//  30-49 key exchange (values reused by different authentication methods)
                     , KEXDH_INIT                     :  30
                     , KEXDH_31                       :  31
                     , KEX_DH_GEX_INIT                :  32
                     , KEX_DH_GEX_REPLY               :  33
                     , KEX_DH_GEX_REQUEST             :  34


//  50-79 user authentication

//  50-59 user authentication generic
                     , USERAUTH_REQUEST               :  50    // string userName, string serviceName, string methodName, ...
/* userName, serviceName, ...

       ... 'none'

       ... 'keyboard-interactive', string lang, string submethods

       ... 'password', boolean bool changePhrase, string passPhrase [, newPhrase]
                     , USERAUTH_PASSWD_CHANGEREQ      :  60


       ... 'publickey', boolean signed, string publicKeyAlgName, string publicKeyData
                     , USERAUTH_PK_OK                 :  60
 */
                     , USERAUTH_FAILURE               :  51    // string-array list, boolean partialSuccess
                     , USERAUTH_SUCCESS               :  52    // -*-
                     , USERAUTH_BANNER                :  53    // string message, string language

//  60-79 authentication tuning (values reused by different authentication methods)
                     , USERAUTH_INFO_REQUEST          :  60
                     , USERAUTH_INFO_RESPONSE         :  61


//  80-127 connection protocol

//  80- 89 connection protocol generic
                     , GLOBAL_REQUEST                 :  80    // ascii requestName, bool wantReply, ...
                     , REQUEST_SUCCESS                :  81    // ...
                     , REQUEST_FAILURE                :  82    // -*-

//  90-127 channel-related messages
                     , CHANNEL_OPEN                   :  90    // ascii name, uint32 number, uint32 initialSize, uint32 maxSize
                     , CHANNEL_OPEN_CONFIRMATION      :  91    // uint32 number, uint32 number, uint32 initialSize, uint32 maxSize
                     , CHANNEL_OPEN_FAILURE           :  92    // uint32 number, uint32 SSH_OPEN_xxx, string description, string language
                     , CHANNEL_WINDOW_ADJUST          :  93    // uint32 number, uint32 additionalOctets
                     , CHANNEL_DATA                   :  94    // uint32 number, string data
                     , CHANNEL_EXTENDED_DATA          :  95    // uint32 number, unit32 SSH_EXTENDED_xxx, string data
                     , CHANNEL_EOF                    :  96    // uint32 number
                     , CHANNEL_CLOSE                  :  97    // uint32 number
                     , CHANNEL_REQUEST                :  98    // cf., RFC-4254
                     , CHANNEL_SUCCESS                :  99    // uint32 number
                     , CHANNEL_FAILURE                : 100    // uint32 number

// 128-191 reserved for client protocols

// 192-255 local extensions
                     };


var SSH_DISCONNECT = { UNKNOWN                        :   0
                     , HOST_NOT_ALLOWED_TO_CONNECT    :   1
                     , PROTOCOL_ERROR                 :   2
                     , KEY_EXCHANGE_FAILED            :   3
                     , RESERVED                       :   4
                     , MAC_ERROR                      :   5
                     , COMPRESSION_ERROR              :   6
                     , SERVICE_NOT_AVAILABLE          :   7
                     , PROTOCOL_VERSION_NOT_SUPPORTED :   8
                     , HOST_KEY_NOT_VERIFIABLE        :   9
                     , CONNECTION_LOST                :  10
                     , BY_APPLICATION                 :  11
                     , TOO_MANY_CONNECTIONS           :  12
                     , AUTH_CANCELLED_BY_USER         :  13
                     , NO_MORE_AUTH_METHODS_AVAILABLE :  14
                     , ILLEGAL_USER_NAME              :  15
                     };

var SSH_OPEN       = { UNKNOWN                        :   0
                     , ADMINISTRATIVELY_PROHIBITED    :   1
                     , CONNECT_FAILED                 :   2
                     , UNKNOWN_CHANNEL_TYPE           :   3
                     , RESOURCE_SHORTAGE              :   4
                     };

var SSH_EXTENDED   = { UNKNOWN                        :   0
                     , DATA_STDERR                    :   1
                     };
