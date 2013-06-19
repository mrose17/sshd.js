    var sshd = require('./sshd').sshd;

    sshd({ hostkey: './ssh_host_rsa_key', portno: 2222 }, null, function(user, service, method, params) {
      console.log('authenticator: user=[' + user + '] service=[' + service + '] method=[' + method + '] params='
                  + JSON.stringify(params));

      if ((method !== 'ssh-connection') && (method !== 'publickey')) return { failure: true, choices: [ 'publickey' ] };

      return null;
    }, null);
