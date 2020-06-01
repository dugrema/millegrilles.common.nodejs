var fs = require('fs');
// var {SocketIoUpload} = require('../routes/res/SocketioUpload');
const debug = require('debug')('millegrilles:coupdoeil:websocketsapp')

// var sessionManagement = require('./routes/res/sessionManagement');
// var pki = require('./routes/res/pki');
// var rabbitMQ = require('./routes/res/rabbitMQ');

const {
    generateRegistrationChallenge,
    parseRegisterRequest,
    generateLoginChallenge,
    parseLoginRequest,
    verifyAuthenticatorAssertion,
} = require('@webauthn/server');

class WebSocketResources {
  // Classe utilisee pour conserver les references vers les ressources privees
  // d'une connexion websocket (e.g. channel MQ, reply_Q).

  constructor(socket) {
    this.socket = socket;

    this.mqChannel = null;
    this.reply_q = null;
    this.expiration = (new Date()).getTime()+120000; // 2 minutes pour socket connect
  }

  close() {
    if(this.mqChannel) {
      try {
        if(this.reply_q) {
          // console.debug("Delete reply Q pour socket " + this.socket.id);
          this.mqChannel.deleteQueue(this.reply_q.queue).catch(err=>{});
        }
      } finally {
        // console.debug("Fermeture channel MQ pour socket " + this.socket.id);
        this.mqChannel.close().catch(err=>{});
      }

    }
  }

}

class WebSocketApp {

  constructor(sessionManagement) {
    // this.rabbitMQ = rabbitMQ;
    // this.pki = pki;
    this.sessionManagement = sessionManagement;

    this.new_sockets = {};
    this.authenticated_sockets = {};

    setInterval(()=>{
      this.cleanNew();
    }, 5000);

    setInterval(()=>{
      this.cleanDisconnected();
    }, 60000);

    // this.rabbitMQ.routingKeyManager.setWebSocketsManager(this); // Permet transmettre incoming msg
  }

  cleanNew() {
    // Nettoyage des sockets nouveaux connectes qui ne sont pas authentifies
    // Limite le temps permis pour authentifier
    let tempsCourant = (new Date()).getTime();
    for(var socket_id in this.new_sockets) {
      let socketResources = this.new_sockets[socket_id];

      let socket = socketResources.socket;
      if(socketResources.expiration < tempsCourant){
        // console.debug("On deconnecte un socket pas authentifie expire: " + socket_id);
        socket.disconnect();
      }

      if(socket.disconnected) {
        // console.debug("Nettoyage socket pas authentifie: " + socket_id);
        socketResources.close();
        delete this.new_sockets[socket_id];
      }
    }
  }

  cleanDisconnected() {
    // Housekeeping, normalement l'evenement disconnect du socket va
    // declencher la suppression du socket.
    for(var socket_id in this.authenticated_sockets) {
      let socketResources = this.authenticated_sockets[socket_id];
      if(socketResources.socket.disconnected) {
        socketResources.close();
        delete this.authenticated_sockets[socket_id];
      }
    }
  }

  disconnectedHandler(socket) {
    // console.debug("Socket deconnecte " + socket.id);

    let socketResources = this.new_sockets[socket.id] || this.authenticated_sockets[socket.id];
    if(socketResources) {
      socketResources.close();
    }

    delete this.new_sockets[socket.id];
    delete this.authenticated_sockets[socket.id];
  }

  // Methode utiliser pour ajouter une nouvelle connexion a partir de Socket.IO (listener)
  // L'authentification securitaire de l'usager est la premier action de addSocket.
  addSocket(socket) {
    debug("Socket connecte")
    debug(socket.request.headers)

    const estProprietaire = socket.request.headers['est-proprietaire']
    const idmgClient = socket.request.headers['idmg']

    // Ajoute un socket d'une nouvelle connexion
    // console.debug("Nouveau socket!");
    if(!estProprietaire) {
      console.error("Usager n'est pas proprietaire de la millegrille sur socket " + socket.id + ", on le ferme.");
      socket.disconnect();
      delete this.new_sockets[socket.id];
    } else if(!socket.disconnected) {
      let socketResources = new WebSocketResources(socket);

      // S'assure que le socket n'a pas ete deconnecte avant d'ajouter
      // l'evenement de gestion du disconnect
      socket.on('disconnect', ()=>{
        this.disconnectedHandler(socket);
      });
      this.new_sockets[socket.id] = socketResources;

      // Ouvrir Channel MQ
      // console.debug("Debut de l'authentification");
      var rabbitMQ_local = null;
      this.sessionManagement.addSocketConnection(socket)
      .then(rabbitMQ=>{
        if(!rabbitMQ) {
          throw new Error("Idmg inconnu");
        }
        rabbitMQ_local = rabbitMQ;

        const idmg = rabbitMQ.pki.idmg;
        debug("Authentification est completee, idmg: %s", idmg);

        return rabbitMQ.createChannel(socketResources);
      })
      .then(()=>{
        this.saveAuthenticated(socketResources);
        this.registerEvents(rabbitMQ_local, socketResources);
      }).catch(err=>{
        console.error("Erreur traitement socket " + socket.id + ", on le ferme.");
        console.error(err);
        socketResources.close();
        socket.disconnect();
        delete this.new_sockets[socket.id];
      });  // Attache evements auth
    }

  }

  saveAuthenticated(socketResources) {
    let socket = socketResources.socket;
    this.authenticated_sockets[socket.id] = socketResources;
    delete this.new_sockets[socket.id];
    console.debug("Moved socket " + socket.id + " from new_sockets to authenticated_sockets");
  }

  registerEvents(rabbitMQ, socketResources) {
    // Enregistre tous les evenements transmis par le front-end coupdoeil.
    // registerDocument: Enregistrer nouvelle routingKey pour le socket
    // unregisterDocument: Retirer routingKey pour socket
    // requete: Executer une requete
    let socket = socketResources.socket;
    let channel = socketResources.mqChannel;
    let reply_q = socketResources.reply_q;

    // Enregistrer evenements upload
    // new SocketIoUpload(rabbitMQ, rabbitMQ.pki).enregistrer(socket);

    socket.on('subscribe', message => {
      rabbitMQ.routingKeyManager
        .addRoutingKeysForSocket(socket, message, channel, reply_q);
    });

    socket.on('unsubscribe', message => {
      // console.debug("Message unsubscribe");
      // console.debug(message);
      rabbitMQ.routingKeyManager
        .removeRoutingKeysForSocket(socket, message, channel, reply_q);
    });

    socket.on('requete', (enveloppe, cb) => {
      console.debug("Enveloppe de requete recue");
      console.debug(enveloppe);
      const domaineAction = enveloppe.domaineAction;
      const requete = enveloppe.requete;
      const opts = enveloppe.opts || {};

      rabbitMQ.transmettreRequete(domaineAction, requete)
      .then( reponse => {
        if(reponse.resultats) {
          cb(reponse.resultats); // On transmet juste les resultats
        } else {
          // C'est une reponse custom
          cb(reponse);
        }

      })
      .catch( err => {
        console.error("Erreur requete");
        console.error(err);
        cb(); // Callback sans valeurs
      });
    });

    socket.on('creerTokenTransfert', (message, cb) => {
      let token = this.sessionManagement.createTokenTransfert(rabbitMQ.pki.idmg);
      if(cb) {
        cb(token); // Renvoit le token pour amorcer le transfert via PUT
      }
    });

    socket.on('creerPINTemporaireDevice', (message, cb) => {
      let pin = this.sessionManagement.createPinTemporaireDevice(rabbitMQ.pki.idmg);
      if(cb) {
        cb({pin: pin});
      }
    })

    socket.on('enregistrerDevice', (message)=> {
      // Declenche l'ajout d'un nouveau device d'Authentification

      // La requete est faite par websocket, l'usager est deja authentifie alors
      // aucune verification supplementaire n'est faite (note: on pourrait re-demander l'authentification)
      // Envoyer le challenge et utiliser callback pour recevoir la confirmation
      // Transmettre le challenge
      const challengeResponse = generateRegistrationChallenge({
          relyingParty: { name: 'coupdoeil' },
          user: { id: 'usager', name: 'usager' }
      });
      var challenge_conserve = challengeResponse.challenge;

      socket.emit('challengeEnregistrerDevice', challengeResponse, (reponse)=>{
        const { key, challenge } = parseRegisterRequest(reponse);

        // console.debug("Parsed: key, challenge de nouveau device");

        var infoToken = {
            'cle': key
        }

        // Tout est correct, on transmet le nouveau token en transaction
        rabbitMQ.transmettreTransactionFormattee(
            infoToken, 'Principale.ajouterToken')
          .then( msg => {
            // console.debug("Recu confirmation d'ajout de device'");
            // console.debug(msg);
          })
          .catch( err => {
            console.error("Erreur message");
            console.error(err);
          });
      });

    });

    socket.on('demandeClePubliqueMaitredescles', (msg, cb) => {
      this.extraireClePubliqueMaitredescles(rabbitMQ).then(clePublique=>{
        cb(clePublique);
      });
    });

    socket.on('activerModeProtege', async () => {
      const actif = await this.sessionManagement.creerChallengeUSB(rabbitMQ, socket)

      socket.modeProtege = actif
      if(actif) {
        // Connecte les operations protegees au socket

        // Expose l'appel aux transactions MQ.
        socket.on('transaction', (message, cb) => {this.traiterTransaction(rabbitMQ, message, cb)})
        socket.on('commande', (message, cb) => {this.traiterCommande(rabbitMQ, message, cb)})
      } else {

      }
    })

    socket.on('desactiverModeProtege', async () => {
      console.debug("Desactiver le mode protege")
      socket.modeProtege = false

      // Desactiver listeners disponibles uniquement dans le mode protege
      socket.removeAllListeners('transaction')
      socket.removeAllListeners('commande')
    })

  }

  traiterTransaction(rabbitMQ, message, cb) {
    // console.log("Message");
    // console.log(message);
    let routingKey = message.routingKey;
    let transaction = message.transaction;
    let opts = message.opts;
    rabbitMQ.transmettreTransactionFormattee(
      transaction, routingKey, opts
    ).then(messageReponse=>{
      cb(messageReponse);
    }).catch(err =>{
      console.error("Erreur transmission transaction");
      console.error(err);
      cb({'err': err.toString()});
    })
  }

  traiterCommande(rabbitMQ, enveloppe, cb) {
    // console.debug("Enveloppe de commande recue");
    // console.debug(enveloppe);
    let routingKey = enveloppe.routingKey;
    let commande = enveloppe.commande;
    let nowait = !cb;

    rabbitMQ.transmettreCommande(routingKey, commande, {nowait})
      .then( reponse => {
        if(reponse) {
          if(cb) {
            cb(reponse.resultats || reponse); // On transmet juste les resultats
          }
        } else {
          if(!nowait) {
            console.error("Erreur reception reponse commande " + routingKey);
          }
        }
      })
      .catch( err => {
        console.error("Erreur commande");
        console.error(err);
        if(cb) {
          cb(); // Callback sans valeurs
        }
      });
  }

  extraireClePubliqueMaitredescles(rabbitMQ) {
    return rabbitMQ.demanderCertificatMaitreDesCles()
    .then(certificat=>{
      // console.debug("Certificat maitredescles");
      // console.debug(certificat);

      const infoCertificat = rabbitMQ.pki.extraireClePubliqueFingerprint(certificat);

      // console.debug(infoCertificat);

      // Enlever le wrapping pour faciliter l'usage pour le navigateur
      return infoCertificat;
    })
  }


}

//const websocketapp = new WebSocketApp();

module.exports = {WebSocketApp};
