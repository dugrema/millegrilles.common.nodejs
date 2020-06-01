import { solveLoginChallenge } from '@webauthn/client'

export class WebSocketManager {

  constructor() {
    this.socket = null
    this.routingKeyCallbacks = {}

    this.callbackModeProtege = null
    this.timeoutModeProtege = null
    this.disconnectHandler = null
  }

  setupWebSocket(webSocket) {
    this.socket = webSocket;

    webSocket.on('disconnect', event => {
      // console.debug("Deconnexion detectee")
      if(this.disconnectHandler) {
        this.disconnectHandler(event)
      }
    });

    webSocket.on('erreur', erreur=>{
      console.error("Erreur recue par Socket.IO");
      console.error(erreur);
    })

    return new Promise((resolve, reject)=>{
      const echecTimeout = setTimeout(()=>{
        reject({erreur: true, cause: "Timeout login Socket.IO"})
      }, 15000);

      webSocket.on('erreur.login',
        erreur => {
          console.error("Erreur connexion");
          console.error(erreur);
          clearTimeout(echecTimeout)
          reject({erreur: true, cause: erreur.erreur || erreur})
        }
      ) // erreur.login

      webSocket.on('pret', confirmation=>{
        console.debug("Message pret recu");
        console.debug(confirmation)

        // Transmettre confirmation de login
        clearTimeout(echecTimeout)
        if(confirmation.login) {
          this._setupEvenements(webSocket)
          resolve(confirmation)
        } else {
          reject({erreur: true, cause: "Login Socket.IO refuse"})
        }
      }) // Pret

    }) // Premise connexion

  }

  _setupEvenements(webSocket) {
    webSocket.on('mq_message', enveloppe=>{
      let {routingKey, message} = enveloppe;
      // console.log("MQ Message recu: " + routingKey);
      // console.log(message);
      this.traiterMessageMq(routingKey, message);
    });

    webSocket.on("challengeU2f", async (message, callback) => {
      console.debug("Message authentifier U2F")
      console.debug(message)
      try {
        const credentials = await solveLoginChallenge(message)
        callback(credentials)   // Callback du challenge via websocket
      } catch(err) {
        console.error("Erreur challenge reply")
        console.error(err)
      }
    })

    webSocket.on("confirmationModeProtege", confirmation => {
      console.debug("Mode protege active : %s", confirmation.actif)
      this.callbackModeProtege(confirmation.actif)
    })
  }

  deconnecter() {
    console.debug("Deconnecter socket.io")
    if(this.socket != null) {
      this.socket.disconnect()
      this.socket = null
    }
  }

  getWebSocket() {
    return this.socket;
  }

  subscribe(routingKeys, callback) {
    // Transmet une liste de routingKeys a enregistrer sur notre Q.
    this.socket.emit('subscribe', routingKeys);

    for(var key_id in routingKeys) {
      let routingKey = routingKeys[key_id];

      var dictCallback = this.routingKeyCallbacks[routingKey];
      if(!dictCallback) {
        this.routingKeyCallbacks[routingKey] = callback;
      } else {
        console.warn("Changement de callback pour " + routingKey);
        this.routingKeyCallbacks[routingKey] = callback;
      }
    }
  }

  unsubscribe(routingKeys, callback) {
    // Transmet une liste de routingKeys a retirer de la Q cote serveur.
    this.socket.emit('unsubscribe', routingKeys);

    for(var key_id in routingKeys) {
      let routingKey = routingKeys[key_id];
      delete this.routingKeyCallbacks[routingKey];
    }

  }

  transmettreRequete(domaineAction, requete, opts) {
    if(!opts) opts = {};

    // Transmet une requete. Retourne une Promise pour recuperer la reponse.
    let socket = this.socket;
    let promise = new Promise((resolve, reject) => {
      let enveloppe = {
        domaineAction,
        'requete': requete,
        opts
      };

      // Transmettre requete
      socket.emit('requete', enveloppe, reponse=>{
        if(!reponse) {
          console.error("Erreur survenue durant requete vers " + domaineAction);
          reject();
          return;
        }
        console.log("Reponse dans websocket pour requete");
        console.log(reponse);
        resolve(reponse);
        return reponse;
      });
    });

    return promise;
  }

  transmettreCommande(routingKey, commande, opts) {
    // Transmet une commande. Retourne une Promise pour recuperer la reponse.
    if(!opts) opts = {};

    let socket = this.socket;
    let promise = new Promise((resolve, reject) => {
      let enveloppe = {
        'routingKey': routingKey,
        'commande': commande
      };

      // Transmettre requete
      let reponseFunction;

      if(!opts.nowait) {

        reponseFunction = reponse=>{
          if(!reponse) {
            console.error("Erreur survenue durant commande vers " + routingKey);
            reject();
            return;
          }
          // console.log("Reponse dans websocket pour requete");
          // console.log(reponse);
          resolve(reponse);
          return reponse;
        };

      }
      socket.emit('commande', enveloppe, reponseFunction);
    });

    return promise;
  }

  transmettreTransaction(routingKey, transaction, opts) {
    let socket = this.socket;
    let promise = new Promise((resolve, reject) => {
      let enveloppe = {routingKey, transaction};
      if(opts) {
        enveloppe['opts'] = opts
      }

      // Transmettre requete
      socket.emit('transaction', enveloppe, reponse=>{
        if(!reponse) {
          reject(new Error("Erreur survenue durant transaction vers " + routingKey));
          return;
        }
        // console.log("Reponse dans websocket pour requete");
        // console.log(reponse);
        resolve(reponse);
      });
    });

    return promise;
  }

  // Transmet une cle au maitredescles
  transmettreCle(domaine, correlation, identificateursDocument, cleChiffree, iv, fingerprint) {
    const routingKeyCle = 'millegrilles.domaines.MaitreDesCles.nouvelleCle.document';
    let transactionCle = {
      fingerprint: fingerprint,
      cle: cleChiffree,
      iv: iv,
      domaine,
      "identificateurs_document": identificateursDocument,
      'uuid-transaction': correlation,
    };

    return this.transmettreTransaction(routingKeyCle, transactionCle);
  }

  traiterMessageMq(routingKey, message) {
    let callback = this.routingKeyCallbacks[routingKey];
    if(callback) {
      callback(routingKey, message);
    }
  }

  demanderTokenTransfert() {
    return this.emit('creerTokenTransfert', {'token': true});
    // let promise = new Promise((resolve, reject)=>{
    //   this.socket.emit('creerTokenTransfert', {'token': true}, reponse=>{
    //     // console.debug("Transmission token " + reponse);
    //     resolve(reponse);
    //   });
    // });
    //
    // return promise;
  }

  emit(eventType, content) {
    let promise = new Promise((resolve, reject)=>{

      var timeoutReponse = setTimeout(function () {
        reject(new Error("Timeout " + eventType));
      }, 10000);

      this.socket.emit(eventType, content, reponse=>{
        clearTimeout(timeoutReponse);  // Annuler timeout

        if(!reponse) {
          reject(new Error("Erreur survenue durant emit " + eventType));
          return;
        }
        resolve(reponse);
      });
    });

    return promise;
  }

  emitWEventCallback(eventType, content, eventTypeCallback) {
    // Methode qui simule la reception d'un callback en emettant un
    // evenement puis en ecoutant sur un nouveau type (socket.on(...))

    let promise = new Promise((resolve, reject) => {
      var socket = this.socket;

      // Creation d'un timeout pour faire le clreanup.
      var timeoutHandler = setTimeout(function () {
        socket.removeListener(eventTypeCallback);
        reject(new Error("Timeout " + eventType));
      }, 15000);

      // Activer le listener.
      socket.on(eventTypeCallback, (event, cb)=>{
        console.debug("Event recu " + eventTypeCallback);
        console.debug(event);

        // Cleanup
        clearTimeout(timeoutHandler);
        socket.removeListener(eventTypeCallback);

        resolve([event, cb]);
      });

      // Emettre l'evenement declencheur.
      socket.emit(eventType, content);
    });

    return promise;
  }

  uploadFichier(uploadInfo) {
    return this.uploadFichierManager.uploadFichier(this.socket, uploadInfo);
  }

  demandeActiverModeProtege() {
    if(!this.timeoutModeProtege) {
      console.debug("WebsocketManagerCoupdoeil : Demande activation mode protege")
      this.socket.emit("activerModeProtege")
      this.timeoutModeProtege = setTimeout(() => {this.clearTimeoutModeProtege()}, 5000)

      return new Promise((resolve, reject) => {
        this.callbackModeProtege = (resultat) => {
          console.debug("Callback : %s", resultat)

          // Nettoyage
          this.callbackModeProtege = null
          this.clearTimeoutModeProtege()

          if(resultat) {
            resolve()
          } else {
            reject()
          }
        }
      })
    }

    throw new Error("Demande deja faite")
  }

  clearTimeoutModeProtege() {
    console.debug("Clear timeout")
    try {
      if(this.timeoutModeProtege) {
        clearTimeout(this.timeoutModeProtege)
      }
      if(this.callbackModeProtege) {
        this.callbackModeProtege(false)
      }
    } catch(err) {
      console.error("Erreur nettoyage timeout mode protege")
    }

    this.callbackModeProtege = null
    this.timeoutModeProtege = null
  }

  desactiverModeProtege() {
    console.debug("Desactiver mode protege")
    this.socket.emit("desactiverModeProtege")
  }


}
