/*
  Wrapper pour amqplib qui ajoute les fonctionnalites pour
  interaction avec MilleGrilles.
 */

const debug = require('debug')('millegrilles:common:amqpdao')
var amqplib = require('amqplib');
var os = require('os');
var fs = require('fs');
var {v4: uuidv4} = require('uuid');

const MG_EXCHANGE_PROTEGE = '3.protege'
const ROUTING_CERTIFICAT = 'requete.certificat'
const MG_ROUTING_EMETTRE_CERTIFICAT = 'evenement.Pki.infoCertificat'
const routingKeyNouvelleTransaction = 'transaction.nouvelle'

class MilleGrillesAmqpDAO {

  constructor(pki, opts) {
    this.pki = pki;
    if(!opts) opts = {}

    this.url = null;
    this.connection = null;
    this.channel = null;
    this.reply_q = null;
    this.consumerTag = null;
    this.exchange = opts.exchange || MG_EXCHANGE_PROTEGE

    // Creer Q que reception separee pour les operations longues
    // comme transcodage, archivage, creation torrents, etc
    this.qOperationLongue = null;
    this.consumerTagOperationLongue = null;

    this.compteurMessages = 0;

    this.reconnectTimeout = null; // Timer de reconnexion - null si inactif

    // Correlation avec les reponses en attente.
    // Cle: uuid de CorrelationId
    // Valeur: callback
    this.pendingResponses = {};

    this.routingKeyManager = new RoutingKeyManager(this, opts);
    this.routingKeyCertificat = null;

    this.connexionListeners = [];  // Listeners a appeler lors de la connexion

    // Conserver une liste de certificats connus, permet d'eviter la
    // sauvegarder redondante du meme certificat
    this.certificatsConnus = {};
  }

  connect(url) {
    this.url = url + "/" + this.pki.idmg;
    return this._connect();
  }

  _connect() {

    if(this.connection === null) {
      let options = {
        ca: this.pki.hoteCA,
        cert: this.pki.hotePEM,
        key: this.pki.cle,
      }
      options['credentials'] = amqplib.credentials.external();

      debug("Connecter a RabbitMQ : %s", this.url);
      return amqplib.connect(this.url, options)
      .then( conn => {
        console.info(new Date() + " Connexion a RabbitMQ reussie");
        this.connection = conn;

        conn.on('close', (reason)=>{
          console.warn(new Date() + " Fermeture connexion RabbitMQ");
          console.warn(reason);
          this.scheduleReconnect();
        });

        return conn.createChannel();
      }).then( (ch) => {
        this.channel = ch;
        return this.ecouter();
      }).then(()=>{
        console.info(new Date() + " Connexion et channel prets");

        // Transmettre le certificat
        let fingerprint = this.transmettreCertificat();

        // Enregistrer routing key du certificat
        // Permet de repondre si un autre composant demande notre certificat
        this.routingKeyCertificat = ROUTING_CERTIFICAT + '.' + fingerprint;
        console.info(new Date() + " Enregistrer routing key: %s", this.routingKeyCertificat)
        this.channel.bindQueue(this.reply_q.queue, this.exchange, this.routingKeyCertificat);
        this.channel.bindQueue(this.reply_q.queue, this.exchange, MG_ROUTING_EMETTRE_CERTIFICAT);
      }).catch(err => {
        this.connection = null;
        console.error("Erreur connexion RabbitMQ");
        console.error(err);
        this.scheduleReconnect();
      });

    }

  }

  scheduleReconnect() {
    // Met un timer pour se reconnecter
    const dureeAttente = 30;

    if(!this.reconnectTimeout) {
      var mq = this;
      this.reconnectTimeout = setTimeout(()=>{
        console.info(new Date() + " Reconnexion en cours");
        mq.reconnectTimeout = null;
        mq._connect();
      }, dureeAttente*1000);

      console.info(new Date() + " Reconnexion a MQ dans " + dureeAttente + " secondes");

      var conn = this.connection, channel = this.channel;
      this.connection = null;
      this.channel = null;

      if(channel) {
        try {
          channel.close();
        } catch (err) {
          debug("Erreur fermeture channel");
          // debug(err);
        }
      }

      if(this.connection) {
        try {
          conn.close();
        } catch (err) {
          console.warn("Erreur fermeture connection");
          console.info(err);
        }
      }
    }
  }

  ecouter() {
    var compteurMessages = 0;

    let promise = new Promise((resolve, reject) => {

      // Creer Q pour ecouter
      this.channel.assertQueue('', {
        durable: false,
        exclusive: true,
      })
      .then( (q) => {
        debug("Queue cree"),
        debug(q);
        this.reply_q = q;

        return this.channel.assertQueue('', {
          durable: false,
          exclusive: true,
        })
      })
      .then( (q) => {
        debug("Queue operations longues cree"),
        debug(q);
        this.qOperationLongue = q;

        // Appeler listeners de connexion
        for(let idx in this.connexionListeners) {
          let listener = this.connexionListeners[idx];
          listener.on_connecter();
        }

        const routingKeyManager = this.routingKeyManager;

        this._consume();

        resolve();
      })
      .catch( err => {
        console.error(new Date() + " Erreur creation Q pour ecouter");
        reject(err);
      })
    });

    return promise;

  }

  createChannel(socketResources) {
    return this.connection.createChannel()
      .then(channel=>{
        socketResources.mqChannel = channel;
        return channel.assertQueue('', {
          durable: false,
          exclusive: true,
        })
      })
      .then(q=>{
        debug("Queue reponse usager via websocket cree %s", q.queue);
        socketResources.reply_q = q;

        // Activer la lecture de message et callback pour notre websocket
        socketResources.mqChannel.consume(
          q.queue,
          (msg) => {
            debug('2. Message recu');
            let messageContent = msg.content.toString('utf-8');
            let json_message = JSON.parse(messageContent);
            let routingKey = msg.fields.routingKey;

            let socket = socketResources.socket;
            socket.emit('mq_message', {routingKey: routingKey, message: json_message});
          },
          {noAck: true}
        );
      });
  }

  _consume() {
    return this.channel.consume(
      this.reply_q.queue,
      async (msg) => {this._traiterMessage(msg)},
      {noAck: true}
    ).then(tag=>{
      // debug("Consumer Tag ");
      // debug(tag);
      this.consumerTag = tag.consumerTag;

      return this.channel.consume(
        this.qOperationLongue.queue,
        (msg) => {this._traiterMessageOperationLongue(msg)},
        {noAck: false}
      );
    })
    .then(tag=>{
      this.consumerTagOperationLongue = tag.consumerTag;
    });
  }

  async _traiterMessageOperationLongue(msg) {
    var consumerTag = this.consumerTagOperationLongue;
    this.consumerTagOperationLongue = null;

    if(consumerTag) {
      // debug("Operation longue");
      // debug(consumerTag);

      try {
        // Traiter tous les messages dans la Q, un a la fois
        // Ne pas utiliser le consumer, il ne permet pas le controle fin.
        await this.channel.cancel(consumerTag);
        while(msg) {
          try {
            // debug("Debut traiter message operation longue");
            await this._traiterMessage(msg);
            // debug("Fin traitement message operation longue")
          } catch (err) {
            // Le traitement du message n'a pas fonctionne, mais on le fait passer quand meme
            // avec ACK dans finally pour eviter de bloquer.
            console.error(new Date() + " Erreur traitement message");
            console.error(err);
          } finally {
            this.channel.ack(msg);
          }

          // Tenter d'aller chercher un autre message
          // Traite un message a la fois
          msg = await this.channel.get(this.qOperationLongue.queue, {noAck: false});
          // debug("Message operation longue suivant")
          // debug(msg);
        }
      } finally {
        // Recommencer a ecouter les evenements
        var nouveauTag = await this.channel.consume(
          this.qOperationLongue.queue,
          async (msg) => {await this._traiterMessageOperationLongue(msg)},
          {noAck: false}
        );
        this.consumerTagOperationLongue = nouveauTag.consumerTag;
      }

      // debug("Fin operation longue");
    } else {
      console.error(new Date() + " Message operation longue recu durant traitement, NACK vers la Q");
      // Remettre le message sur la Q avec un nack
      this.channel.nack(msg);
    }
  }

  async _traiterMessage(msg) {
    // const noMessage = this.compteurMessages;
    // this.compteurMessages = noMessage + 1;

    // debug("Message recu " + noMessage);
    let correlationId = msg.properties.correlationId;
    let callback = this.pendingResponses[correlationId];
    if(callback) {
      delete this.pendingResponses[correlationId];
    }

    // let messageContent = decodeURIComponent(escape(msg.content));
    let messageContent = msg.content.toString();
    let routingKey = msg.fields.routingKey;
    let json_message = JSON.parse(messageContent);
    // debug(json_message);

    if(routingKey && routingKey.startsWith(MG_ROUTING_EMETTRE_CERTIFICAT)) {
      // Sauvegarder le certificat localement pour usage futur
      this.pki.sauvegarderMessageCertificat(messageContent, json_message.fingerprint);
      return; // Ce message ne correspond pas au format standard
    } else if(routingKey && routingKey.startsWith(ROUTING_CERTIFICAT)) {
      // Retransmettre notre certificat
      this.transmettreCertificat(msg.properties)
    }

    // Valider le contenu du message - hachage et signature
    let hashTransactionCalcule = this.pki.hacherTransaction(json_message);
    const entete = json_message['en-tete'];
    if(entete) {
      let hashTransactionRecu = entete['hachage-contenu'];
      if(hashTransactionCalcule !== hashTransactionRecu) {
        debug("Erreur hachage incorrect : " + hashTransactionCalcule + ", message dropped");
        return;
      }
    } else {
      debug("Reponse sans entete");
      debug(json_message);
    }

    return this.pki.verifierSignatureMessage(json_message)
    .then(signatureValide=>{
      if(signatureValide) {
        return this.traiterMessageValide(json_message, msg, callback);
      } else {
        // Cleanup au besoin
        delete this.pendingResponses[correlationId];
      }
    })
    .catch(err=>{
      if(err.inconnu) {
        // Message inconnu, on va verifier si c'est une reponse de
        // certificat.
        if(json_message.resultats && json_message.resultats.certificat_pem) {
          // On laisse le message passer, c'est un certificat
          // debug("Certificat recu");
          callback(msg);
        } else {
          // On tente de charger le certificat
          let fingerprint = json_message['en-tete'].certificat;
          debug("Certificat inconnu, on fait une demande : " + fingerprint);

          return this.demanderCertificat(fingerprint)
          .then(reponse=>{
            // debug("Reponse demande certificat " + fingerprint);
            // debug(reponse);

            var etatCertificat = this.certificatsConnus[fingerprint];

            if(!etatCertificat) {

              // Creer un placeholder pour messages en attente sur ce
              // certificat.
              etatCertificat = {
                reponse: reponse.resultats,
                certificatSauvegarde: false,
                callbacks: [],
                timer: setTimeout(()=>{
                  debug("Timeout traitement certificat " + fingerprint);
                  // Supprimer attente, va essayer a nouveau plus tard
                  delete this.certificatsConnus[fingerprint];
                }, 10000),
              }

              this.certificatsConnus[fingerprint] = etatCertificat;

              // Sauvegarder le certificat et tenter de valider le message en attente
              this.pki.sauvegarderMessageCertificat(JSON.stringify(reponse.resultats))
              .then(()=>this.pki.verifierSignatureMessage(json_message))
              .then(signatureValide=>{
                if(signatureValide) {
                  return this.traiterMessageValide(json_message, msg, callback);
                  clearTimeout(etatCertificat.timer);

                  etatCertificat.certificatSauvegarde = true;

                  while(etatCertificat.callbacks.length > 0) {
                    const callbackMessage = this.certificatsConnus[fingerprint].callbacks.pop();
                    try {
                      // debug("Callback apres reception certificat " + fingerprint);
                      callbackMessage();
                    } catch (err) {
                      debug("Erreur callback certificat " + fingerprint);
                      debug(err)
                    }
                  }

                  // Cleanup memoire
                  this.certificatsConnus[fingerprint] = {certificatSauvegarde: true};

                } else {
                  debug("Signature invalide, message dropped");
                }
              })
              .catch(err=>{
                debug("Message non valide apres reception du certificat, message dropped");
                debug(err);
              });

            } else {

              if(etatCertificat.certificatSauvegarde) {
                return this.traiterMessageValide(json_message, msg, callback);
              } else {
                // Inserer callback a executer lors de la reception du certificat
                etatCertificat.callbacks.push(
                  () => {return this.traiterMessageValide(json_message, msg, callback);}
                );
              }
            };

          })
          .catch(err=>{
            debug("Certificat non charge, message dropped");
            debug(err);
          })
        }
      }
    });
  }

  traiterMessageValide(json_message, msg, callback) {
    let routingKey = msg.fields.routingKey;
    if(callback) {
      callback(json_message);
    } else if(routingKey) {
      // Traiter le message via handlers
      return this.routingKeyManager.handleMessage(routingKey, msg.content, msg.properties);
    } else {
      console.warn("Recu message sans correlation Id ou routing key");
      console.warn(msg);
    }

  }

  enregistrerListenerConnexion(listener) {
    this.connexionListeners.push(listener);
    if(this.channel) {
      // La connexion existe deja, on force l'execution de l'evenement.
      listener.on_connecter();
    }
  }

  // Utiliser cette methode pour simplifier le formattage d'une transaction.
  // Il faut fournir le contenu de la transaction et le domaine (routing)
  transmettreTransactionFormattee(message, domaine, opts) {
    if(!opts) opts = {};

    // Fare un shallow copy du message
    let messageFormatte = {};
    Object.assign(messageFormatte, message);

    const infoTransaction = this._formatterInfoTransaction(domaine, opts);
    const correlation = infoTransaction['uuid-transaction'];
    messageFormatte['en-tete'] = infoTransaction;

    // Crypter le contenu au besoin
    let promise;
    if(messageFormatte['a_crypter']) {
      // Enlever element a_cypter de la transaction principale
      let contenuACrypter = messageFormatte['a_crypter'];
      delete messageFormatte['a_crypter'];
      let idDocumentCrypte = opts.idDocumentCrypte;
      promise = this._transmettreMessageCle(contenuACrypter, correlation, idDocumentCrypte)
      .then(contenuCrypte=>{
        messageFormatte['crypte'] = contenuCrypte;
        return messageFormatte;
      })
    } else {
      promise = new Promise((resolve, reject)=>{resolve(messageFormatte)});
    }

    // Utiliser la promise pour recuperer le contenu du message
    // Si le message contient un element 'a_crypter', il sera remplace
    // par crypte='... contenu base64 ...'.
    return promise.then(messageATransmettre=>{
      // Signer le message avec le certificat
      this._signerMessage(messageATransmettre);
      const jsonMessage = JSON.stringify(messageATransmettre);

      // Transmettre la nouvelle transaction. La promise permet de traiter
      // le message de reponse.
      const routingKey = 'transaction.' + domaine;
      return this._transmettre(routingKey, jsonMessage, correlation);
    })

  }

  _transmettreMessageCle(contenuACrypter, correlation, idDocumentCrypte) {
    let promise = this.demanderCertificatMaitreDesCles()
    .then(certificat=>this.pki.crypterContenu(certificat, contenuACrypter))
    .then(({contenuCrypte, encryptedSecretKey, iv})=>{
      // Transmettre transaction pour la cle
      // Le ma
      const routingKeyCle = 'MaitreDesCles.nouvelleCleDocument';
      let infoTransactionCle = this._formatterInfoTransaction(routingKeyCle, {version: 5});
      let transactionCle = {
        'en-tete': infoTransactionCle,
        fingerprint: 'abcd',
        cle: encryptedSecretKey,
        iv: iv,
        domaine: idDocumentCrypte.domaine,
        'uuid-transaction': correlation,
      };

      // Copier les cles du document dans la transaction
      // domaine: transmis dans idDocumentCrypte, e.g. "millegrilles.domaines.Parametres",
      // uuid-transaction: param correlation
      // identificateurs_document: {
      //     "_mg-libelle": ConstantesParametres.LIBVAL_EMAIL_SMTP
      // },
      let id_document = {};
      for(let key in idDocumentCrypte) {
        let value = idDocumentCrypte[key];
        if(key !== 'domaine') {  // Domaine copie en dehors de l'identificateur, V5 transaction
          id_document[key] = value;
        }
      }
      transactionCle['identificateurs_document'] = id_document

      // Signer le message avec le certificat
      this._signerMessage(transactionCle);
      const jsonMessageCle = JSON.stringify(transactionCle);

      // Transmettre la nouvelle transaction. La promise permet de traiter
      // le message de reponse.
      let correlationCle = infoTransactionCle['uuid-transaction'];

      return this._transmettre(routingKeyNouvelleTransaction, jsonMessageCle, correlationCle)
      .then(()=>{
        return contenuCrypte;
      });
    });

    return promise;
  }

  _formatterInfoTransaction(domaine, opts) {
    // Ces valeurs n'ont de sens que sur le serveur.
    // Calculer secondes UTC (getTime retourne millisecondes locales)
    // debug("Formatter info transaction opts");
    // debug(opts);
    let version = 6;
    var uuidTransaction;
    if(opts) {
      version = opts.version || version;
      uuidTransaction = opts.uuidTransaction || uuidv4();
    } else {
      uuidTransaction = uuidv4();
    }

    let dateUTC = (new Date().getTime()/1000) + new Date().getTimezoneOffset()*60;
    let tempsLecture = Math.trunc(dateUTC);
    let infoTransaction = {
      'domaine': domaine,
      'idmg': this.idmg,
      'uuid-transaction': uuidTransaction,
      'estampille': tempsLecture,
      'certificat': this.pki.getFingerprint(),
      'hachage-contenu': '',  // Doit etre calcule a partir du contenu
      'version': version
    };

    return infoTransaction;
  }

  transmettreEnveloppeTransaction(transactionFormattee, domaine) {
    const jsonMessage = JSON.stringify(transactionFormattee);
    const correlation = transactionFormattee['en-tete']['uuid-transaction'];
    const routingKey = 'transaction.nouvelle';
    let promise = this._transmettre(routingKey, jsonMessage, correlation);

    return promise;
  }

  // Transmet une transaction en mode de restauration (i.e. provient d'un backup)
  restaurerTransaction(transactionStr) {
    // Extraire correlation
    const routingKey = 'transaction.restaurer';
    const promise = this._transmettre(routingKey, transactionStr);
    return promise;
  }

  formatterTransaction(domaine, message) {
    let messageFormatte = message;  // Meme objet si ca cause pas de problemes
    let infoTransaction = this._formatterInfoTransaction(domaine);
    const correlation = infoTransaction['uuid-transaction'];
    messageFormatte['en-tete'] = infoTransaction;

    // Signer le message avec le certificat
    this._signerMessage(messageFormatte);
    return messageFormatte;
  }

  // Transmet reponse (e.g. d'une requete)
  // Repond directement a une Q (exclusive)
  transmettreReponse(message, replyTo, correlationId) {
    const messageFormatte = this.formatterTransaction(replyTo, message);
    const jsonMessage = JSON.stringify(messageFormatte);

    // Faire la publication
    return new Promise((resolve, reject)=>{
      this.channel.publish(
        '',
        replyTo,
        Buffer.from(jsonMessage),
        {
          correlationId: correlationId
        },
        function(err, ok) {
          if(err) {
            debug("Erreur MQ Callback");
            debug(err);
            reject(err);
            return;
          }
          resolve(ok);
        }
      );
    });

  }

  _formatterInfoTransaction(domaine) {
    // Ces valeurs n'ont de sens que sur le serveur.
    // Calculer secondes UTC (getTime retourne millisecondes locales)
    let dateUTC = (new Date().getTime()/1000) + new Date().getTimezoneOffset()*60;
    let tempsLecture = Math.trunc(dateUTC);
    let infoTransaction = {
      'domaine': domaine,
      'idmg': this.pki.idmg,
      'uuid-transaction': uuidv4(),
      'estampille': tempsLecture,
      'certificat': this.pki.getFingerprint(),
      'hachage-contenu': '',  // Doit etre calcule a partir du contenu
      'version': 6
    };

    return infoTransaction;
  }

  _signerMessage(message) {
    // Produire le hachage du contenu avant de signer - le hash doit
    // etre inclus dans l'entete pour faire partie de la signature.
    let hachage = this.pki.hacherTransaction(message);
    message['en-tete']['hachage-contenu'] = hachage;

    // Signer la transaction. Ajoute l'information du certificat dans l'entete.
    let signature = this.pki.signerTransaction(message);
    message['_signature'] = signature;
  }

  // Methode qui permet de transmettre une transaction au backend RabbitMQ
  // Les metadonnees sont ajoutees automatiquement
  _transmettreTransaction(routingKey, message) {
    let jsonMessage = JSON.stringify(message);

    // Le code doit uniquement etre execute sur le serveur
    // console.log("Message: routing=" + routingKey + " message=" + jsonMessage);
    try {
      // console.log("Message a transmettre: " + routingKey + " = " + jsonMessage);
      this.channel.publish(
        this.exchange,
        routingKey,
         new Buffer(jsonMessage),
         {
           correlationId: message['correlation'],
           replyTo: this.reply_q.queue,
         },
         function(err, ok) {
           if(err) {
             debug("Erreur MQ Callback");
             debug(err);
           }
         }
      );
    }
    catch (e) {
      debug("Erreur MQ");
      debug(e);
      this.reconnect(); // Tenter de se reconnecter
    }
  }

  transmettreRequete(domaineAction, message, opts) {
    if(!opts) opts = {};
    const routingKey = 'requete.' + domaineAction;

    const infoTransaction = this._formatterInfoTransaction(routingKey);

    message['en-tete'] = infoTransaction;
    this._signerMessage(message);

    const correlation = infoTransaction['uuid-transaction'];
    const jsonMessage = JSON.stringify(message);

    // Transmettre requete - la promise permet de traiter la reponse
    debug("Transmettre requete, routing : %s", routingKey)
    // debug(jsonMessage)
    var promise = this._transmettre(routingKey, jsonMessage, correlation);

    if(opts.decoder) {
      promise = promise.then(msg=>{
        debug("Message recu, decoder")
        debug(msg)

        if(msg.resultats) {
          return msg.resultats
        }

        let messageContent = decodeURIComponent(escape(msg.content))
        debug("Message content")
        debug(messageContent)

        let documentRecu = messageContent
        if(messageContent) {
          try {
            let json_message = JSON.parse(messageContent)
            documentRecu = json_message
            if(json_message.resultats) {
              documentRecu = json_message['resultats']
              if(documentRecu[0]) {
                documentRecu = documentRecu[0]
                if(documentRecu[0]) {
                  documentRecu = documentRecu[0]
                }
              }
            }
          } catch(err) {
            debug("Erreur decodage message en JSON")
            debug(err)
          }
        }

        return documentRecu
      })

    }

    return promise
  }

  transmettreCommande(domaineAction, message, opts) {
    if(!opts) opts = {};
    const routingKey = 'commande.' + domaineAction;

    const infoTransaction = this._formatterInfoTransaction(domaineAction);

    message['en-tete'] = infoTransaction;
    this._signerMessage(message);

    var correlation = null;
    if(!opts.nowait) {
      correlation = infoTransaction['uuid-transaction'];
    }

    const jsonMessage = JSON.stringify(message);

    // Transmettre requete - la promise permet de traiter la reponse
    debug("Transmettre : %s", routingKey);
    const promise = this._transmettre(routingKey, jsonMessage, correlation);
    return promise;
  }

  emettreEvenement(message, routingKey) {

    const infoTransaction = this._formatterInfoTransaction(routingKey);

    message['en-tete'] = infoTransaction;
    this._signerMessage(message);

    const jsonMessage = JSON.stringify(message);

    // Transmettre requete - la promise permet de traiter la reponse
    const promise = this._transmettre(routingKey, jsonMessage);
    return promise;
  }

  _transmettre(routingKey, jsonMessage, correlationId, opts) {
    if(!opts) opts = {}
    // Setup variables pour timeout, callback
    let timeout, fonction_callback;

    let promise = new Promise((resolve, reject) => {

      var processed = false;

      // Exporter la fonction de callback dans l'objet RabbitMQ.
      // Permet de faire la correlation lorsqu'on recoit la reponse.
      const properties = {
        replyTo: this.reply_q.queue,
      };

      if(correlationId) {
        // On a un correlationId, generer promise et callback
        const pendingResponses = this.pendingResponses;
        fonction_callback = function(msg, err) {
          // Cleanup du callback
          delete pendingResponses[correlationId];
          clearTimeout(timeout);

          if(msg && !err) {
            resolve(msg);
          } else {
            reject(err);
          }
        };
        pendingResponses[correlationId] = fonction_callback;
        properties.correlationId = correlationId;
      }

      const exchange = opts.exchange || this.exchange

      // Faire la publication
      this.channel.publish(
        exchange,
        routingKey,
        Buffer.from(jsonMessage),
        properties,
        function(err, ok) {
          debug("Erreur MQ Callback");
          debug(err);
          delete pendingResponses[correlationId];
          reject(err);
        }
      );

      if(!correlationId) {
        resolve();
      }

    });

    if(correlationId) {
      // Lancer un timer pour permettre d'eviter qu'une requete ne soit
      // jamais nettoyee ou repondue.
      timeout = setTimeout(
        () => {fonction_callback(null, {'err': 'mq.timeout'})},
        15000
      );
    }

    return promise;
  };

  _publish(routingKey, jsonMessage) {
    // Faire la publication
    this.channel.publish(
      this.exchange,
      routingKey,
      Buffer.from(jsonMessage),
      (err, ok) => {
        debug("Erreur MQ Callback");
        debug(err);
        if(correlationId) {
          delete pendingResponses[correlationId];
        }
      }
    );
  }

  // Retourne un document en fonction d'un domaine
  get_document(domaine, filtre) {
    // Verifier que la MilleGrille n'a pas deja d'empreinte usager
    let requete = {
      "requetes": [
        {
          "filtre": filtre
        }
      ]
    }
    let promise = this.transmettreRequete(
      'requete.' + domaine,
      requete
    )
    .then((msg) => {
      let messageContent = decodeURIComponent(escape(msg.content));
      let json_message = JSON.parse(messageContent);
      let document_recu = json_message['resultats'][0][0];
      return(document_recu);
    })

    return promise;
  }

  demanderCertificat(fingerprint) {
    var requete = {fingerprint}
    var routingKey = 'certificat.' + fingerprint
    // debug(routingKey);
    return this.transmettreRequete(routingKey, requete)
    .then(reponse=>{
      // debug(reponse);
      if(reponse.content) {
        let messageContent = decodeURIComponent(escape(reponse.content))
        let json_message = JSON.parse(messageContent)
        return json_message
      } else {
        return reponse
      }
    })
  }

  demanderCertificatMaitreDesCles() {
    const tempsCourant = new Date().getTime();
    if(this.certificatMaitreDesCles && this.certificatMaitreDesCles.expiration < tempsCourant) {
      return new Promise((resolve, reject) => {
        resolve(this.certificatMaitreDesCles.cert);
      });
    } else {
      let objet_crypto = this;
      // console.debug("Demander certificat MaitreDesCles");
      var requete = {}
      var routingKey = 'MaitreDesCles.certMaitreDesCles';
      return this.transmettreRequete(routingKey, requete)
      .then(reponse=>{
        let messageContent = decodeURIComponent(escape(reponse.content));
        let json_message = JSON.parse(messageContent);
        // console.debug("Reponse cert maitre des cles");
        // console.debug(messageContent);
        const cert = forge.pki.certificateFromPem(json_message.certificat);
        objet_crypto.certificatMaitreDesCles = {
          expiration: tempsCourant + 120000,
          cert,
        }

        return cert;
      })
    }
  }

  transmettreCertificat(properties) {
    debug("Repondre avec le certificat local")
    let messageCertificat = this.pki.preparerMessageCertificat()
    let fingerprint = messageCertificat.fingerprint

    if(properties && properties.correlationId && properties.replyTo) {
      // On repond avec le certificat
      this.transmettreReponse(messageCertificat, properties.replyTo, properties.correlationId)
    } else {
      // Il n'y a pas de demandeur specifique, on emet le certificat
      let messageJSONStr = JSON.stringify(messageCertificat)
      this._publish(MG_ROUTING_EMETTRE_CERTIFICAT, messageJSONStr)
    }

    return fingerprint
  }

}

class RoutingKeyManager {

  constructor(mq, opts) {
    if(!opts) opts = {}

    // Lien vers RabbitMQ, donne acces au channel, Q et routing keys
    this.mq = mq;
    this.exchange = opts.exchange || '3.protege'
    debug("Exchange : %s", this.exchange)

    // Dictionnaire de routing keys
    //   cle: string (routing key sur RabbitMQ)
    //   valeur: liste de callbacks
    this.registeredRoutingKeyCallbacks = {};

    this.handleMessage.bind(this);
  }

  async handleMessage(routingKey, messageContent, properties) {
    let callback = this.registeredRoutingKeyCallbacks[routingKey];
    var promise;
    if(callback) {
      let json_message = JSON.parse(messageContent);
      let opts = {
        properties
      }
      promise = callback(routingKey, json_message, opts);
      // if(promise) {
      //   debug("Promise recue");
      // } else {
      //   debug("Promise non recue");
      // }
    } else {
      debug("Routing key pas de callback: " + routingKey);
    }

    return promise;
  }

  addRoutingKeyCallback(callback, routingKeys, opts) {
    if(!opts) opts = {}

    const operationLongue = opts.operationLongue || false

    for(var routingKey_idx in routingKeys) {
      let routingKeyName = routingKeys[routingKey_idx];
      this.registeredRoutingKeyCallbacks[routingKeyName] = callback;

      // Ajouter la routing key
      if(operationLongue) {
        debug("Ajouter callback pour routingKey %s sur Q operation longue", routingKeyName);
        this.mq.channel.bindQueue(this.mq.qOperationLongue.queue, this.exchange, routingKeyName);
      } else {
        debug("Ajouter callback pour routingKey %s", routingKeyName);
        this.mq.channel.bindQueue(this.mq.reply_q.queue, this.exchange, routingKeyName);
      }
    }
  }

  removeRoutingKeys(routingKeys) {
    for(var routingKey_idx in routingKeys) {
      let routingKeyName = routingKeys[routingKey_idx];
      delete this.registeredRoutingKeyCallbacks[routingKeyName];

      // Retirer la routing key
      debug("Enlever routingKeys %s", routingKeyName);
      this.mq.channel.unbindQueue(this.mq.reply_q.queue, this.exchange, routingKeyName);
    }
  }

  addRoutingKeysForSocket(socket, routingKeys, channel, reply_q) {
    const socketId = socket.id;

    for(var routingKey_idx in routingKeys) {
      let routingKeyName = routingKeys[routingKey_idx];

      // Ajouter la routing key
      this.mq.channel.bindQueue(reply_q.queue, this.exchange, routingKeyName);
    }
  }

  removeRoutingKeysForSocket(socket, routingKeys, channel, reply_q) {
    for(var routingKey_idx in routingKeys) {
      let routingKeyName = routingKeys[routingKey_idx];

      // Retirer la routing key
      this.mq.channel.unbindQueue(reply_q.queue, this.exchange, routingKeyName);
    }
  }

}

module.exports = MilleGrillesAmqpDAO;
