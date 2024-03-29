/*
  Wrapper pour amqplib qui ajoute les fonctionnalites pour
  interaction avec MilleGrilles.
 */

const debug = require('debug')('millegrilles:common:amqpdao')
const debugMessages = require('debug')('millegrilles:common:amqpdao:messages')
const amqplib = require('amqplib');
const os = require('os');
const fs = require('fs');
const {v4: uuidv4} = require('uuid');

const RoutingKeyManager = require('./routingKeyManager')
const GestionnaireCertificatMessages = require('./certificatManager')

const MG_EXCHANGE_PROTEGE = '3.protege'
const ROUTING_CERTIFICAT = 'requete.certificat'
const MG_ROUTING_EMETTRE_CERTIFICAT = 'evenement.certificat.infoCertificat'
const TYPES_MESSAGES_ROOM_ACCEPTES = ['evenement', 'transaction', 'commande']
// const routingKeyNouvelleTransaction = 'transaction.nouvelle'
const EXPIRATION_MESSAGE_DEFAUT = 15 * 60 * 1000  // 15 minutes en millisec


class MilleGrillesAmqpDAO {

  constructor(pki, opts) {
    this.pki = pki;
    if(!opts) opts = {}

    this.url = null
    this.connection = null

    // Flags connexion, trigger une reconnexion a l'entretien
    this.connectionError = null
    this.connectionBlocked = false  // Connexion bloquee (surcharge serveur)

    this.channel = null
    this.channelError = null

    this.reply_q = null;
    this.consumerTag = null;
    this.exchange = opts.exchange || MG_EXCHANGE_PROTEGE

    // Q Custom
    // Format par Q : key = maQueue, value = {q, tag}
    this.qCustom = {
      // 'operationsLongues': {}
    }
    if(opts.nomsQCustom) {
      opts.nomsQCustom.forEach(nom=>{
        // Ajouter un placeholder pour la Q custom
        this.qCustom[nom]={}
      })
    }
    if(opts.qCustom) {
      for(const nom in opts.qCustom) {
        const params = opts.qCustom[nom]
        this.qCustom[nom]={...params}
      }
    }

    this.compteurMessages = 0;

    this.reconnectTimeout = null; // Timer de reconnexion - null si inactif

    // Correlation avec les reponses en attente.
    // Cle: uuid de CorrelationId
    // Valeur: {callback, nodelete, creationDate}
    this.pendingResponses = {}

    this.routingKeyManager = new RoutingKeyManager(this, opts);
    this.routingKeyCertificat = null;

    this.certificatManager = new GestionnaireCertificatMessages(pki, this)

    // Injecter le gestinnonnaire de certificats, permet a PKI de faire des
    // requetes avec MQ
    pki.gestionnaireCertificatMessages = this.certificatManager

    this.connexionListeners = [];  // Listeners a appeler lors de la connexion

    this.intervalEntretien = setInterval(_=>{this.entretien()}, 30000)
  }

  connect(url) {
    this.url = url + "/" + this.pki.idmg;
    return this._connect();
  }

  _connect() {

    // Reset erreurs
    this.connectionError = null
    this.channelError = null

    if(this.connection === null) {
      let options = {
        ca: this.pki.ca,
        cert: this.pki.chainePEM,
        key: this.pki.cle,
      }
      options['credentials'] = amqplib.credentials.external()

      debug("Connecter a RabbitMQ : %s", this.url)
      return amqplib.connect(this.url, options)
      .then( conn => {
        console.info(new Date() + " Connexion a RabbitMQ reussie")
        this.connection = conn;

        // Event handlers
        conn.on('close', (reason)=>{
          console.warn(new Date() + " Fermeture connexion RabbitMQ")
          console.warn(reason);
          this.connection = null
          this.channel = null
          this.scheduleReconnect()
        })
        conn.on('error', reason => {
          this.connectionError = reason
          console.error(new Date() + 'Erreur RabbitMQ : %O', reason);
          if(this.connection) this.connection.close()
          this.connection = null
          this.channel = null
        })
        conn.on('blocked', reason => {
          this.connectionBlocked = true
          console.error(new Date() + 'RabbitMQ blocked : %O', reason);
        })
        conn.on('unblocked', () => {
          this.connectionBlocked = false
          console.info(new Date() + 'RabbitMQ unblocked');
        })

        return conn.createChannel()
      }).then( (ch) => {

        // Enregistrer event handlers channel
        ch.on('error', reason => {
          console.error(new Date() + ' Erreur channel (error), on va recycler la connexion : %O', reason)
          this.channelError = reason
          this.channel = null
          if(this.connection) this.connection.close()
          this.connection = null
        })
        ch.on('close', () => {
          console.error(new Date() + ' Fermeture channel (close), on va recycler la connexion : %O', reason)
          this.channelError = 'closed'  // Pour l'entretien si c'est une fermeture impromptue
          this.channel = null
          if(this.connection) this.connection.close()
          this.connection = null
        })
        ch.on('drain', () => {
          console.warn(new Date() + " Channel etait bloque, recu event drain pour pouvoir poursuivre")
        })

        this.channel = ch
        return this.ecouter()
      }).then(()=>{
        console.info(new Date() + " Connexion et channel prets")

        // Transmettre le certificat
        let fingerprintSha256B64 = this.certificatManager.transmettreCertificat()

        // Enregistrer routing key du certificat
        // Permet de repondre si un autre composant demande notre certificat
        this.routingKeyCertificat = ROUTING_CERTIFICAT + '.' + fingerprintSha256B64;
        console.info(new Date() + " Enregistrer routing key: %s", this.routingKeyCertificat)

        return this.channel.bindQueue(this.reply_q.queue, this.exchange, this.routingKeyCertificat)
      }).then(_=>{
        const niveauExchange = this.exchange.split('.').shift()
        console.info("Enregistrer listeners de certificats sur exchange %d et +", niveauExchange)
        if(niveauExchange >= 3) {
          this.channel.bindQueue(this.reply_q.queue, '3.protege', MG_ROUTING_EMETTRE_CERTIFICAT)
        }
        if(niveauExchange >= 2) {
          this.channel.bindQueue(this.reply_q.queue, '2.prive', MG_ROUTING_EMETTRE_CERTIFICAT)
        }

        this.channel.bindQueue(this.reply_q.queue, '1.public', MG_ROUTING_EMETTRE_CERTIFICAT)

      }).catch(err => {
        this.connection = null;
        var reconnectDelay = 30
        try {
          if(err.message.indexOf('403') > 0) {
            debug("Erreur 403, tenter de s'inscrire avec le certificat")
            var axios = require('axios')
            var https = require('https')

            const cert = this.pki.chainePEM,
                  key = this.pki.cle,
                  ca = this.pki.ca,
                  port = 443

            // Extraire de amqps://HOST:port/vhost
            // Par defaut on prend le HOST pour acceder via nginx
            var host = process.env.MG_INSTALLATION_HOST || process.env.HOST || 'nginx'
            const httpsAgent = new https.Agent({
              ca, cert,
              key,
              rejectUnauthorized: false,
            })

            const urlConnexion = 'https://' + host + ':' + port + '/administration/ajouterCompte'
            console.log("Connecter a : %s\nCerts\n%s\nCA\n%s", urlConnexion, cert, ca)

            axios({method: 'post', url: urlConnexion, httpsAgent})
            .then(resp=>{
              console.error("Reponse inscription MQ : code %d %s", resp.status, resp.statusText)
              reconnectDelay = 2  // Attendre 2 secondes puis reconnecter
            })
            .catch(err=>{
              console.error("Erreur (1) tentative de creation de compte MQ, fallback sur 'nginx'\n%s", err)
              debug("Erreur (1-detail) tentative de creation de compte MQ, fallback sur 'nginx'\n%s", err)

              if(host !== 'nginx') {
                // Fallback sur https;//nginx/...
                const urlConnexion = 'https://nginx/administration/ajouterCompte'
                console.log("Connecter a : %s\nCerts\n%s\nCA\n%s", urlConnexion, cert, ca)

                return axios({method: 'post', url: urlConnexion, httpsAgent})
              }

              return Promise.resolve()  // Rien a faire, on reessaiera plus tard
            })
            .catch(err=>{
              console.error("Erreur (2) tentative de creation de compte MQ via nginx\n%s", err)
              debug("Erreur (2-detail) tentative de creation de compte MQ via nginx\n%s", err)
            })
          } else {
            console.error("Erreur (3) connexion RabbitMQ : %s", err.message);
            debug("Erreur (3-detail) connexion RabbitMQ:\n%O", err)
          }
        } catch(err) {
          console.error("Erreur (4) tentative de creation de compte MQ\n%s", err.message)
          debug("Erreur (4-detail) connexion RabbitMQ:\n%O", err)
        }

        this.scheduleReconnect({attente: reconnectDelay});
      });

    }

  }

  entretien() {
    debug("Entretient MQ")
    const tempsExpire = new Date().getTime() - 20000  // 20 secondes

    if(!this.connection || this.connectionError || this.connectionBlocked || this.channelError) {
      if(this.connection) {
        try {
          this.connection.close()
        } catch(e) {
          console.error("Erreur fermeture connexion (raison fermeture: flags erreurs presents ): %O", e)
        }

        // Nettoyage objets connexion et flags
        this.connection = null
        this.channel = null
        this.connectionError = null
        this.connectionBlocked = false
        this.channelError = null

        this.scheduleReconnect({attente: 25});
      }
    }

    // Supprimer callback passe date
    const pendingReponsesUpdate = {}
    for( let correlationId in this.pendingResponses ) {
      const callbackInfo = this.pendingResponses[correlationId]
      if( callbackInfo.nodelete || callbackInfo.creationDate.getTime() > tempsExpire ) {
        // Conserver callback
        pendingReponsesUpdate[correlationId] = callbackInfo
      } else {
        debug("entretien: delete callback correlationId:%s", correlationId)
      }
      debug("Attente reponse %s", correlationId)
    }
    this.pendingResponses = pendingReponsesUpdate
  }

  scheduleReconnect(opts) {
    if(!opts) opts = {}
    // Met un timer pour se reconnecter
    const dureeAttente = opts.attente || 30;

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

    // Creer Q pour ecouter
    const promiseQPrincipale = this.channel.assertQueue('', {
      durable: false,
      exclusive: true,
    }).then( async q => {
      debug("Queue principale cree : %O", q)
      this.reply_q = q

      // Appeler listeners de connexion
      for(let idx in this.connexionListeners) {
        let listener = this.connexionListeners[idx]
        listener.on_connecter()
      }

      // this._consume()
      // Commencer a consommer des messages sur la Q principale
      this.consumerTag = await this.channel.consume(
        this.reply_q.queue,
        msg => {return this._traiterMessage(msg)},
        {noAck: true}
      )
      debug("Consumer tag principal %s", this.consumerTag)
    })

    const promises = [promiseQPrincipale]

    // Preparer les Q custom (utilisees pour traitements de longue duree)
    for(let nomQ in this.qCustom) {
      const infoQ = this.qCustom[nomQ]
      const messageTtl = infoQ.ttl
      const qName = infoQ.name || ''  // Par defaut q nommee automatiquement
      debug("Creer q custom %O", infoQ)
      const promise = this.channel.assertQueue(qName, {
        durable: false,
        exclusive: !qName,  // Si qName est vide, on met exclusive (amq...)
        messageTtl,
      }).then( async q => {
        debug("Q creee : %O", q)
        infoQ.q = q
        /*
        const tag = await this.channel.consume(
          q.queue,
          msg => { this._traiterMessageCustom(msg, infoQ) },
          {noAck: true}
        )
        infoQ.tag = tag.consumerTag
        debug("Queue custom %s cree (tag) : %O", nomQ, tag, q)
        */
        //this._traiterMessageCustom(msg, infoQ)
        this._traiterMessageCustom(infoQ)
          .catch(err=>{console.error("ERROR Fin traitement Q longue %s : %O", q, err)})
      })
      promises.push(promise)
    }

    return Promise.all(promises)
  }

  createChannel(socket) {
    return this.connection.createChannel()
      .then(channel=>{
        socket.mqChannel = channel
        return channel.assertQueue('', {
          durable: false,
          exclusive: true,
        })
      })
      .then(q=>{
        debug("Queue reponse usager via websocket cree %s", q.queue);
        socket.reply_q = q;

        // Activer la lecture de message et callback pour notre websocket
        socket.mqChannel.consume(
          q.queue,
          (msg) => {
            debug('2. Message recu');
            let messageContent = msg.content.toString('utf-8');
            let json_message = JSON.parse(messageContent);
            let routingKey = msg.fields.routingKey;

            socket.emit('mq_message', {routingKey: routingKey, message: json_message});
          },
          {noAck: true}
        );
      });
  }

  //async _traiterMessageCustom(msg, infoQ) {
  async _traiterMessageCustom(infoQ) {
    // let consumerTag = infoQ.tag
    // infoQ.tag = null

    // if(consumerTag) {

      try {
        // Traiter tous les messages dans la Q, un a la fois
        // Ne pas utiliser le consumer, il ne permet pas le controle fin.
        //await this.channel.cancel(consumerTag)
        let msg = await this.channel.get(infoQ.q.queue, {noAck: true});
        while(msg) {
          try {
            // debug("Debut traiter message operation longue");
            await this._traiterMessage(msg)
            // debug("Fin traitement message operation longue")
          } catch (err) {
            // Le traitement du message n'a pas fonctionne, mais on le fait passer quand meme
            // avec ACK dans finally pour eviter de bloquer.
            console.error(`${new Date()} _traiterMessageCustom : Erreur traitement message : ${err}\n${msg}`)
          } finally {
            // this.channel.ack(msg);  // Change pour auto-ack
          }

          // Tenter d'aller chercher un autre message
          // Traite un message a la fois
          msg = await this.channel.get(infoQ.q.queue, {noAck: true});
          // debug("Message operation longue suivant")
          // debug(msg);
        }
      } finally {
        // Recommencer a ecouter les evenements
        // var nouveauTag = await this.channel.consume(
        //   infoQ.q.queue,
        //   async msg => { this._traiterMessageCustom(msg, infoQ) },
        //   {noAck: true}
        // )
        // infoQ.tag = nouveauTag.consumerTag

        // Faire un nouveau get dans 5 secondes
        setTimeout(()=>{this._traiterMessageCustom(infoQ)}, 5000)

      }

    //   // debug("Fin operation longue");
    // } else {
    //   console.error(new Date() + " Message operation longue recu durant traitement, NACK vers la Q");
    //   // Remettre le message sur la Q avec un nack
    // }
  }

  async _traiterMessage(msg) {
    // Traitement des messages recus sur la Q principale (pas operations longues)

    // debug("Message recu - TEMP - \n%O", msg)

    // let messageContent = decodeURIComponent(escape(msg.content));
    const messageContent = msg.content.toString(),
          routingKey = msg.fields.routingKey,
          exchange = msg.fields.exchange,
          correlationId = msg.properties.correlationId
    const messageDict = JSON.parse(messageContent)

    debugMessages("Message recu sur Q principale :\n  routing keys : %O\n  exchange : %s\n  correlation id : %s\n%O",
      routingKey, exchange, correlationId, messageDict)

    if( routingKey && routingKey === MG_ROUTING_EMETTRE_CERTIFICAT ) {
      // Sauvegarder le certificat localement pour usage futur
      const fingerprint = messageDict.fingerprint
      debug("Certificat recu (non sollicite) : " + fingerprint)
      try {
        await this.certificatManager.sauvegarderMessageCertificat(messageContent, fingerprint)
      } catch(err) {
        console.error("_traiterMessage: Erreur sauvegarde certificat\n%O", err)
      }

    } else if(routingKey && routingKey === this.routingKeyCertificat) {
      // Retransmettre notre certificat
      this.certificatManager.transmettreCertificat(msg.properties)
    } else {
      // Message standard
      try {
        debug("_traiterMessage: Verifier signature message")
        const signatureValide = await this.pki.verifierMessage(messageDict)
        debug("_traiterMessage: Resultat verification signature %O", signatureValide)

        if(signatureValide) {
          await this.traiterMessageValide(messageDict, msg)
        } else {
          await this.traiterMessageInvalide(messageDict, msg)
        }
      } catch(err) {
        debug("Erreur verification signature : %O", err)
        await this.traiterMessageInvalide(messageDict, msg, err)
      }

    }

  }

  async traiterMessageValide(messageDict, msg) {
    debug("Traiter message valide")

    const routingKey = msg.fields.routingKey,
          exchange = msg.fields.exchange,
          correlationId = msg.properties.correlationId

    var callbackInfo = null
    try {

      if( ! exchange && correlationId ) {  // Exclure message sur exchange, uniquement utiliser direct Q ('')
        debug("Reponse message direct, correlationId : %s", correlationId)

        callbackInfo = this.pendingResponses[correlationId]
        if(callbackInfo) {
          if( ! callbackInfo.nodelete ) {
            delete this.pendingResponses[correlationId]
          }
          debug("traiterMessageValide: executer callback")
          await callbackInfo.callback(messageDict)
          debug("traiterMessageValide: callback termine")
        } else {
          debug("Message recu sur Q (direct), aucun callback pour correlationId %s. Transferer au routingKeyManager.", correlationId)
          await this.routingKeyManager.handleResponse(correlationId, msg.content, {properties: msg.properties, fields: msg.fields});
        }

      } else if(routingKey) {
        // Traiter le message via handlers
        debugMessages("traiterMessageValide par routing keys:\nFields: %O\nProperties: %O\n%O",
          msg.fields, msg.properties, messageDict)
        await this.routingKeyManager.handleMessage(
          routingKey, msg.content, {properties: msg.properties, fields: msg.fields});

      } else {
        console.warn("Recu message sans correlation Id ou routing key :\n%O", messageDict);
      }
    } catch(err) {
      console.error("Erreur traitement message : erreur %O\nRouting Keys %O, correlation id : %s", err, routingKey, correlationId)
      if(callbackInfo && callbackInfo.callback) {
        return callbackInfo.callback({err: err})
      }
    }

  }

  async traiterMessageInvalide(messageDict, msg, err) {
    if(!err) err = {}

    const messageContent = msg.content.toString(),
          routingKey = msg.fields.routingKey,
          exchange = msg.fields.routingKey,
          correlationId = msg.fields.correlationId

    if(err.inconnu) {
      // Message certificat inconnu, on va verifier si c'est une reponse de
      // certificat.
      if(messageDict.chaine_pem) {
        // On laisse le message passer, c'est un certificat
        debug("Certificat recu: %O", messageDict);

        try {
          await this.certificatManager.sauvegarderMessageCertificat(messageContent, messageDict.fingerprint_sha256_b64)

          if(callback) {
            callback(msg)
          }
        } catch(err) {
          console.error("traiterMessageInvalide : Erreur traitement\n%O", err)
        }

      } else {
        // On tente de charger le certificat, transferer callback vers l'attente
        // du certificat
        let fingerprint = messageDict['en-tete'].fingerprint_certificat;
        debug("Certificat inconnu, on fait une demande : %s", fingerprint);

        // Creer un callback a utiliser apres reception du certificat
        const callback = _ => {
          this._traiterMessage(msg)
        }

        return this.certificatManager.demanderCertificat(fingerprint, {callback})
      }
    }
  }

  creerCorrelationPermanent(correlationId, callback) {
    this.pendingResponses[correlationId] = {
      nodelete: true,
      permanent: true,
      creationDate: new Date(),
      callback,
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
  async transmettreTransactionFormattee(message, domaine, opts) {
    if(!opts) opts = {}

    // Ajouter entete et signature
    const messageFormatte = await this.pki.formatterMessage(message, domaine, opts)
    let routingKey = 'transaction.' + domaine
    if(opts.partition) routingKey = routingKey + '.' + opts.partition
    if(opts.action) routingKey = routingKey + '.' + opts.action
    const correlation = messageFormatte['en-tete']['uuid_transaction'];

    // On attache toujours le certificat pour une transaction
    const chaineCertificatsList = this.pki.chaineCertificatsList
    messageFormatte['_certificat'] = chaineCertificatsList

    const messageString = JSON.stringify(messageFormatte)

    // Retourner promise
    return this._transmettre(routingKey, messageString, correlation)
  }

  transmettreEnveloppeTransaction(transactionFormattee, domaine) {
    const jsonMessage = JSON.stringify(transactionFormattee);
    const correlation = transactionFormattee['en-tete']['uuid_transaction'];
    let domaine_rk = domaine || transactionFormattee['en-tete'].domaine
    let action_rk = transactionFormattee['en-tete'].action
    let partition_rk = transactionFormattee['en-tete'].partition

    let routingKey = 'transaction.' + domaine_rk
    if(partition_rk) routingKey = routingKey + '.' + partition_rk
    if(action_rk) routingKey = routingKey + '.' + action_rk

    debug("Transmettre transaction routing:%s, %O", routingKey, transactionFormattee)
    let promise = this._transmettre(routingKey, jsonMessage, correlation);

    return promise;
  }

  transmettreEnveloppeCommande(commandeSignee, domaine, opts) {
    opts = opts || {}

    const jsonMessage = JSON.stringify(commandeSignee);
    let correlation = null
    let entete = commandeSignee['en-tete'],
        partition = opts.partition || entete.partition,
        action = opts.action || entete.action
    if(!opts.nowait) {
      correlation = entete['uuid_transaction']
    }
    var routingKey = domaine
    if(!routingKey) {
      routingKey = entete.domaine
    }
    if(!routingKey.startsWith('commande.')) {
      routingKey = 'commande.' + routingKey
    }
    if(partition) routingKey = routingKey + '.' + partition
    if(action) routingKey = routingKey + '.' + action
    debug("Transmettre transaction routing:%s, %O", routingKey, commandeSignee)
    let promise = this._transmettre(routingKey, jsonMessage, correlation)

    return promise
  }

  // Transmet une transaction en mode de restauration (i.e. provient d'un backup)
  restaurerTransaction(transactionStr) {
    // Extraire correlation
    const routingKey = 'commande.transaction.restaurerTransaction';
    const promise = this._transmettre(routingKey, transactionStr, null, {exchange: '4.secure'});
    return promise;
  }

  // formatterTransaction(domaine, message, opts) {
  //   if(!opts) opts = {}
  //
  //   // Formatte la transaction en modifiant le parametre message
  //   const infoTransaction = this._formatterInfoTransaction(domaine, opts);
  //   message['en-tete'] = infoTransaction
  //
  //   // Filtrer tous les champs commencant par _
  //   const messageFiltre = {}
  //   for(let champ in message) {
  //     if( ! champ.startsWith('_') ) {
  //       messageFiltre[champ] = message[champ]
  //     }
  //   }
  //
  //   // Signer le message avec le certificat, calcul aussi en-tete.hachage_contenu
  //   const signature = this._signerMessage(messageFiltre)
  //
  //   message['_signature'] = signature
  //
  //   if( opts.attacherCertificat ) {
  //     // Attacher la chaine de certificats utilisee pour signer la requete
  //     const chaineCertificatsList = this.pki.chaineCertificatsList
  //     debug("Chaine de certificats : %O", chaineCertificatsList)
  //     message['_certificat'] = chaineCertificatsList
  //   }
  //
  //   return message
  // }

  // Transmet reponse (e.g. d'une requete)
  // Repond directement a une Q (exclusive)
  async transmettreReponse(message, replyTo, correlationId) {
    const messageFormatte = await this.pki.formatterMessage(message);
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

  // _formatterInfoTransaction(domaine, opts) {
  //   if(!opts) opts = {}
  //   // Ces valeurs n'ont de sens que sur le serveur.
  //   // Calculer secondes UTC (getTime retourne millisecondes locales)
  //   let dateUTC = (new Date().getTime()/1000) + new Date().getTimezoneOffset()*60;
  //   let tempsLecture = Math.trunc(dateUTC);
  //   let infoTransaction = {
  //     'idmg': this.pki.idmg,
  //     'uuid_transaction': uuidv4(),
  //     'estampille': tempsLecture,
  //     'fingerprint_certificat': this.pki.fingerprint,
  //     'hachage_contenu': '',  // Doit etre calcule a partir du contenu
  //     'version': 6
  //   };
  //   if(domaine) {
  //     infoTransaction.domaine = domaine
  //   }
  //
  //   return infoTransaction;
  // }

  // _signerMessage(message) {
  //   // Produire le hachage du contenu avant de signer - le hash doit
  //   // etre inclus dans l'entete pour faire partie de la signature.
  //   let hachage = this.pki.hacherTransaction(message)
  //   message['en-tete']['hachage_contenu'] = hachage
  //
  //   // Signer la transaction. Ajoute l'information du certificat dans l'entete.
  //   let signature = this.pki.signerTransaction(message)
  //   message['_signature'] = signature
  //
  //   return signature
  // }

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

  async transmettreRequete(domaineAction, message, opts) {
    if(!opts) opts = {};
    let routingKey = 'requete.' + domaineAction
    let entete_in = message['en-tete'] || {}
    let partition = opts.partition || entete_in.partition
    let action = opts.action || entete_in.action
    if(partition) routingKey = routingKey + '.' + partition
    if(action) routingKey = routingKey + '.' + action
    debug("!!! Transmettre requete, routing : %s (opts: %O)", routingKey, opts)

    if( ! opts.noformat ) {
      // infoTransaction = this._formatterInfoTransaction(routingKey);
      // message['en-tete'] = infoTransaction;
      // this._signerMessage(message);
      message = await this.pki.formatterMessage(message, domaineAction, opts)

      // Changement - on attache toujours le certificat pour une requete
      const chaineCertificatsList = this.pki.chaineCertificatsList
      message['_certificat'] = chaineCertificatsList
    }

    const entete = message['en-tete']

    // debug("Verifier si on attache certs, opts : %O", opts)
    // if( opts.attacherCertificat ) {
    //   // Attacher la chaine de certificats utilisee pour signer la requete
    //   const chaineCertificatsList = this.pki.chaineCertificatsList
    //   debug("Chaine de certificats : %O", chaineCertificatsList)
    //   message['_certificat'] = chaineCertificatsList
    // }

    var correlationId = null
    if( ! opts.nowait ) {
      correlationId = entete['uuid_transaction']
    }
    const jsonMessage = JSON.stringify(message)

    // Transmettre requete - la promise permet de traiter la reponse
    // debug(jsonMessage)
    const msg = await this._transmettre(routingKey, jsonMessage, correlationId, opts)

    if(opts.decoder) {
      debug("Message recu, decoder")

      if(!msg.content) {
        // Le message a deja ete decode
        return msg.resultats || msg
      }

      // Decoder le message
      let messageContent = decodeURIComponent(escape(msg.content))
      debug("Message content")
      debug(messageContent)

      let documentRecu = messageContent
      if(messageContent) {
        try {
          let json_message = JSON.parse(messageContent)
          documentRecu = json_message
        } catch(err) {
          debug("Erreur decodage message en JSON")
          debug(err)
        }
      }

      return documentRecu
    } else {
      return msg
    }

  }

  async transmettreCommande(domaineAction, message, opts) {
    if(!opts) opts = {}
    debug("transmettreCommande opts: %O", opts)

    var routingKey = domaineAction
    if( ! domaineAction.startsWith('commande.') ) {
      routingKey = 'commande.' + routingKey
    }
    if(opts.partition) routingKey = routingKey + '.' + opts.partition
    if(opts.action) routingKey = routingKey + '.' + opts.action

    var entete = message['en-tete']
    if( ! opts.noformat || ! entete ) {
      // Formatter l'entete et signer la commande
      // infoTransaction = this._formatterInfoTransaction(domaineAction)
      // message['en-tete'] = infoTransaction
      // this._signerMessage(message)
      message = await this.pki.formatterMessage(message, domaineAction, opts)
      entete = message['en-tete']

      // On attache toujours le certificat pour une commande
      const chaineCertificatsList = this.pki.chaineCertificatsList
      message['_certificat'] = chaineCertificatsList
    }

    var correlation = null
    if(!opts.nowait) {
      correlation = entete['uuid_transaction']
    }

    const jsonMessage = JSON.stringify(message)

    // Transmettre requete - la promise permet de traiter la reponse
    debug("transmettreCommande : %s", routingKey)

    // Return promise
    return this._transmettre(routingKey, jsonMessage, correlation, opts)
  }

  async emettreEvenement(message, domaineAction, opts) {
    opts = opts || {}

    // const infoTransaction = this._formatterInfoTransaction(routingKey);
    // message['en-tete'] = infoTransaction;
    // this._signerMessage(message);
    // let domaine = opts.domaine || routingKey
    message = await this.pki.formatterMessage(message, domaineAction, opts)

    let routingKey = domaineAction
    if(!routingKey.startsWith('evenement')) {
      routingKey = 'evenement.' + routingKey
    }
    if(opts.partition) routingKey = routingKey + '.' + opts.partition
    if(opts.action) routingKey += '.' + opts.action

    const jsonMessage = JSON.stringify(message);
    // console.debug("!!!! Emission %s\n%s", routingKey, jsonMessage)

    // Return promise
    return this._transmettre(routingKey, jsonMessage, null, opts);
  }

  // Transmet une requete ouverte a tous les domaines. On ne sait pas a
  // l'avance combien de domaines vont repondre.
  // La fonction attend un certain temps apres reception du premier message
  // avant de retourner la reponse pour tenter de grouper toutes les reponses.
  // opts :
  //   - socketId : permet de transmettre des reponses "en retard"
  //   - attenteApresReception : nom de millisecs a attendre apres reception de 1ere reponse
  async transmettreRequeteMultiDomaines(domaineAction, message, opts) {
    if(!opts) opts = {}
    const routingKey = 'requete.' + domaineAction

    // const infoTransaction = this._formatterInfoTransaction(routingKey)
    // message['en-tete'] = infoTransaction;
    // this._signerMessage(message);
    message = await this.pki.formatterMessage(message, domaineAction, opts)

    const correlationId = message['en-tete']['uuid_transaction'];
    const jsonMessage = JSON.stringify(message);

    // Transmettre requete - la promise permet de traiter la reponse
    debug("Transmettre requete multi-domaines, routing : %s", routingKey)

    var fonction_callback

    // Setup variables pour timeout
    const timeout = setTimeout(
      () => {fonction_callback(null, {'err': 'mq.multidomaine.timeout'})},
      15000
    )

    var timerResolve = null

    const promise = new Promise((resolve, reject) => {

      var processed = false;

      // Exporter la fonction de callback dans l'objet RabbitMQ.
      // Permet de faire la correlation lorsqu'on recoit la reponse.
      const properties = {
        replyTo: this.reply_q.queue,
        correlationId,
      };

      // On a un correlationId, generer promise et callback
      const messagesRecus = []
      const transmettreReponse = () => {
        debug("Transmission resultats multi-domaines:\n%O", messagesRecus)
        resolve({resultats: messagesRecus})
      }
      fonction_callback = function(msg, err) {
        if(msg && !err) {
          debug("Message multi-domaine recu\n%O", msg)
          // let messageContent = decodeURIComponent(escape(msg.content))
          messagesRecus.push(msg)

          // Reset timer d'attente de message au besoin
          if(timerResolve) clearTimeout(timerResolve)

          // Attendre des messages supplementaires
          timerResolve = setTimeout(transmettreReponse, 50) // Attendre messages supplementaires
        } else {
          reject(err);
        }
      };
      this.pendingResponses[correlationId] = {
        callback: fonction_callback,
        nodelete: true,
        creationDate: new Date()
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
          // delete pendingResponses[correlationId];
          reject(err);
        }
      );

    })
    .finally(()=>{
      // Cleanup du callback
      debug("Cleanup callback requete multi-domaine %s", routingKey)
      delete this.pendingResponses[correlationId]
      clearTimeout(timeout)
    })

    return promise
  }

  _transmettre(routingKey, jsonMessage, correlationId, opts) {
    opts = opts || {}
    debug("_transmettre opts : %O", opts)
    // Setup variables pour timeout, callback
    let timeout, fonction_callback;

    let promise = new Promise((resolve, reject) => {

      var processed = false;

      // Exporter la fonction de callback dans l'objet RabbitMQ.
      // Permet de faire la correlation lorsqu'on recoit la reponse.
      const properties = {
        replyTo: this.reply_q.queue,
      }
      if(opts.operationLongue) {
        properties.replyTo = this.qOperationLongue.queue
      }

      if(correlationId) {

        properties.correlationId = correlationId

        debug("Transmettre message, callback sur correlationId=%s, queue=%s", correlationId, properties.replyTo)
        // On a un correlationId, generer promise et callback
        fonction_callback = function(msg, err) {
          if(msg && !err) {
            resolve(msg);
          } else {
            reject({err, msg});
          }
        };
        this.pendingResponses[correlationId] = {callback: fonction_callback, creationDate: new Date()}
      }

      const exchange = opts.exchange || this.exchange

      // console.debug("Publish exchange: %s, routingKey: %s, message: %s", exchange, routingKey, jsonMessage)

      // Faire la publication
      this.channel.publish(
        exchange,
        routingKey,
        Buffer.from(jsonMessage),
        properties,
        function(err, ok) {
          if(err) {
            console.error("AMQPDAO ERROR : Erreur MQ Callback : %O", err);
            delete this.pendingResponses[correlationId];
            reject();
          }
        }
      );

      if(!correlationId) {
        resolve();
      }

    })
    .finally(()=>{
      delete this.pendingResponses[correlationId];
      clearTimeout(timeout);
    });

    if(correlationId) {
      // Lancer un timer pour permettre d'eviter qu'une requete ne soit
      // jamais nettoyee ou repondue.

      // Creer une erreur pour conserver la stack d'appel.
      const erreurPotentielle = new Error("Stack")

      timeout = setTimeout(
        () => {
          console.error("AMQPDAO ERROR timeout sur correlationId:%s, stack appel : %O", correlationId, erreurPotentielle)
          fonction_callback(null, {'err': 'mq.timeout', correlationId, 'stack': erreurPotentielle.stack})
        },
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
      let document_recu
      if(json_message.resultats) {
        // Retourner uniquement le document dans element resultats
        document_recu = json_message['resultats'][0][0]
      } else {
        document_recu = json_message
      }
      return(document_recu);
    })

    return promise;
  }

  estExpire(message, opts) {
    /* Verifie si le message est expire (contextuel) */
    opts = opts || {}
    const expiration = opts.expiration || EXPIRATION_MESSAGE_DEFAUT  // expiration en millisecs
    const epochCourant = new Date().getTime()
    const estampille = message['en-tete'].estampille * 1000
    const tempsExpire = epochCourant - expiration

    if(estampille > epochCourant) {
      throw new Error("Message avec une date future %d (epoch)", estampille)
    }

    if(estampille > tempsExpire) {
      return false
    }

    // Message est expire
    return true
  }

}

module.exports = MilleGrillesAmqpDAO
