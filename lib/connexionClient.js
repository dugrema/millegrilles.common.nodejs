const openSocket = require('socket.io-client')

var _socket = null,
    _clePriveeSubtleDecrypt = null,
    _clePriveeSubtleSign = null

async function connecter(url, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if( ! _socket ) {
    if(DEBUG) console.debug("Connecter socket.io sur %s", url)
    _socket = openSocket('/', {
      path: url,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 500,
      reconnectionDelayMax: 30000,
      randomizationFactor: 0.5
    })

    _socket.on('challengeAuthCertificatNavigateur', (authRequest, cb) => {
      console.error("!!! CHALLENGE %O", authRequest)
      cb({err: 'nanana'})
    })

  } else {
    throw new Error("_socket deja charge")
  }
}

async function initialiserFormatteurMessage(opts) {
  opts = opts || {}
  const clePriveePem = opts.clePriveePem,
        certificatPem = opts.certificatPem,
        DEBUG = opts.DEBUG

  if(clePriveePem) {
    if(DEBUG) console.debug("Charger cle privee PEM (en parametres)")
    // Note : on ne peut pas combiner les usages decrypt et sign
    _clePriveeSubtleDecrypt = await importerClePriveeSubtle(clePriveePem, {usage: ['decrypt']})
    _clePriveeSubtleSign = await importerClePriveeSubtle(clePriveePem, {
      usage: ['sign'], algorithm: 'RSA-PSS', hash: 'SHA-512'})
  } else if(opts.clePriveeDecrypt && opts.clePriveeSign) {
    if(DEBUG) console.debug("Chargement cle privee Subtle")
    _clePriveeSubtleDecrypt = opts.clePriveeDecrypt
    _clePriveeSubtleSign = opts.clePriveeSign
  } else {
    if(DEBUG) console.debug("Charger cle privee a partir de IndexedDB")
    throw new Error("TODO : Importer cle privee a partir de IndexedDB")
  }

  if(certificatPem) {
    if(DEBUG) console.debug("Utiliser chaine pem fournie : %O", certificatPem)
  } else {
    if(DEBUG) console.debug("Charger certificat a partir de IndexedDB")
    throw new Error("TODO : Charger certificat a partir de IndexedDB")
  }

  if(DEBUG) console.debug("Cle privee subtle chargee")
  _formatteurMessage = new FormatteurMessageSubtle(certificatPem, clePriveeSubtleSign)
  await _formatteurMessage.ready  // Permet de recevoir erreur si applicable
}

function socketOn(eventName, callback) {
  _socket.on(eventName, message => { callback(message) })
}

function socketOff(eventName, callback) {
  _socket.off(eventName, callback)
}

// function setSocket(socket, opts) {
//   opts = opts || {}
//   _DEBUG = opts.DEBUG || false
//
//   _socket = socket
//   socket.on('erreur', erreur=>{
//     console.error("Erreur recue par connexionClient");
//     console.error(erreur);
//   })
// }

function deconnecter() {
  if(_socket != null) {
    _socket.disconnect()
    _socket = null
  }
}

function subscribe(routingKeys, callback, opts) {
  if(!opts) opts = {}
  const DEBUG = opts.DEBUG

  const niveauxSecurite = opts.exchange || ['1.public']
  if(DEBUG) console.debug("Enregistrer %O sur exchanges %O", routingKeys, niveauxSecurite)

  const callbackFilter = function(message) {
    if(!message) return

    // Filtrer par routing key
    const routingKey = message.routingKey

    if(routingKeys.includes(routingKey) && niveauSecurite === message.exchange) {
      try {
        callback(message)
      } catch(err) {
        console.error("Erreur traitement callback sur %s", routingKey)
      }
    }
  }

  // Transmet une liste de routingKeys a enregistrer sur notre Q.
  niveauxSecurite.forEach(exchange=>{
    _socket.emit('subscribe', {routingKeys, exchange})
  })

  const domainesActions = getDomainesActions(routingKeys)
  if(DEBUG) console.debug("Enregistrer listeners domaineAction : %O", domainesActions)
  domainesActions.forEach(domaineAction=>{
    _socket.on(domaineAction, callback)
  })

  // Retourne une methode pour faire le "unsubscribe"
  return callbackFilter
}

function unsubscribe(routingKeys, callback, opts) {
  // Retrait du listener d'evenement
  // console.debug("Unsubscribe callback, socket.off %O", routingKeys)
  _socket.emit('unsubscribe', {callback, opts})

  const domainesAction = getDomainesActions(routingKeys)
  domainesAction.forEach(domaineAction=>{
    _socket.off(domaineAction, callback)
  })

}

async function emitBlocking(event, message, opts) {
  opts = opts || {}

  if( message && !message['_signature'] && !opts.noformat ) {
    // Signer le message
    try {
      var domaine = opts.domaine || message['en-tete'].domaine
      message = await _formatteurMessage.formatterMessage(domaine, message, opts)
    } catch(err) {
      console.warn("Erreur formattage message : %O", err)
    }
  }

  return new Promise( (resolve, reject) => {

    // Creer timeout pour echec de commande
    const timeout = setTimeout(_=>{
      reject(new Error('emitBlocking ' + event + ': Timeout socket.io'))
    }, 7500)

    const traiterReponse = reponse => {
      clearTimeout(timeout)  // Reponse recue, annuler le timeout

      if(reponse && reponse.err) return reject(reponse.err)  // Erreur cote serveur

      resolve(reponse)
    }

    if(params) {
      _socket.emit(event, message, traiterReponse)
    } else {
      _socket.emit(event, traiterReponse)
    }

  })
}

function getDomainesActions(routingKeys) {
  // console.debug("Domaines actions, routingKeys : %O", routingKeys)
  const domainesActions = {}
  for(let idx in routingKeys) {
    const rkSplit = routingKeys[idx].split('.')
    var domaineAction = [rkSplit[0], rkSplit[1], rkSplit[rkSplit.length-1]].join('.')
    domainesActions[domaineAction] = true
  }

  return Object.keys(domainesActions)
}

module.exports = {
  connecter, deconnecter, initialiserFormatteurMessage,
  subscribe, unsubscribe, emitBlocking,
  socketOn, socketOff,
}