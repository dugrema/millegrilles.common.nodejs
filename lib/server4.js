const debug = require('debug')('millegrilles:common:server4')
const fs = require('fs')
const socketio = require('socket.io')
const morgan = require('morgan')
const session = require('express-session')
//const MemoryStore = require('memorystore')(session)
const FileStore = require('session-file-store')(session)
const socketioSession = require('express-socket.io-session')
const {v4: uuidv4} = require('uuid')

const { genererChallengeCertificat, veriferUpgradeProtegerApp } = require('./authentification')
const { init: initComptesUsagers } = require('./dao/comptesUsagersDao')

const MilleGrillesPKI = require('./pki')
const MilleGrillesAmqpDAO = require('./amqpdao')

// Preparer certificats
const _certPems = {
  millegrille: fs.readFileSync(process.env.MG_MQ_CAFILE).toString('utf-8'),
  cert: fs.readFileSync(process.env.MG_MQ_CERTFILE).toString('utf-8'),
  key: fs.readFileSync(process.env.MG_MQ_KEYFILE).toString('utf-8'),
}
const hostname = process.env.HOST
const secretCookiesPassword = process.env.COOKIE_PASSWORD || ''+uuidv4()

const _exchange = process.env.MG_EXCHANGE_DEFAUT || '3.protege'

// Charger PKI
const instPki = new MilleGrillesPKI()
const amqpdao = new MilleGrillesAmqpDAO(instPki, {exchange: _exchange})

async function initialiser(app, configurerEvenements, opts) {
  opts = opts || {}

  // Connecter a MQ
  debug("Initialiser MQ, opts:%O", opts)
  await instPki.initialiserPkiPEMS(_certPems)

  if(opts.exchange) {
    debug("Utilisation exchange %s", opts.exchange)
    amqpdao.exchange = opts.exchange || _exchange
  }

  let urlMq
  try {
    urlMq = new URL(process.env.MG_MQ_URL)
  } catch(err) {
    urlMq = new URL('amqps://mq:5673')  // Default
    urlMq.host = process.env.MQ_HOST || urlMq.host
    urlMq.port = process.env.MQ_PORT || urlMq.port
  }
  console.info("****************")
  console.info("server4.initialiser Connecter a AMQPDAO sur %s", urlMq)
  await amqpdao.connect(urlMq.href)
  console.info("server4.initialiser AMQPDAO connexion prete")
  console.info("****************")

  // Morgan logging
  const loggingType = process.env.NODE_ENV !== 'production' ? 'dev' : 'combined'
  app.use(morgan('combined'))

  const hostname = process.env.HOST
  const port = process.env.PORT || '443'
  const pathApp = opts.pathApp || '/'
  var pathCookie = pathApp
  if(opts.cookiePath) {
    pathCookie = opts.cookiePath
  }

  var cookieName = 'millegrilles.sid'
  if(opts.pathApp) {
    cookieName = opts.pathApp + '.sid'
    cookieName = cookieName.replace('/', '')
  }
  debug("Cookie name : %O", cookieName)

  const maxAge = opts.maxAge || 3600000   // 1 heure par defaut

  const sessionConfig = {
    secret: secretCookiesPassword,
    name: cookieName,
    cookie: {
      path: pathCookie,
      domain: hostname,
      sameSite: 'strict',
      secure: true,
      maxAge,
    },
    // store: new MemoryStore({
    //   checkPeriod: 3600000 // prune expired entries every 1h
    // }),
    store: new FileStore(),
    proxy: true,
    // saveUninitialized: false,
    resave: false,
    saveUninitialized: true,  // Requis pour s'assurer de creer le cookie avant ouverture socket.io (call /verifier)
    // resave: true,
  }

  debug("Setup session hostname %s avec path : %s\n%O", hostname, pathApp, sessionConfig)
  const sessionMiddleware = session(sessionConfig)

  // Utiliser la session pour toutes les routes
  app.use(sessionMiddleware)
  app.use(transferHeaders)
  if( ! opts.noPreAuth ) app.use(verifierAuthentification)

  // Configurer server et socket.io
  const server = _initServer(app, hostname)
  const socketIo = _initSocketIo(server, sessionMiddleware, configurerEvenements, opts)

  // Injecter DAOs
  const {comptesUsagersDao} = initComptesUsagers(amqpdao)
  app.use((req, res, next)=>{
    req.amqpdao = amqpdao
    req.comptesUsagersDao = comptesUsagersDao
    next()
  })
  socketIo.use((socket, next)=>{
    socket.amqpdao = amqpdao
    socket.comptesUsagersDao = comptesUsagersDao
    socket.comptesUsagers = comptesUsagersDao

    if(opts.verifierAutorisation) {
      socket.verifierAutorisation = opts.verifierAutorisation
    }

    next()
  })

  debug('Demarrage server %s:%s', hostname, port)
  server.listen(port)

  return {server, socketIo, amqpdao}
}

function _initServer(app, hostname) {
  // Serveurs supportes : https, spdy, (http2)
  const serverType = process.env.SERVER_TYPE || 'spdy'
  const serverTypeLib = require(serverType)
  debug("server: Type de serveur web : %s", serverType)

  const config = {
      hostIp: hostname,
      cert: _certPems.cert,
      key: _certPems.key,
  };

  const server = serverType === 'http2'?
    serverTypeLib.createSecureServer(config, app):
    serverTypeLib.createServer(config, app)

  return server
}

function _initSocketIo(server, sessionMiddleware, configurerEvenements, opts) {
  opts = opts || {}

  var pathSocketio = opts.pathApp
  var cookieName = 'millegrilles.io'
  if(opts.pathApp) {
    cookieName = opts.pathApp + '.io'
    cookieName = cookieName.replace('/', '')
  }
  const path = [pathSocketio, 'socket.io'].join('/')
  const ioConfig = {
    path,
    cookie: cookieName,
    // cookie: {
    //   name: cookieName,
    //   httpOnly: true,
    //   sameSite: "strict",
    //   maxAge: 86400
    // }
  }

  if(opts.socketIoCORS) {
    ioConfig.cors = opts.socketIoCORS
  }

  debug("Demarrage socket.io avec config %O", ioConfig)
  var socketIo = socketio(server, ioConfig)

  // Morgan logging
  const loggingType = process.env.NODE_ENV !== 'production' ? 'dev' : 'combined'

  // Injecter socketIo dans le routingKeyManager pour supporter reception
  // de messages.
  amqpdao.routingKeyManager.socketio = socketIo

  // Ajouter middleware
  const socketioSessionMiddleware = socketioSession(sessionMiddleware, {autoSave: true})
  socketIo.use(socketioSessionMiddleware)
  socketIo.use(socketActionsMiddleware(configurerEvenements, opts))
  socketIo.on('connection', (socket) => {
    debug("server4._initSocketIo: Connexion id = %s, remoteAddress = %s", socket.id, socket.conn.remoteAddress);
    socket.on('disconnect', reason=>{
      if(reason === 'transport error') {
        console.error("ERROR server4._initSocketIo: Connexion id = %s, remoteAddress = %s err: %O", socket.id, socket.conn.remoteAddress, reason);
      }
    })
  })

  return socketIo
}

function socketActionsMiddleware(configurerEvenements, opts) {
  opts = opts || {}

  const _configurerEvenements  = configurerEvenements

  const middleware = (socket, next) => {
    // Injecter mq
    socket.amqpdao = amqpdao
    const headers = socket.handshake.headers
    debug("server4.socketActionsMiddleware Headers: %O", headers)

    // Configuration des listeners de base utilises pour enregistrer ou
    // retirer les listeners des sockets
    const configurationEvenements = _configurerEvenements(socket)
    socket.configurationEvenements = configurationEvenements
    debug("server4.socketActionsMiddleware Configuration evenements : %O", socket.configurationEvenements)

    // Injecter nom d'usager sur le socket
    let nomUsager = headers['x-user-name'],
        userId = headers['x-user-id']

    // Determiner score d'authentification
    let authScore = headers['x-user-authscore']

    if(!userId) {
      if(opts.noPreAuth) {
        // Mode maitredescomptes, utilise session pour charger valeurs si disponible
        if(!nomUsager) nomUsager = session.nomUsager
        if(!userId) userId = session.userId
        if(!authScore) authScore = session.authScore
      } else {
        debug("ERREUR server4.socketActionsMiddleware : headers.user-id n'est pas fourni")
        console.error("ERREUR server4.socketActionsMiddleware : headers.user-id n'est pas fourni")
        return socket.disconnect()
      }
    }

    if(authScore) {
      authScore = Number(authScore)
    } else {
      authScore = 0
    }

    // Conserver l'information sur le socket (utiliser par apps)
    socket.nomUsager = nomUsager
    socket.userId = userId
    socket.authScore = authScore

    // Enregistrer evenements publics de l'application
    enregistrerListener(socket, configurationEvenements.listenersPublics)
    socket.activerListenersPrives = _ => enregistrerListenersPrives(socket, configurationEvenements.listenersPrives, opts)
    socket.activerModeProtege = _ => {activerModeProtege(socket, configurationEvenements.listenersProteges)}

    if(authScore > 0) {
      // On peut activer options privees, l'usager est authentifie
      debug("Configurer evenements prives : %O", configurationEvenements.listenersPrives)
      socket.activerListenersPrives()
    }

    socket.on('unsubscribe', (params, cb) => unsubscribe(socket, params, cb))
    socket.on('downgradePrive', (params, cb) => downgradePrive(socket, params, cb))
    socket.on('genererChallengeCertificat', async cb => {cb(await genererChallengeCertificat(socket))})
    socket.on('getCertificatsMaitredescles', async cb => {cb(await getCertificatsMaitredescles(socket))})

    socket.subscribe =   (params, cb) => { subscribe(socket, params, cb) }
    socket.unsubscribe = (params, cb) => { unsubscribe(socket, params, cb) }
    socket.modeProtege = false

    socket.on('getInfoIdmg', (params, cb) => getInfoIdmg(socket, params, cb, opts))

    debug("Socket events apres connexion: %O", Object.keys(socket._events))

    next()
  }

  return middleware

}

function enregistrerListenersPrives(socket, listenersPrives, opts) {
  opts = opts || {}
  const session = socket.handshake.session
  const {nomUsager} = socket
  enregistrerListener(socket, listenersPrives)
  debug("Listeners prives usager %s\n%O", nomUsager, listenersPrives)

  socket.on('upgradeProtege', async (params, cb) => {
    debug("server4.enregistrerListenersPrives event upgradeProtege %O / session %O", params, session)
    const resultat = await veriferUpgradeProtegerApp(socket, params, opts)
    debug("server4.enregistrerListenersPrives event upgradeProtege resultat %O", resultat)
    cb(resultat)
  })
}

function activerModeProtege(socket, listenersProteges) {
  const session = socket.handshake.session

  enregistrerListener(socket, listenersProteges)
  debug("Activation mode protege pour socketId %s\n%O", socket.id, Object.values(socket._events))

  socket.modeProtege = true
  socket.emit('modeProtege', {'etat': true})
}

function downgradePrive(socket, params, cb) {
  try {
    const nomUsager = socket.nomUsager
    socket.modeProtege = false
    debug("Downgrade vers mode prive - usager %s", nomUsager)
    socket.emit('modeProtege', {'etat': false})

    const listenersProtegesMillegrilles = socket.configurationEvenements.listenersProteges
    debug("Listeners proteges millegrilles\n%O", listenersProtegesMillegrilles)
    retirerListener(socket, listenersProtegesMillegrilles)

    // Retrait subscribe
    socket.removeAllListeners('subscribe')

    debug("Socket events apres downgrade: %O", Object.keys(socket._events))

    if(cb) cb(true)
  } catch(err) {
    console.error('server4.downgradePrive error : %O', err)
    if(cb) cb(false)
  }
}

function enregistrerListener(socket, collectionListener) {
  debug("server4.enregistrerListener %O", collectionListener)
  for(let idx in collectionListener) {
    const listener = collectionListener[idx]
    debug("Ajout listener %s", listener.eventName)
    if(listener.eventName) {
      socket.on(listener.eventName, listener.callback)
    }
  }
}

function retirerListener(socket, collectionListener) {
  for(let idx in collectionListener) {
    const listener = collectionListener[idx]
    debug("Retrait du listener %s", listener.eventName)
    socket.removeAllListeners(listener.eventName) //, listener.callback)
  }
}

function subscribe(socket, params, cb) {
  try {
    debug("Subscribe : %O", params)

    const routingKeys = params.routingKeys
    const niveauxSecurite = params.exchange || ['2.prive']
    debug("Subscribe securite %O, %O", niveauxSecurite, routingKeys)

    const amqpdao = socket.amqpdao
    const channel = amqpdao.channel,
          reply_q = amqpdao.reply_q

    niveauxSecurite.forEach(niveauSecurite=>{
      amqpdao.routingKeyManager.addRoutingKeysForSocket(socket, routingKeys, niveauSecurite, channel, reply_q)
    })

    debug("Socket events apres subscribe: %O", Object.keys(socket._events))

    if(cb) cb(true)
  } catch(err) {
    console.error('server4.subscribe error : %O', err)
    if(cb) cb(false)
  }
}

function unsubscribe(socket, params, cb) {
  try {
    const routingKeys = params.routingKeys
    if(routingKeys) {
      routingKeys.forEach(rk=>{
        socket.leave(rk)
      })
    }
    if(cb) cb(true)
  } catch(err) {
    console.error('server4.subscribe error : %O', err)
    if(cb) cb(false)
  }

}

function getInfoIdmg(socket, params, cb, opts) {
  const session = socket.handshake.session,
        headers = socket.handshake.headers
  debug("server4.getInfoIdmg headers: %O\nsession %O", headers, session)

  const idmg = socket.amqpdao.pki.idmg
  let nomUsager = headers['x-user-name'] || socket.nomUsager
  let userId = headers['x-user-id'] || socket.userId

  if(!userId && opts.noPreAuth) {
    // Maitre des comptes - permettre d'utiliser la session pour recuperer l'information
    nomUsager = session.nomUsager
    userId = session.userId
  }

  cb({idmg, nomUsager, userId})
}

async function getCertificatsMaitredescles(socket, cb) {
  debug("server4.getCertificatsMaitredescles")

  const amqpdao = socket.amqpdao
  const domaineAction = 'MaitreDesCles.certMaitreDesCles'
  const params = {}

  try {
    debug("Requete certificats maitredescles")
    const reponse = await amqpdao.transmettreRequete(domaineAction, params, {decoder: true})
    debug("Reponse certificats maitredescles %O", reponse)
    return reponse
  } catch(err) {
    debug("Erreur traitement liste applications\n%O", err)
    return {err}
  }

}

function transferHeaders(req, res, next) {
  /* Transferer infortion des headers vers la session. */
  const session = req.session
  if( ! session.nomUsager ) {
    session.nomUsager = req.headers['x-user-name']
    session.userId = req.headers['x-user-id']
    session.authScore = req.headers['x-user-authscore']
  }
  next()
}

function verifierAuthentification(req, res, next) {
  const session = req.session
  if( ! (session.nomUsager && session.userId) ) {
    debug("Nom usager/userId ne sont pas inclus dans les req.headers : %O", req.headers)
    return res.sendStatus(403)
  }
  next()
}

function calculerAuthScore(auth) {
  if(!auth) return 0
  const score = Object.values(auth)
    .reduce((score, item)=>{return score + item}, 0)
  return score
}

module.exports = initialiser
