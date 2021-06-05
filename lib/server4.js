const debug = require('debug')('millegrilles:common:server4')
const fs = require('fs')
const socketio = require('socket.io')
const morgan = require('morgan')
const session = require('express-session')
//const MemoryStore = require('memorystore')(session)
const FileStore = require('session-file-store')(session)
const socketioSession = require('express-socket.io-session')
const {v4: uuidv4} = require('uuid')

const { genererChallengeCertificat, upgradeProteger, upgradeProtegeCertificat } = require('./authentification')
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
  var urlMq = process.env.MG_MQ_URL
  if(!urlMq) {
    urlMq = 'amqps://' + process.env.MQ_HOST
    if(process.env.MQ_PORT) urlMq = `${urlMq}:${process.env.MQ_PORT}`
  }
  await amqpdao.connect(urlMq)
  console.info("server4.initialiser AMQPDAO connexion prete sur %s", urlMq)

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
    saveUninitialized: true,
    store: new FileStore(),
    proxy: true,
    resave: false,
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
    next()
  })

  // _configurerRoutes(root, apps)

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
  // const morganMiddleware = morgan(loggingType, 'immediate')
  // socketIo.use((socket, next) => {morganMiddleware(socket.handshake, null, next)})

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

    // Injecter nom d'usager
    const userId = headers['user-id']
    if(!userId && !opts.noPreAuth) {
      debug("ERREUR server4.socketActionsMiddleware : headers.user-id n'est pas fourni")
      console.error("ERREUR server4.socketActionsMiddleware : headers.user-id n'est pas fourni")
      return socket.disconnect()
    }

    if(userId) {  // On peut activer options privees, l'usager est authentifie
      const nomUsager = socket.handshake.headers['user-name']
      socket.nomUsager = nomUsager
      socket.userId = userId
      socket.idmg = amqpdao.pki.idmg

      debug("Configurer evenements prives : %O", configurationEvenements.listenersPrives)
      enregistrerListener(socket, configurationEvenements.listenersPrives)

      if(opts.upgradeProtegeComplet) {
        socket.on('upgradeProtege', (params, cb) => upgradeProtegeCompletVerification(socket, params, cb))
      } else {
        socket.on('upgradeProtege', (params, cb) => upgradeProtegeVerification(socket, params, cb))
      }
    }

    // Enregistrer evenements publics de l'application
    enregistrerListener(socket, configurationEvenements.listenersPublics)

    socket.on('unsubscribe', (params, cb) => unsubscribe(socket, params, cb))
    socket.on('downgradePrive', (params, cb) => downgradePrive(socket, params, cb))
    socket.on('genererChallengeCertificat', async cb => {cb(await genererChallengeCertificat(socket))})
    socket.on('getCertificatsMaitredescles', async cb => {cb(await getCertificatsMaitredescles(socket))})

    socket.subscribe =   (params, cb) => { subscribe(socket, params, cb) }
    socket.unsubscribe = (params, cb) => { unsubscribe(socket, params, cb) }
    socket.modeProtege = false
    // } else {
    //   // Enregistrer evenements publics
    //   debug("Enregistrer evenements publics")
    //   enregistrerListener(socket, configurationEvenements.listenersPublics)
    // }
    socket.on('getInfoIdmg', (params, cb) => getInfoIdmg(socket, params, cb))

    debug("Socket events apres connexion: %O", Object.keys(socket._events))

    next()
  }

  return middleware

}

async function upgradeProtegeCompletVerification(socket, params, cb) {

  try {
    if( await upgradeProteger(socket, params) ) {
      const nomUsager = socket.nomUsager
      socket.modeProtege = true
      socket.emit('modeProtege', {'etat': true})
      debug("Activation mode protege - usager %s", nomUsager)

      const listenersProtegesMillegrilles = socket.configurationEvenements.listenersProteges
      debug("Listeners proteges millegrilles\n%O", listenersProtegesMillegrilles)
      enregistrerListener(socket, listenersProtegesMillegrilles)

      socket.on('subscribe', (params, cb) => subscribe(socket, params, cb))

      if(socket._events) {
        debug("Socket events apres upgrade: %O", Object.keys(socket._events))
      }

      if(cb) cb(true)
      return
    }

  } catch(err) {
    console.error('server4.upgradeProtege error : %O', err)
  }

  if(cb) cb(false)

}

async function upgradeProtegeVerification(socket, params, cb) {

  try {
    if( await upgradeProtegeCertificat(socket, params) ) {
      const nomUsager = socket.nomUsager
      socket.modeProtege = true
      socket.emit('modeProtege', {'etat': true})
      debug("Activation mode protege - usager %s", nomUsager)

      const listenersProtegesMillegrilles = socket.configurationEvenements.listenersProteges
      debug("Listeners proteges millegrilles\n%O", listenersProtegesMillegrilles)
      enregistrerListener(socket, listenersProtegesMillegrilles)

      socket.on('subscribe', (params, cb) => subscribe(socket, params, cb))

      if(socket._events) {
        debug("Socket events apres upgrade: %O", Object.keys(socket._events))
      }

      if(cb) cb(true)
      return
    }

  } catch(err) {
    console.error('server4.upgradeProtege error : %O', err)
  }

  if(cb) cb(false)

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

function getInfoIdmg(socket, params, cb) {
  // const session = socket.handshake.session
  // const comptesUsagers = socket.comptesUsagers
  debug("server4.getInfoIdmg headers: %O\nsession %O", socket.handshake.headers, session)

  // TODO - Verifier challenge
  const idmg = socket.idmg
  const nomUsager = socket.nomUsager
  const userId = socket.userId
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
    session.nomUsager = req.headers['user-name']
    session.userId = req.headers['user-id']
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

module.exports = initialiser
