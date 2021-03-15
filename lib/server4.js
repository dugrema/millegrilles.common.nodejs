const debug = require('debug')('millegrilles:common:server4')
const fs = require('fs')
const socketio = require('socket.io')
const morgan = require('morgan')
const session = require('express-session')
const MemoryStore = require('memorystore')(session)
const socketioSession = require('express-socket.io-session')

const MilleGrillesPKI = require('./pki')
const MilleGrillesAmqpDAO = require('./amqpdao')

// Preparer certificats
const _certPems = {
  millegrille: fs.readFileSync(process.env.MG_MQ_CAFILE).toString('utf-8'),
  cert: fs.readFileSync(process.env.MG_MQ_CERTFILE).toString('utf-8'),
  key: fs.readFileSync(process.env.MG_MQ_KEYFILE).toString('utf-8'),
}

const secretCookiesPassword = 'moncookiesecret98321'
const hostname = process.env.HOST

// Charger PKI
const instPki = new MilleGrillesPKI()
const amqpdao = new MilleGrillesAmqpDAO(instPki)

// Middleware, injecte l'instance
const middlewareAmqpdao = (req, res, next) => {
  req.amqpdao = amqpdao
  next()
}

async function initialiser(app, configurerEvenements, opts) {
  opts = opts || {}

  // Connecter a MQ
  debug("Initialiser MQ")
  await instPki.initialiserPkiPEMS(_certPems)
  await amqpdao.connect(process.env.MG_MQ_URL)
  debug("AMQPDAO connexion prete")

  // Morgan logging
  const loggingType = process.env.NODE_ENV !== 'production' ? 'dev' : 'combined'
  app.use(morgan('combined'))

  const hostname = process.env.HOST
  const port = process.env.PORT || '443'
  const pathApp = opts.pathApp || '/'

  debug("Setup session hostname %s avec path : %s", hostname, pathApp)
  const sessionMiddleware = session({
    secret: secretCookiesPassword,
    cookie: { path: pathApp, domain: hostname, sameSite: 'strict', secure: true, maxAge: 3600000 },
    store: new MemoryStore({
      checkPeriod: 3600000 // prune expired entries every 1h
    }),
    proxy: true,
    resave: false,
  })

  // Utiliser la session pour toutes les routes
  app.use(sessionMiddleware)

  // Configurer server et socket.io
  const server = _initServer(app, hostname)
  const socketIo = _initSocketIo(server, sessionMiddleware, configurerEvenements, opts)

  // _configurerRoutes(root, apps)

  debug('Demarrage server %s:%s', hostname, port)
  server.listen(port)

  return {server, socketIo}
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
  const path = [pathSocketio, 'socket.io'].join('/')
  debug("Demarrage socket.io sur %s", path)
  var socketIo = socketio(server, {path})

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
    debug("socketio: Connexion id = %s, remoteAddress = %s", socket.id, socket.conn.remoteAddress);
  })

}

function socketActionsMiddleware(configurerEvenements, opts) {

  const _configurerEvenements  = configurerEvenements

  const middleware = (socket, next) => {
    // Injecter mq
    socket.amqpdao = amqpdao

    // Configuration des listeners de base utilises pour enregistrer ou
    // retirer les listeners des sockets
    socket.configurationEvenements = _configurerEvenements(socket)
    debug("Configuration evenements : %O", socket.configurationEvenements)

    socket.on('upgradeProtege', (params, cb) => upgradeProtege(socket, params, cb))
    socket.on('downgradePrive', (params, cb) => downgradePrive(socket, params, cb))
    socket.on('getInfoIdmg', (params, cb) => getInfoIdmg(socket, params, cb))

    // socket.upgradeProtege =        cb => { upgradeProtege(socket, cb) }
    // socket.downgradePrive =        cb => { downgradePrive(socket, cb) }
    socket.subscribe =   (params, cb) => { subscribe(socket, params, cb) }
    socket.unsubscribe = (params, cb) => { unsubscribe(socket, params, cb) }
    socket.modeProtege = false

    debug("Socket events apres connexion: %O", Object.keys(socket._events))

    next()
  }

  return middleware

}

function upgradeProtege(socket, params, cb) {
  try {
    const nomUsager = socket.nomUsager
    socket.modeProtege = true
    debug("Activation mode protege - usager %s", nomUsager)

    const listenersProtegesMillegrilles = socket.configurationEvenements.listenersProteges
    debug("Listeners proteges millegrilles\n%O", listenersProtegesMillegrilles)
    enregistrerListener(socket, listenersProtegesMillegrilles)

    if(socket._events) {
      debug("Socket events apres upgrade: %O", Object.keys(socket._events))
    }
    if(cb) cb(true)

  } catch(err) {
    console.error('server4.upgradeProtege error : %O', err)
    if(cb) cb(false)
  }


}

function downgradePrive(socket, params, cb) {
  try {
    const nomUsager = socket.nomUsager
    socket.modeProtege = false
    debug("Downgrade vers mode prive - usager %s", nomUsager)

    const listenersProtegesMillegrilles = socket.configurationEvenements.listenersProteges
    debug("Listeners proteges millegrilles\n%O", listenersProtegesMillegrilles)
    retirerListener(socket, listenersProtegesMillegrilles)

    debug("Socket events apres downgrade: %O", Object.keys(socket._events))

    if(cb) cb(true)
  } catch(err) {
    console.error('server4.downgradePrive error : %O', err)
    if(cb) cb(false)
  }
}

function enregistrerListener(socket, collectionListener) {
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
    socket.off(listener.eventName, listener.callback)
  }
}

function subscribe(socket, params, cb) {
  try {
    debug("Subscribe : %O", params)

    const routingKeys = params.routingKeys
    const niveauSecurite = params.exchange || '2.prive'
    debug("Subscribe securite %s, %O", niveauSecurite, routingKeys)

    const amqpdao = socket.amqpdao
    const channel = amqpdao.channel,
          reply_q = amqpdao.reply_q

    amqpdao.routingKeyManager.addRoutingKeysForSocket(socket, routingKeys, niveauSecurite, channel, reply_q)

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
  const session = socket.handshake.session
  const comptesUsagers = socket.comptesUsagers
  debug("server4.getInfoIdmg session %O", session)

  // TODO - Verifier challenge
  cb({idmgCompte: session.idmgCompte, idmgsActifs: session.idmgsActifs})
}

module.exports = initialiser
