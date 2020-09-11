const debug = require('debug')('millegrilles:common:server3')
const fs = require('fs')
const socketio = require('socket.io')
const logger = require('morgan')

const configurationEvenements = {}

// Initialise une liste d'applications sur unr root express()
// apps : dictionnaire format { path : {route, socketio} }
//        path : path relatif -> (root.use(path, route))
//       route : objet express()
//    socketio : {function addSocket(socket), string pathSocketio}
function initialiser(root, apps, opts) {
  if( !opts ) opts = {}

  _initLogging(root)

  const hostIp = process.env.HOST
  const port = process.env.PORT || '443'
  const server = _initServer(root, hostIp)

  const socketIo = _configurerSocketIo(server, apps, opts)

  _configurerRoutes(root, apps)

  debug('Demarrage server %s:%s', hostIp, port)
  server.listen(port)

  return server
}

function _initServer(root, hostIp, port) {
  // Serveurs supportes : https, spdy, (http2)
  const serverType = process.env.SERVER_TYPE || 'spdy'
  const serverTypeLib = require(serverType)
  debug("server: Type de serveur web : %s", serverType)

  const certPem = fs.readFileSync(process.env.MG_MQ_CERTFILE).toString('utf-8');
  const keyPem = fs.readFileSync(process.env.MG_MQ_KEYFILE).toString('utf-8');
  const certMillegrillePem = fs.readFileSync(process.env.MG_MQ_CAFILE).toString('utf-8');

  const config = {
      hostIp: hostIp,
      cert: certPem,
      key: keyPem,
  };

  const server = serverType === 'http2'?
    serverTypeLib.createSecureServer(config, root):
    serverTypeLib.createServer(config, root)

  return server
}

function _configurerRoutes(root, apps) {
  for(let idx in apps) {
    const app = apps[idx]
    const path = app.path
    const route = app.route

    debug("Ajouter route /%s", path)

    // Mapper via Express
    root.use('/' + path, route)
  }
}

function _configurerSocketIo(server, apps, opts) {

  var pathSocketio = opts.pathSocketio || ''  // Par defaut, path /

  // Ajouter socket.io au besoin
  debug("Creation socket.io sur path /%s", pathSocketio)

  const socketIo = _initSocketIo(server,pathSocketio)

  if(opts.mqList) {
    opts.mqList.forEach(mq=>{
      debug("Injecter socket.IO dans connexions MQ idmg %s", mq.pki.idmg)
      mq.routingKeyManager.socketio = socketIo
    })
  }

  // Ajouter le middleware
  if(opts.sessionMiddleware) {
    debug("Socket.io : ajout session middleware")
    socketIo.use(opts.sessionMiddleware)
  }
  socketIo.use(socketActionsMiddleware)

  for(let idx in apps) {
    const app = apps[idx]
    const path = app.path
    const appSocketio = app.socketio || {}

    if(appSocketio.callbackPreSetup) {
      // Methode qui permet d'effectuer des configurations additionnelles
      // sur les routes a configurer avant les autres middlewares
      debug("Configuration callbackPreSetup app %s", path)
      appSocketio.callbackPreSetup(socketIo)
    }
  }

  if(opts.fctRabbitMQParIdmg) {
    debug("Socket.io : injection fctRabbitMQParIdmg")
    socketIo.use( (socket, next) => {
      socketInjectionMq(opts.fctRabbitMQParIdmg, socket, next)
    })
  }

  // Preparer evenements et subscriptions pour toutes les apps
  for(let idx in apps) {
    const app = apps[idx]
    const path = app.path
    const appSocketio = app.socketio || {}

    debug("Configuration socket.io, application %s\n%O", path, appSocketio)

    // Conserver methode de configuration pour chaque application
    if(appSocketio.configurationEvenements) {
      // Placer dans variable globale configurationEvenements
      configurationEvenements[path] = appSocketio.configurationEvenements
    }

    if(appSocketio.middleware) {
      debug("Ajout middleware app %s", path)
      socketIo.use(appSocketio.middleware)
    }

    if(appSocketio.callbackSetup) {
      // Methode qui permet d'effectuer des configurations additionnelles
      // sur les routes a configurer
      debug("Configuration callbackSetup app %s", path)
      appSocketio.callbackSetup(socketIo)
    }
  }

  socketIo.use(initialisationAppListeners)

  return socketIo
}

function _initSocketIo(server, pathSocketIo) {
  const path = ['', pathSocketIo, 'socket.io'].join('/')
  debug("Demarrage socket.io sur %s", path)
  var socketIo = socketio(server, {path})

  debug("Ajouter connection listener sur Socket.IO pour %s", path)
  socketIo.on('connection', onConnection)

  return socketIo
}

function socketActionsMiddleware(socket, next) {

  // Configuration des listeners de base utilises pour enregistrer ou
  // retirer les listeners des sockets
  socket.configurationEvenements = {}
  for(let app in configurationEvenements) {
    socket.configurationEvenements[app] = configurationEvenements[app](socket)
  }
  debug("Configuration evenements : %O", socket.configurationEvenements)
  socket.upgradeProtege = cb => {upgradeProtege(socket, cb)}
  socket.downgradePrive = cb => {downgradePrive(socket, cb)}
  socket.changerApplication = (application, cb) =>{changerApplication(socket, application, cb)}
  socket.estProprietaire = false
  socket.modeProtege = false

  debug("socketIo.on(connection): Configuration evenements\n%O", socket.configurationEvenements)

  // Configurer application courante, evenements prives millegrilles
  socket.applicationCourante = ''

  next()
}

function initialisationAppListeners(socket, next) {
  if(socket.configurationEvenements.millegrilles) {
    const listenersPrives = socket.configurationEvenements.millegrilles.listenersPrives
    debug("Listeners prives millegrilles\n%O", listenersPrives)
    enregistrerListener(socket, listenersPrives)
  } else {
    debug("WARN Listeners millegrilles non initialises - OK pour dev")
  }

  changerApplication(socket, socket.application)

  next()
}

function socketInjectionMq(fctRabbitMQParIdmg, socket, next) {
  debug("Injection amqpdao dans socket")

  var idmg = null
  if(socket.handshake.session) {
    debug("Session (handshake) : %O", socket.handshake.session)
    idmg = socket.handshake.session.idmgCompte
  }

  if(idmg) {
    debug("IDMG : %s", idmg)
    const amqpdao = fctRabbitMQParIdmg(idmg)
    debug("MQ trouve : %s", amqpdao?'Oui':'Non')
    socket.amqpdao = amqpdao
  } else {
    debug("WARN : idmg non trouve")
  }

  next()
}

async function onConnection(socket) {
  debug("server:Connexion socket.IO id = %s, remoteAddress = %s", socket.id, socket.conn.remoteAddress);
}

function _initLogging(app) {
  const loggingType = process.env.NODE_ENV !== 'production' ? 'dev' : 'combined';
  app.use(logger(loggingType));  // logging
}

function upgradeProtege(socket, callback) {
  socket.modeProtege = true
  const application = socket.application
  debug("Mode protege - usager, application %s", application)

  if(socket.configurationEvenements.millegrilles) {
    const listenersProtegesMillegrilles = socket.configurationEvenements.millegrilles.listenersProteges
    debug("Listeners proteges millegrilles\n%O", listenersProtegesMillegrilles)
    enregistrerListener(socket, listenersProtegesMillegrilles)
  } else {
    debug("WARN: listeners millegrilles non presents (OK pour dev)")
  }

  // Enregistrer tous les listeners proteges
  if(application) {
    const listenersProtegesApplication = socket.configurationEvenements[application].listenersProteges
    debug("Listeners proteges %s\n%O", application, listenersProtegesApplication)
    enregistrerListener(socket, listenersProtegesApplication)
  }

  if(socket._events) {
    debug("Socket events apres upgrade: %O", Object.keys(socket._events))
  }

  if(callback) {
    debug("Callback protege : %O", callback)
    callback(true)
  }
}

function changerApplication(socket, application, callback) {
  debug("Changer listeners de %s vers %s, mode protege=%s", socket.application, application, socket.modeProtege)
  debug("Applications avec listeners configurees :\n%O", Object.keys(socket.configurationEvenements))

  if(socket.application) {
    // Enlever listeners pour application precedente
    const listenersProtegesApplication = socket.configurationEvenements[socket.application].listenersProteges
    const listenersPrivesApplication = socket.configurationEvenements[socket.application].listenersPrives
    debug("Listeners proteges %s\n%O", application, listenersProtegesApplication)
    retirerListener(socket, [...listenersProtegesApplication, ...listenersPrivesApplication])
  }

  // Changement d'application
  socket.application = application

  if(socket.application) {
    const configurationEvenements = socket.configurationEvenements[socket.application]
    if(configurationEvenements) {
      // Enregistrer listeners pour application
      const listenersPrivesApplication = configurationEvenements.listenersPrives
      var listeners = null
      if(socket.modeProtege) {
        const listenersProtegesApplication = configurationEvenements.listenersProteges
        listeners = [...listenersPrivesApplication, ...listenersProtegesApplication]
      } else {
        listeners = [...listenersPrivesApplication]
      }
      enregistrerListener(socket, listeners)
    } else {
      debug("Aucuns listeners configures pour application %s", socket.application)
    }
  }

  const listeEvents = socket._events?Object.keys(socket._events):'[]'
  debug("Socket events apres changement application: %O", listeEvents)

  if(callback) {
    callback(true)
  }
}

function downgradePrive(socket, callback) {
  const application = socket.application
  socket.modeProtege = false
  debug("Downgrade vers mode prive - usager, application %s", application)

  if(socket.configurationEvenements.millegrilles) {
    const listenersProtegesMillegrilles = socket.configurationEvenements.millegrilles.listenersProteges
    debug("Listeners proteges millegrilles\n%O", listenersProtegesMillegrilles)
    retirerListener(socket, listenersProtegesMillegrilles)
  } else {
    debug("WARN: listeners millegrilles non presents (OK pour dev)")
  }

  // Enregistrer tous les listeners proteges
  if(application) {
    const listenersProtegesApplication = socket.configurationEvenements[application].listenersProteges
    debug("Listeners proteges %s\n%O", application, listenersProtegesApplication)
    retirerListener(socket, listenersProtegesApplication)
  }

  debug("Socket events apres downgrade: %O", Object.keys(socket._events))
  if(callback) {
    callback(true)
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

module.exports = {initialiser}
