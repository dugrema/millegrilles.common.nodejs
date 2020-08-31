const debug = require('debug')('millegrilles:common:server2')
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

  // Serveurs supportes : https, spdy, (http2)
  const serverType = process.env.SERVER_TYPE || 'spdy'
  const serverTypeLib = require(serverType)
  debug("server: Type de serveur web : %s", serverType)

  const certPem = fs.readFileSync(process.env.MG_MQ_CERTFILE).toString('utf-8');
  const keyPem = fs.readFileSync(process.env.MG_MQ_KEYFILE).toString('utf-8');
  const certMillegrillePem = fs.readFileSync(process.env.MG_MQ_CAFILE).toString('utf-8');

  const hostIp = process.env.HOST;
  const port = process.env.PORT || '443'
  const config = {
      hostIp: hostIp,
      cert: certPem,
      key: keyPem,
  };
  debug('Demarrage server %s:%s', hostIp, port)

  const server = serverType === 'http2'?
    serverTypeLib.createSecureServer(config, root):
    serverTypeLib.createServer(config, root)

  // Preparer evenements et subscriptions pour toutes les apps
  for(let path in apps) {
    const app = apps[path]
    // Conserver methode de configuration pour chaque application
    configurationEvenements[path] = app.configurationEvenements
  }

  var socketIoAddSocketHooksCommun = null

  for(let path in apps) {
    debug("Ajouter route /%s", path)
    const app = apps[path]
    const route = app.route

    var pathSocketio = opts.pathSocketio
    if( !pathSocketio ) pathSocketio = path

    // Ajouter socket.io au besoin
    if(app.socketio) {
      debug("Creation socket.io sur path /%s", pathSocketio)
      const {socketIo, addSocketHooks} = _initSocketIo(server, app.socketio, {path: pathSocketio})
      if(!socketIoAddSocketHooksCommun) {
        socketIoAddSocketHooksCommun = addSocketHooks
      }
      if(opts.mqList) {
        opts.mqList.forEach(mq=>{
          debug("Injecter socket.IO dans connexions MQ idmg %s", mq.pki.idmg)
          mq.routingKeyManager.socketio = socketIo
        })
      }
    }

    if(app.addSocket) { // Ajout socket a socketIo commun
      // _initSocketIo(server, app.addSocket)
      if(!socketIoAddSocketHooksCommun) {
        throw new Error("Socket.IO commun n'a pas ete configure (chargement " + path + ")")
      }
      debug("Ajout addSocket hook sur socket.io commun pour %s", path)
      socketIoAddSocketHooksCommun.push(app.addSocket)
    }

    debug("Socket.io hooks\n%O", socketIoAddSocketHooksCommun)

    // Mapper via Express
    root.use('/' + path, route)
  }

  server.listen(port)

  return server
}

function injecterConfiguration(socket) {
  socket.configurationEvenements = configurationEvenementsSocket
}

function _initSocketIo(server, paramsSocketio, opts) {
  if(!opts) opts = {}

  // Extraire configuration d<evenements  et de subscription
  const addSocketHooks = []

  const path = paramsSocketio.pathSocketio || '/' + opts.path + '/socket.io'
  debug("Demarrage socket.io sur %s, keys params: %s", path, Object.keys(paramsSocketio))

  var socketIo = socketio(server, {path})

  debug("Ajouter connection listener sur Socket.IO pour %s", path)
  socketIo.on('connection', async (socket) => {
    debug("server:Connexion socket.IO id = %s, remoteAddress = %s", socket.id, socket.conn.remoteAddress);
    try {

      // Configuration des listeners de base utilises pour enregistrer ou
      // retirer les listeners des sockets
      socket.configurationEvenements = {}
      for(let app in configurationEvenements) {
        socket.configurationEvenements[app] = configurationEvenements[app](socket)
      }
      debug("Configuration evenements : %O", socket.configurationEvenements)

      socket.upgradeProtege = _=>{upgradeProtege(socket)}
      socket.downgradePrive = _=>{downgradePrive(socket)}
      socket.changerApplication = application =>{changerApplication(socket, application)}
      socket.estProprietaire = false
      socket.modeProtege = false

      debug("socketIo.on(connection): Configuration evenements\n%O", socket.configurationEvenements)

      // await paramsSocketio.addSocket(socket);
      debug("Hooks:\n%O", addSocketHooks)
      for(let idx in addSocketHooks) {
        debug("Ajout hook %d", idx)
        const hook = addSocketHooks[idx]
        await hook(socket)
      }

      // Configurer application courante, evenements prives millegrilles
      socket.applicationCourante = ''
      const listenersPrives = socket.configurationEvenements['millegrilles'].listenersPrives
      debug("Listeners prives millegrilles\n%O", listenersPrives)
      enregistrerListener(socket, listenersPrives)

      if(socket.modeProtege) {
        socket.upgradeProtege()
      }

      debug("server:Connexion socket.IO prete. id = %s, remoteAddress = %s", socket.id, socket.conn.remoteAddress);
    } catch(err) {
      console.error("Erreur connexion websocket")
      console.error(err)
      socket.close()
    }
  })

  if(paramsSocketio.configurerServer) {
    debug("Configurer server Socket.IO pour %s", path)
    paramsSocketio.configurerServer(socketIo)
  }

  if(paramsSocketio.session) {
    debug("Ajouter lecteur de session expressjs a socket.io")
    socketIo.use(paramsSocketio.session)
  }

  if(paramsSocketio.callbackSetup) {
    // Methode qui permet d'effectuer des configurations additionnelles
    // sur les routes a configurer
    debug("Configuration callbackSetup")
    paramsSocketio.callbackSetup(socketIo)
  }

  if(paramsSocketio.addSocket) {
    addSocketHooks.push(paramsSocketio.addSocket)
  }

  return {socketIo, addSocketHooks}
}

function _initLogging(app) {
  const loggingType = process.env.NODE_ENV !== 'production' ? 'dev' : 'combined';
  app.use(logger(loggingType));  // logging
}

function upgradeProtege(socket) {
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

  debug("Socket events apres upgrade: %O", Object.keys(socket._events))
}

function enregistrerListener(socket, collectionListener) {
  for(let idx in collectionListener) {
    const listener = collectionListener[idx]
    debug("Ajout listener %s", listener.eventName)
    socket.on(listener.eventName, listener.callback)
  }
}

function changerApplication(socket, application) {
  debug("Changer listeners de %s vers %s, mode protege=%s", socket.application, application, socket.modeProtege)

  if(socket.application) {
    // Enlever listeners pour application precedente
    const listenersProtegesApplication = socket.configurationEvenements[socket.application].listenersProteges
    const listenersPrivesApplication = socket.configurationEvenements[socket.application].listenersProteges
    debug("Listeners proteges %s\n%O", application, listenersProtegesApplication)
    enregistrerListener(socket, [...listenersProtegesApplication, ...listenersPrivesApplication])
  }

  socket.application = application

  if(application) {
    // Enregistrer listeners pour application
    const listenersPrivesApplication = socket.configurationEvenements[socket.application].listenersProteges
    var listeners = [...listenersPrivesApplication]
    if(socket.modeProtege) {
      const listenersProtegesApplication = socket.configurationEvenements[socket.application].listenersProteges
      listeners = [...listeners, listenersProtegesApplication]
    }
    enregistrerListener(socket, listeners)
  }

  debug("Socket events apres changement application: %O", Object.keys(socket._events))
}

function downgradePrive(socket) {
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

}

function retirerListener(socket, collectionListener) {
  for(let idx in collectionListener) {
    const listener = collectionListener[idx]
    debug("Retrait du listener %s", listener.eventName)
    socket.off(listener.eventName, listener.callback)
  }
}

module.exports = {initialiser}
