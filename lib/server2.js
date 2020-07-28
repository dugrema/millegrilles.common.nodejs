const debug = require('debug')('millegrilles:common:server')
const fs = require('fs')
const socketio = require('socket.io')
const logger = require('morgan')

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
      const {addSocketHooks} = _initSocketIo(server, app.socketio, {path: pathSocketio})
      if(!socketIoAddSocketHooksCommun) {
        socketIoAddSocketHooksCommun = addSocketHooks
      }
    }

    if(app.addSocket) { // Ajout socket a socketIo commun
      // _initSocketIo(server, app.addSocket)
      if(!socketIoAddSocketHooksCommun) {
        throw new Error("Socket.IO commun n'a pas ete configure (chargement %s)", path)
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

function _initSocketIo(server, paramsSocketio, opts) {
  if(!opts) opts = {}

  const addSocketHooks = []

  const path = paramsSocketio.pathSocketio || '/' + opts.path + '/socket.io'
  debug("Demarrage socket.io sur %s", path)
  debug(paramsSocketio)

  var socketIo = socketio(server, {path})

  debug("Ajouter connection listener sur Socket.IO pour %s", path)
  socketIo.on('connection', async (socket) => {
    debug("server:Connexion socket.IO id = %s, remoteAddress = %s", socket.id, socket.conn.remoteAddress);
    try {
      // await paramsSocketio.addSocket(socket);
      debug("Hooks:\n%O", addSocketHooks)
      for(let idx in addSocketHooks) {
        debug("Ajout hook %d", idx)
        const hook = addSocketHooks[idx]
        hook(socket)
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

module.exports = {initialiser}
