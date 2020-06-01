const debug = require('debug')('millegrilles:common:server')
const fs = require('fs')
const socketio = require('socket.io')
const logger = require('morgan')

// Initialise une liste d'applications sur unr root express()
// apps : dictionnaire format { path : {route, socketio} }
//        path : path relatif -> (root.use(path, route))
//       route : objet express()
//    socketio : {function addSocket(socket), string pathSocketio}
function initialiser(root, apps) {

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

  for(let path in apps) {
    debug("Ajouter route /%s", path)
    const app = apps[path]
    const route = app.route

    // Ajouter socket.io au besoin
    if(app.socketio) {
      _initSocketIo(server, app.socketio, {path})
    }

    // Mapper via Express
    root.use('/' + path, route)
  }

  server.listen(port)


  return server
}

function _initSocketIo(server, paramsSocketio, opts) {
  if(!opts) opts = {}

  const path = paramsSocketio.pathSocketio || '/' + opts.path + '/socket.io'
  debug("Demarrage socket.io sur %s", path)

  const socketIo = socketio(server, {path});

  socketIo.on('connection', async (socket) => {
    debug("server:Connexion socket.IO id = %s, remoteAddress = %s", socket.id, socket.conn.remoteAddress);
    try {
      await paramsSocketio.addSocket(socket);
    } catch(err) {
      console.error("Erreur connexion websocket")
      console.error(err)
      socket.close()
    }
  });

}

function _initLogging(app) {
  const loggingType = process.env.NODE_ENV !== 'production' ? 'dev' : 'combined';
  app.use(logger(loggingType));  // logging
}

module.exports = {initialiser}
