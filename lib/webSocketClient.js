// Classe helper pour connecter le navigateur (client) via Socket.IO
// DEPRECATED - remplacer par connexionClient.js
export class WebSocketClient {

  constructor(socket, opts) {
    if(!opts) opts = {}
    this.opts = opts
    this.socket = socket
    this.addSocket(socket)
  }

  addSocket(webSocket) {

    webSocket.on('erreur', erreur=>{
      console.error("Erreur recue par Socket.IO");
      console.error(erreur);
    })

    return Promise.resolve()

  }

  deconnecter() {
    // console.debug("Deconnecter socket.io")
    if(this.socket != null) {
      this.socket.disconnect()
      this.socket = null
    }
  }

  getWebSocket() {
    return this.socket;
  }

  getClesChiffrage() {
    console.debug("Demande cles chiffrage")
    return new Promise((resolve, reject)=>{
      this.socket.emit('grosfichiers/getClesChiffrage', reponse=>{
        if(reponse.err) reject(reponse.err)
        resolve(reponse)
      })
    })
  }

  getFichiersActivite() {
    return new Promise((resolve, reject)=>{
      this.socket.emit('grosfichiers/getActivite', reponse=>{
        if(reponse.err) return reject(reponse.err)
        resolve(reponse)
      })
    })
  }

  subscribe(routingKeys, callback, opts) {
    if(!opts) opts = {}

    const niveauSecurite = opts.exchange || '2.prive'
    // console.debug("Subscribe securite %s, %O", niveauSecurite, routingKeys)

    const callbackFilter = function(message) {
      if(!message) return

      // Filtrer par routing key
      const routingKey = message.routingKey

      if(routingKeys.includes(routingKey) && niveauSecurite === message.exchange) {
        // console.debug("Message subscription recu %s:\n%O", routingKey, message)
        try {
          callback(message)
        } catch(err) {
          console.error("Erreur traitement callback sur %s", routingKey)
        }
      }
    }

    const socket = this.socket

    // Transmet une liste de routingKeys a enregistrer sur notre Q.
    socket.emit('subscribe', {routingKeys, exchange: niveauSecurite})

    // socket.on('mq_evenement', callbackFilter)
    const domainesActions = getDomainesActions(routingKeys)
    // console.debug("Enregistrer listeners domaineAction : %O", domainesActions)
    domainesActions.forEach(domaineAction=>{
      this.socket.on(domaineAction, callback)
    })

    // Retourne une methode pour faire le "unsubscribe"
    return callbackFilter
  }

  unsubscribe(routingKeys, callback, opts) {
    // Retrait du listener d'evenement
    // console.debug("Unsubscribe callback, socket.off %O", routingKeys)
    this.socket.emit('unsubscribe', {callback, opts})

    const domainesAction = getDomainesActions(routingKeys)
    domainesAction.forEach(domaineAction=>{
      this.socket.off(domaineAction, callback)
    })

  }

  emitBlocking(event, params) {
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
        this.socket.emit(event, params, traiterReponse)
      } else {
        this.socket.emit(event, traiterReponse)
      }

    })
  }

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
