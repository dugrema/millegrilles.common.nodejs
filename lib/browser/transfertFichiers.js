async function fetchAvecProgress(url, opts) {
  opts = opts || {}
  const progressCb = opts.progressCb,
        downloadToken = opts.downloadToken,
        DEBUG = opts.DEBUG

  var dataProcessor = opts.dataProcessor

  const reponse = await fetch(url)

  if(DEBUG) console.debug("Reponse object : %O", reponse)
  const reader = reponse.body.getReader()
  const contentLength = Number(reponse.headers.get('Content-Length'))

  progressCb(0, contentLength)

  if(dataProcessor && dataProcessor.start) {
    // Initialiser le data processor au besoin
    const actif = await dataProcessor.start(reponse)
    if(!actif) dataProcessor = null
  }

  const downloadEnvironment = {
    dataProcessor,  // Si present, permet d'appliquer un traitement sur les donnes au vol
    downloadToken,  // .cancel === true indique que le client veut annuler le download
    progressCb,
    DEBUG,
  }

  const downloadStream = _creerDownloadStream(reader, contentLength, downloadEnvironment)

  return {
    reader: downloadStream,
    headers: reponse.headers,
    status: reponse.status,
    downloadToken,
  }

}

const DECHIFFRAGE_TAILLE_BLOCK = 256 * 1024

function _creerDownloadStream(reader, contentLength, opts) {
  opts = opts || {}

  const downloadToken = opts.downloadToken,
        dataProcessor = opts.dataProcessor,
        DEBUG = opts.DEBUG

  const progressCb = opts.progressCb || function(){}  // Default fonction sans effet

  if(typeof(contentLength) === 'string') contentLength = Number(contentLength)

  var receivedLength = 0
  var done = false

  return new ReadableStream({
    start: controller => {
      if(DEBUG) console.debug("start _creerDownloadStream")
    },
    pull: async controller => {
      if(done) {
        if(DEBUG) console.debug("_creerDownloadStream - done deja sette, termine")
        controller.close()
        progressCb(contentLength, contentLength)  // Complet
        return
      }

      if(downloadToken && downloadToken.annuler) {
        throw new Error("Usager a annule le transfert")
      }
      progressCb(receivedLength, contentLength, {flag: 'lecture'})  // Complet
      const {done: _done, value} = await reader.read()
      progressCb(receivedLength, contentLength, {flag: '', message: value?`Lu ${value.length}`:'Lecture null'})  // Complet

      if(DEBUG) console.debug("_creerDownloadStream pull (done: %s) value = %O", _done, value)
      if(_done) {
        done = true
        if(dataProcessor) {
          if(DEBUG) console.debug("_creerDownloadProcess termine, on fait dataProcessor.finish()")
          const value = await dataProcessor.finish()
          if(value && value.length > 0) {
            controller.enqueue(value)
          } else {
            controller.close()
            progressCb(contentLength, contentLength)  // Complet
          }
        } else {
          controller.close()
          progressCb(contentLength, contentLength)  // Complet
        }
        return
      }

      // Verifier taille recue, traiter en petits blocks
      for(let _position=0; _position < value.length; _position += DECHIFFRAGE_TAILLE_BLOCK) {
        // Traitement block

        if(downloadToken) {
          // Donner une chance d'intercepter l'evenement
          await new Promise(resolve=>setTimeout(resolve, 1))
          if(downloadToken.annuler) {
            throw new Error("Usager a annule le transfert")
          }
        }

        const positionFin = Math.min(_position + DECHIFFRAGE_TAILLE_BLOCK, value.length)
        var sousBlock = value.slice(_position, positionFin)

        if(dataProcessor) {
          if(DEBUG) console.debug("Dechiffrer")
          try {
            progressCb(receivedLength, contentLength, {
              flag: 'dechiffrage', message: `Dechiffrage ${sousBlock.length}, position : ${receivedLength}`
            })
            sousBlock = await dataProcessor.update(sousBlock)
            progressCb(receivedLength, contentLength, {flag: ''})
          } catch(err) {
            if(DEBUG) console.error("Erreur dechiffrage, %O", err)
            throw err
          }
          if(DEBUG) console.debug("Value chiffree : %O", sousBlock)
        }

        receivedLength += sousBlock.length
        if(DEBUG) console.debug(`Recu ${receivedLength} / ${contentLength}`)
        progressCb(receivedLength, contentLength)

        controller.enqueue(sousBlock)
      }
    }
  })

}


module.exports = {fetchAvecProgress}
