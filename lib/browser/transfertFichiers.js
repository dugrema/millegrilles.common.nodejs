async function fetchAvecProgress(url, progressCb, dataProcessor, downloadToken) {
  const reponse = await fetch(url)

  console.debug("Reponse object : %O", reponse)
  const reader = reponse.body.getReader()
  const contentLength = reponse.headers.get('Content-Length')

  progressCb(0, contentLength)

  if(dataProcessor.start) {
    // Initialiser le data processor au besoin
    dataProcessor.start(reponse)
  }

  const downloadEnvironment = {
    dataProcessor,  // Si present, permet d'appliquer un traitement sur les donnes au vol
    downloadToken,  // .cancel === true indique que le client veut annuler le download
  }

  const downloadStream = _creerDownloadStream(reader, contentLength, progressCb, downloadEnvironment)

  return {
    reader: downloadStream,
    headers: reponse.headers,
    status: reponse.status,
    downloadToken,
  }

}

const DECHIFFRAGE_TAILLE_BLOCK = 256 * 1024

function _creerDownloadStream(reader, contentLength, progressCb, downloadEnvironment) {

  var receivedLength = 0
  var done = false
  const downloadToken = downloadEnvironment.downloadToken

  return new ReadableStream({
    start: controller => {
      console.debug("start _creerDownloadStream")
    },
    pull: async controller => {
      if(done) {
        console.debug("_creerDownloadStream - done deja sette, termine")
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

      console.debug("_creerDownloadStream pull (done: %s) value = %O", _done, value)
      if(_done) {
        done = true
        if(downloadEnvironment.dataProcessor) {
          console.debug("_creerDownloadProcess termine, on fait dataProcessor.finish()")
          const value = await downloadEnvironment.dataProcessor.finish()
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

        if(downloadEnvironment.dataProcessor) {
          console.debug("Dechiffrer")
          try {
            progressCb(receivedLength, contentLength, {
              flag: 'dechiffrage', message: `Dechiffrage ${sousBlock.length}, position : ${receivedLength}`
            })
            sousBlock = await downloadEnvironment.dataProcessor.update(sousBlock)
            progressCb(receivedLength, contentLength, {flag: ''})
          } catch(err) {
            console.error("Erreur dechiffrage, %O", err)
            throw err
          }
          console.debug("Value chiffree : %O", sousBlock)
        }

        receivedLength += sousBlock.length
        console.debug(`Recu ${receivedLength} / ${contentLength}`)
        progressCb(receivedLength, contentLength)

        controller.enqueue(sousBlock)
      }
    }
  })

}


module.exports = {fetchAvecProgress}
