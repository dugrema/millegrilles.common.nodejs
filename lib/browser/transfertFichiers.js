async function fetchAvecProgress(url, progressCb, dataProcessor) {
  const reponse = await fetch(url)

  console.debug("Reponse object : %O", reponse)
  const reader = reponse.body.getReader()
  const contentLength = reponse.headers.get('Content-Length')

  progressCb(0, contentLength)

  const downloadEnvironment = {
    dataProcessor,  // Si present, permet d'appliquer un traitement sur les donnes au vol
  }

  const downloadStream = _creerDownloadStream(reader, contentLength, progressCb, downloadEnvironment)

  return {
    reader: downloadStream,
    headers: reponse.headers,
    status: reponse.status
  }

}

const DECHIFFRAGE_TAILLE_BLOCK = 256 * 1024

function _creerDownloadStream(reader, contentLength, progressCb, downloadEnvironment) {

  var receivedLength = 0
  var done = false

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

      progressCb(receivedLength, contentLength, {flag: 'lecture'})  // Complet
      const {done: _done, value} = await reader.read()
      progressCb(receivedLength, contentLength, {flag: '', message: value?`Lu ${value.length}`:'Lecture null'})  // Complet

      console.debug("_creerDownloadStream pull (done: %s) value = %O", _done, value)
      if(_done) {
        if(downloadEnvironment.dataProcessor) {
          console.debug("_creerDownloadProcess termine, on fait dataProcessor.finish()")
          done = true
          const value = await downloadEnvironment.dataProcessor.finish()
          controller.enqueue(value)
        } else {
          done = true
          controller.close()
          progressCb(contentLength, contentLength)  // Complet
        }
        return
      }

      // Verifier taille recue, traiter en petits blocks
      for(let _position=0; _position < value.length; _position += DECHIFFRAGE_TAILLE_BLOCK) {
        // Traitement block

        const positionFin = Math.min(_position + DECHIFFRAGE_TAILLE_BLOCK, value.length)
        var sousBlock = value.slice(_position, positionFin)

        if(downloadEnvironment.dataProcessor) {
          console.debug("Dechiffrer")
          try {
            progressCb(receivedLength, contentLength, {
              flag: 'chiffrage', message: `Dechiffrage ${sousBlock.length}, position : ${receivedLength}`
            })
            sousBlock = await downloadEnvironment.dataProcessor.update(sousBlock)
            // console.warn("*** Throttle ***")
            // progressCb(receivedLength, contentLength, {flag: 'throttle', message: `Taille block : ${sousBlock.length}, position : ${receivedLength}`})
            // await new Promise(resolve=>{setTimeout(resolve, 50)})
            // console.warn("*** Throttle fin ***")
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

  // return new Promise(async (resolve, reject)=>{
  //   try {
  //     var traitementFinalDone = false
  //     while(true) {
  //       var count = 0 //, stopcount = 500
  //       // console.debug("Loop download count %d", count)
  //       // if(count++ > stopcount) throw new Error("Whoa!")
  //
  //       downloadEnvironment.promiseReader = new Promise(async (resolve, reject) => {
  //         if(traitementFinalDone) {
  //           console.debug("_creerDownloadProcess traitement final complete")
  //           downloadEnvironment.done = true
  //           progressCb(contentLength, contentLength)
  //           return resolve({done: true})
  //         }
  //
  //         const resultat = await reader.read()
  //         console.debug("Resultat reader.read() download : %O", resultat)
  //
  //         // Exposer done immediatement
  //         if(resultat.done) {
  //           if(downloadEnvironment.dataProcessor) {
  //             // Il reste le dernier block a transmettre
  //             console.debug("_creerDownloadProcess termine, on fait dataProcessor.finish()")
  //             const value = await downloadEnvironment.dataProcessor.finish()
  //             traitementFinalDone = true
  //             console.debug("_creerDownloadProcess: dataProcessor.finish() OK, dernier block : %O", value)
  //             downloadEnvironment.chunks.push(Buffer.from(value))
  //             return resolve({done: false})
  //           } else {
  //             // Completement termine
  //             console.debug("_creerDownloadProcess termine, pas de dataProcessor")
  //             traitementFinalDone = true
  //             downloadEnvironment.done = true
  //             return resolve({done: true})
  //           }
  //         }
  //
  //         var value = resultat.value
  //         if(downloadEnvironment.dataProcessor) {
  //           value = await downloadEnvironment.dataProcessor.update(value)
  //         }
  //         downloadEnvironment.chunks.push(Buffer.from(value))
  //
  //         receivedLength += value.length
  //         console.debug(`Recu ${receivedLength} / ${contentLength}`)
  //         progressCb(receivedLength, contentLength)
  //
  //         if(downloadEnvironment.demarrer) {
  //           console.debug("Demarrer ecriture")
  //           downloadEnvironment.demarrer()
  //           downloadEnvironment.demarrer = null
  //         }
  //
  //         return resolve({done: false})
  //       })
  //
  //       console.debug("Loop download, attente promise reader")
  //       const resultat = await downloadEnvironment.promiseReader
  //       console.debug("Loop download resultat : %O", resultat)
  //       downloadEnvironment.done = resultat.done
  //
  //       if(resultat.done) {
  //         console.debug("Promise download completee")
  //         return resolve()
  //       }
  //     }
  //   } catch(err) {
  //     reject(err)
  //   }
  // })
}

// function _creerReader(downloadStream, downloadEnvironment) {
//   return async controller => {
//     const {done, value} = downloadStream.read()
//
//     console.debug("Reader - invocation, value : %O, done: %s", value, done)
//
//     // var compteur = 0  // Infinite-loop guard
//     // while(compteur++ < 2) {
//     // Recommencer la loop apres resolution d'un read
//       // console.debug("Reader - Attente promise reader")
//       // await downloadEnvironment.promiseReader
//       // console.debug("Reader - Promise reader completee (readerFunction)")
//
//       // await new Promise(resolve=>{setTimeout(resolve, 2000)})
//
//       // var chunk = null
//       // if(downloadEnvironment.chunks.length > 0) {
//       //   chunk = Buffer.concat(downloadEnvironment.chunks)
//       //   downloadEnvironment.chunks = []
//       // }
//       //
//       // console.debug("Chunk : %O, chunks: %O, done: %s", chunk, downloadEnvironment.chunks, downloadEnvironment.done)
//
//       if(value) {
//         console.debug("Enqueue chunk %O", chunk)
//         controller.enqueue(chunk)
//         return
//       }
//       if(downloadEnvironment.done) {
//         console.debug("Fermer controller")
//         controller.close()
//         return
//       }
//
//       // Attendre prochain block
//       if(!downloadEnvironment.promiseReader) throw new Error("read promise - out of sync")
//
//     // }
//   }
// }

module.exports = {fetchAvecProgress}
