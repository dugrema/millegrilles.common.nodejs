async function fetchAvecProgress(url, progressCb) {
  const reponse = await fetch(url)

  console.debug("Reponse object : %O", reponse)
  const reader = reponse.body.getReader()
  const contentLength = reponse.headers.get('Content-Length')
  // let receivedLength = 0
  // let chunks = []

  progressCb(0, contentLength)

  // Variables globales entre les fonctions - acces direct
  var demarrer = null
  // var done = false
  var promiseReader = new Promise(resolve=>{
    demarrer = _ => {
      console.debug("PromiseReader semaphore : demarrer!")
      resolve()
    }
  })

  const downloadEnvironment = {
    done: false,
    demarrer,       // Methode de demarrage du promise reader
    promiseReader,  // Semaphore d'attente pour ecriture
    chunks: [],
    receivedLength: 0,
  }

  const readerFunction = _creerReader(downloadEnvironment)

  // const readerFunction = async controller => {
  //   console.debug("Reader - invocation, chunks : %O, done: %s, promiseReader: %O", chunks, done, promiseReader)
  //   var compteur = 0
  //   while(compteur++ < 2) {
  //     var chunk = null
  //     if(chunks.length > 0) {
  //       chunk = Buffer.concat(chunks)
  //       chunks = []
  //     }
  //
  //     console.debug("Chunk : %O, chunks: %O", chunk, chunks)
  //
  //     if(chunk) {
  //       // return {done: false, value: chunk}
  //       // return chunk
  //       console.debug("Enqueue chunk %O", chunk)
  //       controller.enqueue(chunk)
  //       return
  //     }
  //     if(done) {
  //       // return {done: true, value: null}
  //       console.debug("Fermer controller")
  //       controller.close()
  //       return
  //     }
  //
  //     // Attendre prochain block
  //     if(!promiseReader) throw new Error("read promise - out of sync")
  //
  //     // Recommencer la loop apres resolution d'un read
  //     console.debug("Attente promise reader")
  //     await promiseReader
  //     console.debug("Promise reader completee (readerFunction)")
  //   }
  // }

  const readerStream = _creerReaderStream(readerFunction)

  const process = _creerDownloadProcess(reader, contentLength, progressCb, downloadEnvironment)

  // const process = new Promise(async (resolve, reject)=>{
  //   try {
  //     while(true) {
  //       var stopcount = 500, count = 0
  //       console.debug("Loop download count %d", count)
  //       if(count++ > stopcount) throw new Error("Whoa!")
  //
  //       promiseReader = new Promise(async (resolve, reject) => {
  //         const resultat = await reader.read()
  //         console.debug("Resultat reader.read() download : %O", resultat)
  //
  //         // Exposer done immediatement
  //         if(resultat.done) {
  //           done = true
  //           return resolve({done: true, value: null})
  //         }
  //
  //         const value = resultat.value
  //         chunks.push(Buffer.from(value))
  //
  //         receivedLength += value.length
  //         console.debug(`Recu ${receivedLength} / ${contentLength}`)
  //         progressCb(receivedLength, contentLength)
  //
  //         if(demarrer) {demarrer(); demarrer = null}
  //
  //         return resolve({done, value})
  //       })
  //
  //       const resultat = await promiseReader
  //       console.debug("Loop download resultat : %O", resultat)
  //       done = resultat.done
  //
  //       if(done) {
  //         console.debug("Promise download completee")
  //         return resolve()
  //       }
  //     }
  //   } catch(err) {
  //     reject(err)
  //   }
  // })

  // const buffer = Buffer.concat(chunks)
  return {
    reader: readerStream,
    complete: process,
    headers: reponse.headers,
    status: reponse.status
  }

}

function _creerReaderStream(readerFunction) {
  return new ReadableStream({
    start: controller => {
      console.debug("Start invoque : %O", controller)
    },
    pull: controller => readerFunction(controller)
  })
}

function _creerDownloadProcess(reader, contentLength, progressCb, downloadEnvironment) {

  var receivedLength = 0

  return new Promise(async (resolve, reject)=>{
    try {
      while(true) {
        var stopcount = 500, count = 0
        console.debug("Loop download count %d", count)
        if(count++ > stopcount) throw new Error("Whoa!")

        downloadEnvironment.promiseReader = new Promise(async (resolve, reject) => {
          const resultat = await reader.read()
          console.debug("Resultat reader.read() download : %O", resultat)

          // Exposer done immediatement
          if(resultat.done) {
            downloadEnvironment.done = true
            return resolve({done: true, value: null})
          }

          const value = resultat.value
          downloadEnvironment.chunks.push(Buffer.from(value))

          receivedLength += value.length
          console.debug(`Recu ${receivedLength} / ${contentLength}`)
          progressCb(receivedLength, contentLength)

          if(downloadEnvironment.demarrer) {
            console.debug("Demarrer ecriture")
            downloadEnvironment.demarrer()
            downloadEnvironment.demarrer = null
          }

          return resolve({done: false, value})
        })

        console.debug("Loop download, attente promise reader")
        const resultat = await downloadEnvironment.promiseReader
        console.debug("Loop download resultat : %O", resultat)
        downloadEnvironment.done = resultat.done

        if(resultat.done) {
          console.debug("Promise download completee")
          return resolve()
        }
      }
    } catch(err) {
      reject(err)
    }
  })
}

function _creerReader(downloadEnvironment) {
  return async controller => {
    console.debug("Reader - invocation, chunks : %O, done: %s, promiseReader: %O",
      downloadEnvironment.chunks,
      downloadEnvironment.done,
      downloadEnvironment.promiseReader)

    var compteur = 0
    while(compteur++ < 2) {
      var chunk = null
      if(downloadEnvironment.chunks.length > 0) {
        chunk = Buffer.concat(downloadEnvironment.chunks)
        downloadEnvironment.chunks = []
      }

      console.debug("Chunk : %O, chunks: %O, done: %s", chunk, downloadEnvironment.chunks, downloadEnvironment.done)

      if(chunk) {
        console.debug("Enqueue chunk %O", chunk)
        controller.enqueue(chunk)
        return
      }
      if(downloadEnvironment.done) {
        console.debug("Fermer controller")
        controller.close()
        return
      }

      // Attendre prochain block
      if(!downloadEnvironment.promiseReader) throw new Error("read promise - out of sync")

      // Recommencer la loop apres resolution d'un read
      console.debug("Reader - Attente promise reader")
      await downloadEnvironment.promiseReader
      console.debug("Reader - Promise reader completee (readerFunction)")
    }
  }
}

module.exports = {fetchAvecProgress}
