const {supporteFileStream} = require('./detecterAppareils')

/** Genere un reader pour le fichier (acceptedFile) */
function getAcceptedFileReader(file) {
    let reader = null
  
    // Utiliser detection pro-active, safari sur iOS plante en mode stream
    // pour fichiers larges.
    const supporteStream = supporteFileStream()
  
    if(supporteStream) {
      try {
        // Tenter d'utiliser le stream pour l'upload
        const stream = file.stream()
        return stream.getReader()
      } catch(err) {
        // Echec stream, tenter de proceder par slice
      }
    }
  
    // reader.read retourne : {done, value}
    return sliceReader(file)
  }
  
  /** Simulacre de reader qui utilise plusieurs appels a blob.slice */
  function sliceReader(file, opts) {
    opts = opts || {}
    const TAILLE_BUFFER = opts.tailleBuffer || (256 * 1024)  // 256 kB par defaut
    // const tailleFichier = file.size
  
    var position = 0
    var done = false
    const read = async (len) => {
      const tailleBuffer = len || TAILLE_BUFFER
  
      console.debug("sliceReader Read invoque, position %d, done %s", position, done)
      done = position === file.size
      if(done) return {done, value: null}
  
      const positionFin = Math.min(position + tailleBuffer, file.size)
      const blob = file.slice(position, positionFin)
      const arrayBuffer = await blob.arrayBuffer()
  
      // Preparer pour prochaine iteration
      position = positionFin
  
      return {done: false, value: arrayBuffer}
    }
  
    return {read}
  }

  /** 
   * opts : {
   *    batchSize, 
   *    transform(value)->value
   * }
   */
  async function* streamAsyncIterable(reader, opts) {
    opts = opts || {}
    const batchSize = opts.batchSize || 256 * 1024
    const transform = opts.transform
    try {
        var tempBuffer = null
        while (true) {
            let { done, value } = await reader.read(batchSize)
            console.debug("streamAsyncIterable Lecture (done?%s) len %s", done, value?value.length:'NA')
            if (done && !tempBuffer) {
                console.debug("streamAsyncIterable Termine sur block")
                return
            }

            if(transform) {
                value = opts.transform(value)
            }

            if(value) {
                if(!tempBuffer) {
                    tempBuffer = Buffer.from(value)
                } else {
                    tempBuffer = Buffer.concat([tempBuffer, Buffer.from(value)])
                }
            }

            if(done) {
                console.debug("streamAsyncIterable Done, traitement final de %s bytes", tempBuffer.length)
                if(tempBuffer) {
                    console.debug("streamAsyncIterable yield final")
                    yield tempBuffer
                }
                // Invocation finale
                console.debug("streamAsyncIterable Termine apres yield")
                return
            } else if(tempBuffer.length >= batchSize) {
                yield tempBuffer
                tempBuffer = null
            }
        }
    } finally {
      reader.releaseLock()
    }
  }
  
  module.exports = {getAcceptedFileReader, streamAsyncIterable}