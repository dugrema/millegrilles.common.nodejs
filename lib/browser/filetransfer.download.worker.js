const path = require('path')
const {expose: comlinkExpose} = require('comlink')

var URL_DOWNLOAD = '/fichiers'
const CACHE_TEMP_NAME = 'fichiersDechiffresTmp',
      CACHE_DURABLE_NAME = 'fichiersSauvegardes',
      TAILLE_LIMITE_SUBTLE = 100 * 1024 * 1024,  // La limite de dechiffrage vient de tests sur iPhone 7
      DECHIFFRAGE_TAILLE_BLOCK = 256 * 1024

// Globals
var _chiffrage = null

// Structure downloads : {}
var _downloadsPending = [],
    _downloadEnCours = null,
    _downloadsCompletes = []

const STATUS_NOUVEAU = 1,
  STATUS_ENCOURS = 2,
  STATUS_SUCCES = 3,
  STATUS_ERREUR = 4

function getEtatCourant() {
  const etat = {
      downloadsPending: _downloadsPending,
      downloadEnCours: _downloadEnCours,
      downloadsCompletes: _downloadsCompletes,
  }
  console.debug("Retourner etat : %O", etat)
  return etat
}

async function ajouterDownload(fuuid, opts) {
  opts = opts || {}
  // Note: opts doit avoir iv, tag et password/passwordChiffre pour les fichiers chiffres
  const url = path.join(URL_DOWNLOAD, ''+fuuid+'.mgs2')  // Peut etre override dans opts

  console.debug("ajouterDownload %s, %O", fuuid, opts)

  const infoDownload = {
    url,
    size: '',
    conserver: false,  // Indique de conserver le fichier dans un cache longue duree (offline viewing)
    ...opts,  // Overrides et params

    fuuid,

    annuler: false,
    status: STATUS_NOUVEAU,
    loaded: 0,
  }

  console.debug("ajouterDownload push %O", infoDownload)
  _downloadsPending.push(infoDownload)
  traiterDownloads()
}

async function traiterDownloads() {
  if(_downloadEnCours) return  // Rien a faire

  const progressCb = (loaded, size, flags) => {
    flags = flags || {}
    emettreEtat({loaded, size, ...flags})
  }

  let complete = ''
  for(_downloadEnCours = _downloadsPending.shift(); _downloadEnCours; _downloadEnCours = _downloadsPending.shift()) {
      console.debug("Traitement fichier %O", _downloadEnCours)
      _downloadEnCours.status = STATUS_ENCOURS
      emettreEtat({complete}).catch(err=>(console.warn("Erreur maj etat : %O", err)))
      try {
          // Download le fichier.
          await downloadCacheFichier(_downloadEnCours, {DEBUG: true, progressCb})
          emettreEtat({fuuidReady: _downloadEnCours.fuuid}).catch(err=>(console.warn("Erreur maj etat apres download complet : %O", err)))
      } catch(err) {
          console.error("Erreur GET fichier : %O", err)
          _downloadEnCours.status = STATUS_ERREUR
      } finally {
          if(!_downloadEnCours.annuler) {
              _downloadsCompletes.push(_downloadEnCours)
          }
          complete = _downloadEnCours.correlation
          _downloadEnCours.complete = true

          _downloadEnCours = null
          emettreEtat({complete}).catch(err=>(console.warn("Erreur maj etat : %O", err)))
      }
  }

}

/** Fetch fichier, permet d'acceder au reader */
async function fetchAvecProgress(url, opts) {
  opts = opts || {}
  const progressCb = opts.progressCb,
        downloadEnCours = opts.downloadEnCours,
        DEBUG = opts.DEBUG

  var dataProcessor = opts.dataProcessor

  const reponse = await fetch(url)

  if(DEBUG) console.debug("Reponse object : %O", reponse)
  const reader = reponse.body.getReader()
  const contentLength = Number(reponse.headers.get('Content-Length'))

  progressCb(0, contentLength, {})

  if(dataProcessor && dataProcessor.start) {
    // Initialiser le data processor au besoin
    const actif = await dataProcessor.start(reponse)
    if(!actif) dataProcessor = null
  }

  const downloadEnvironment = {
    dataProcessor,  // Si present, permet d'appliquer un traitement sur les donnes au vol
    downloadEnCours,  // .annuler === true indique que le client veut annuler le download
    progressCb,
    DEBUG,
  }

  const downloadStream = _creerDownloadStream(reader, contentLength, downloadEnvironment)

  return {
    reader: downloadStream,
    headers: reponse.headers,
    status: reponse.status,
  }

}

function _creerDownloadStream(reader, contentLength, opts) {
  opts = opts || {}

  const downloadEnCours = opts.downloadEnCours || {},
        dataProcessor = opts.dataProcessor,
        DEBUG = opts.DEBUG

  const {fuuid, filename} = downloadEnCours

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
        progressCb(contentLength, contentLength, {})  // Complet
        return
      }

      if(downloadEnCours && downloadEnCours.annuler) {
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
            progressCb(contentLength, contentLength, {})  // Complet
          }
        } else {
          controller.close()
          progressCb(contentLength, contentLength, {})  // Complet
        }
        return
      }

      // Verifier taille recue, traiter en petits blocks
      for(let _position=0; _position < value.length; _position += DECHIFFRAGE_TAILLE_BLOCK) {
        // Traitement block

        if(downloadEnCours) {
          // Donner une chance d'intercepter l'evenement
          await new Promise(resolve=>setTimeout(resolve, 1))
          if(downloadEnCours.annuler) {
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
        progressCb(receivedLength, contentLength, {})

        controller.enqueue(sousBlock)
      }
    }
  })

}

async function preparerDataProcessor(iv, tag, opts) {
  opts = opts || {}
  let {password, passwordChiffre} = opts
  const tailleLimiteSubtle = opts.tailleLimiteSubtle || TAILLE_LIMITE_SUBTLE
  const clePriveePem = opts.clePriveePem

  if(!password && !passwordChiffre) throw new Error("Il faut fournir opts.password ou opts.passwordChiffre")
  
  // Charger cle privee subtle, dechiffrer mot de passe
  if(!password) {
    // Dechiffrer le mot de passe
    if( clePriveePem ) {
      if(DEBUG) console.debug("Charger cle privee PEM sous format subtle")
      password = await _chiffrage.dechiffrerCleSecreteSubtle(clePriveePem, passwordChiffre, {DEBUG})
    } else if(clePriveeSubtleDecrypt) {
      if(DEBUG) console.debug("Dechiffrer avec cle privee subtle deja chargee")
      password = await _chiffrage.dechiffrerCleSecreteSubtle(clePriveeSubtleDecrypt, passwordChiffre, {DEBUG})
    } else {
      // Charger la cle a partir de IndexedDB
      throw new Error("Cle privee non chargee pour dechiffrage")
    }
  }

  dataProcessor = {
    start: async response => {
      // On active le blockCipher si le fichier depasse le seuil pour utiliser subtle
      const size = Number(response.headers.get('content-length'))
      if(size > tailleLimiteSubtle) {
        if(DEBUG) console.debug("Fichier taille %d, on va utiliser le block cipher javascript pur", size)
        blockCipher = await creerDecipher(password, iv, tag)
        return true
      } else {
        if(DEBUG) console.debug("Fichier taille %d sous seuil, on utilise subtle pour dechiffrer", size)
        // Retourner false, indique que le dataProcessor est inactif
        return false
      }
    },
    update: data => {
      if(!blockCipher) throw new Error("Data processor est inactif")
      return blockCipher.update(data)
    },
    finish: () => {
      if(!blockCipher) throw new Error("Data processor est inactif")
      return blockCipher.finish()
    },
  }

}

/** Download un fichier, effectue les transformations (e.g. dechiffrage) et
 *  conserve le resultat dans cache storage */
async function downloadCacheFichier(downloadEnCours, opts) {
  opts = opts || {}
  progressCb = opts.progressCb || function() {}  // Par defaut fonction vide

  console.debug("downloadCacheFichier %O, Options : %O", downloadEnCours, opts)
  const DEBUG = opts.DEBUG

  var blockCipher = null
  var dataProcessor = null
  const {fuuid, url, filename, mimetype, iv, tag, password, passwordChiffre} = downloadEnCours
  if(iv && tag && (password || passwordChiffre)) {
    dataProcessor = await preparerDataProcessor(iv, tag, {password, passwordChiffre})
  }

  let pathname
  try {
    const {reader: stream, headers, status} = await fetchAvecProgress(
      url,
      {progressCb, dataProcessor, DEBUG}
    )

    if(DEBUG) console.debug("Stream recu : %O", stream)

    const size = Number(headers.get('content-length'))
    const headerList = await Promise.all(headers.entries())
    const headersModifies = new Headers()
    if(DEBUG) console.debug("Headers originaux avant dechiffrage : %O", headerList)
    for(let idx in headerList) {
      const header = headerList[idx]
      headersModifies.set(header[0], header[1])
    }
    if(mimetype) {
      headersModifies.set('content-type', mimetype)
    }
    if(filename) {
      headersModifies.set('content-disposition', `attachment; filename="${filename}"`)
    }

    var response = null
    if(blockCipher) {  // size > TAILLE_LIMITE_SUBTLE) {
      // Download et dechiffrage en stream
      if(DEBUG) console.debug("Dechiffrage mode stream")
      response = new Response(stream, {headers: headersModifies, status})
    } else {
      if(DEBUG) console.debug("Creation buffer %d bytes pour cipher/subtle", size)
      var buffer = new Uint8Array(size)
      var position = 0
      const reader = stream.getReader()
      while(downloadEnCours.annuler !== true) {
        const {done, value} = await reader.read()
        if(DEBUG) console.debug("Chiffrage.worker reader : done=%s, value=%O", done, value)
        if(done) break
        buffer.set(value, position)
        position += value.length
      }

      if(dataProcessor) {
        // On avait un processor, finir le dechiffrage
        if(DEBUG) console.debug("Dechiffrer avec subtle")
        progressCb(size-1, size, {flag: 'Dechiffrage en cours'})
        buffer = await dechiffrer(buffer, password, iv, tag)
        if(DEBUG) console.debug("Dechiffrage avec subtle termine")
        progressCb(size, size, {flag: 'Mise en cache'})
      }
      response = new Response(buffer, {headers: headersModifies, status})
    }

    if(downloadEnCours.annuler) throw new Error("Download annule")

    if(DEBUG) console.debug("Conserver %s dans cache", url)
    if(fuuid) {
      pathname = '/' + fuuid
    } else if(!pathname) {
      pathname = url
      try { pathname = new URL(url).pathname } catch(err) {
        if(DEBUG) console.debug("Pathname a utiliser pour le cache : %s", pathname)
      }
    }
    if(DEBUG) console.debug("Fuuid a mettre dans le cache : %s", pathname)

    console.debug("Caches : %O, CacheStorage: %O", caches, CacheStorage)

    const cache = await caches.open(CACHE_TEMP_NAME)
    if(DEBUG) console.debug("Cache instance : %O", cache)
    const promiseCache = cache.put(pathname, response)

    // Attendre que le download soit termine
    if(DEBUG) console.debug("Attendre que le download soit termine, response : %O", response)

    await promiseCache
    progressCb(size, size, {})
    if(DEBUG) console.debug("Caching complete")
  } catch(err) {
    console.error("Erreur download/processing : %O", err)
    if(progressCb) progressCb(-1, -1, {flag: 'Erreur', err: ''+err, stack: err.stack})
    try {
      const cache = await caches.open(CACHE_TEMP_NAME)
      cache.delete(pathname)
    } catch(err) {console.warn("Erreur suppression cache %s : %O", pathname, err)}
    throw err
  } finally {
    downloadEnCours.termine = true
    _downloadsEnCours = null
  }
}

async function emettreEtat(flags) {
  flags = flags || {}
  if(_callbackEtatDownload) {
      console.debug("Emettre etat")

      let pctFichierEnCours = 0
      if(_downloadEnCours) {
          flags.enCoursFuuid = _downloadEnCours.fuuid
          flags.enCoursSize = isNaN(_downloadEnCours.size)?0:_downloadEnCours.size
          flags.enCoursLoaded = isNaN(_downloadEnCours.loaded)?0:_downloadEnCours.loaded
      }

      _callbackEtatDownload(
          _downloadsPending.length, 
          pctFichierEnCours,
          flags,
      )
  }
}

function annulerDownload(fuuid) {
  if(!fuuid) {
    console.debug("Annuler tous les downloads")
    _downloadsPending = []
    if(_downloadEnCours) _downloadEnCours.annuler = true
  } else {
    console.warn("Annuler download %s", fuuid)
    if(_downloadEnCours && _downloadEnCours.fuuid === fuuid) {
      _downloadEnCours.annuler = true
    } else {
      _downloadsPending.forEach(item=>{
        if(item.fuuid === fuuid) item.annuler = true
      })
    }
  }
}

/** Set le chiffrage worker */
function setChiffrage(chiffrage) {
  _chiffrage = chiffrage
}

function setCallbackDownload(cb) {
  _callbackEtatDownload = cb
}

comlinkExpose({
  fetchAvecProgress,
  getEtatCourant,
  ajouterDownload,  
  setChiffrage,
  annulerDownload,
  setCallbackDownload,
})
