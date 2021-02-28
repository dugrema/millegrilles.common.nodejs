import axios from 'axios'
import * as Comlink from 'comlink'
import multibase from 'multibase'

import {chiffrer, dechiffrer, creerCipher, creerDecipher} from '../chiffrage'
import {fetchAvecProgress} from './transfertFichiers'

const TAILLE_BUFFER = 1 * 1024 * 1024
const URL_UPLOAD = ''
const CACHE_NAME = 'fichiersDechiffres'
const TAILLE_LIMITE_SUBTLE = 10 * 1024 * 1024  // La limite de dechiffrage vient de tests sur iPhone 7

const uploadsEnCours = {}  // Key: correlation
const downloadsEnCours = {}  // Key: url

async function annulerUpload(correlation) {
  const infoUpload = uploadsEnCours[correlation]
  infoUpload.annuler = true
  if(infoUpload.cancelTokenSource) {
    // Toggle annulation dans Axios
    infoUpload.cancelTokenSource.cancel('Usager annule upload')
  }
}

async function uploaderFichier(correlation, size, reader, progressCb) {
  console.debug("Worker : commencer chiffrage et upload correlation %s, taille %d", correlation, size)

  const infoUpload = {
    size,
    annuler: false,
    cancelTokenSource: '',
    positionChiffrage: 0,
    positionUpload: 0,
  }

  if(progressCb) {
    const progressUpdate = _ => {
      const positionMoyenne = Math.floor((infoUpload.positionChiffrage + infoUpload.positionUpload) / 2)
      if(isNaN(positionMoyenne)) {
        console.debug("NaN update : %O", infoUpload)
      } else {
        console.debug("Progress Update : chiffrage %d, upload %d => %d/%d",
          infoUpload.positionChiffrage, infoUpload.positionUpload, positionMoyenne, size)
      }

      progressCb({loaded: positionMoyenne, total: size})
    }
    infoUpload.progressUpdate = progressUpdate
  }

  const cipher = await creerCipher()
  const cb = async (value, position) => {
    console.debug("Callback position :%d, value: %O", position, value)
    if(infoUpload.annuler) {
      throw new Error("Upload annule par l'usager")
    }
    await _putFichierPartiel(correlation, position, infoUpload, value)
  }

  try{
    uploadsEnCours[correlation] = infoUpload
    await _chiffrerFichier(cipher, reader, infoUpload, cb)

    const resultat = await cipher.finish()
    console.debug("Upload termine, tranmission de la confirmation : %O", resultat)

    const password = String.fromCharCode.apply(null, multibase.encode('base64', resultat.password))
    const confirmationResultat = {
      password,
      ...resultat.meta
    }

    const reponse = await axios.post('/upload/' + correlation, confirmationResultat)
    return {status: reponse.status, resultat}
  } catch(err) {
    // Tenter de faire un nettoyage cote serveur, fire and forget
    axios.delete('/upload/' + correlation)
    throw err
  } finally {
    // Cleanup variables environnement d'upload
    try {
      delete uploadsEnCours[correlation]
    } catch(err) {
      // OK
    }
  }

}

async function _chiffrerFichier(cipher, reader, infoUpload, cb) {
  var positionFichier = 0
  var positionLocale = 0
  var tempBuffer = null

  var promisePrecedente = null
  while(true) {
    var {done, value} = await reader.read()
    if(value) {
      // Update progres du quart pour le chiffrage
      // Si la chunk est grande, peut prendre du temps pour avoir prochain update
      infoUpload.positionChiffrage = positionLocale + Math.floor(value.length / 4)
      if(infoUpload.progressUpdate) infoUpload.progressUpdate()

      console.debug("Stream value : %O", value)
      value = cipher.update(value)
      console.debug("Cipher value : %O", value)
      if(infoUpload.annuler) {
        throw new Error("Upload annule par l'usager")
      }

      // Permettre maj du progres
      positionLocale += value.length
      infoUpload.positionChiffrage = positionLocale
      if(infoUpload.progressUpdate) infoUpload.progressUpdate()

      if(!tempBuffer) {
        tempBuffer = Buffer.from(value)
      } else {
        tempBuffer = Buffer.concat([tempBuffer, Buffer.from(value)])
      }

      if(tempBuffer.byteLength > TAILLE_BUFFER) {
        // Effectuer callback, attendre la fin de l'execution
        if(promisePrecedente) await promisePrecedente

        const view = new Uint8Array(tempBuffer)
        promisePrecedente = cb(view, positionFichier)
        positionFichier += view.length

        // Reset buffer
        tempBuffer = null
      }
    }

    // Sortir de la boucle pour terminer
    if(done) break
  }

  if(promisePrecedente) await promisePrecedente

  // Transmettre dernier bloc
  if(tempBuffer) {
    console.debug("Upload dernier block : %O", tempBuffer)
    await cb(new Uint8Array(tempBuffer), positionFichier)
  }
}

async function _putFichierPartiel(correlation, position, infoUpload, ciphertext) {

  const cancelTokenSource = axios.CancelToken.source()
  infoUpload.cancelTokenSource = cancelTokenSource

  const onUploadProgress = progress => {
    const {loaded, total} = progress
    console.debug("Axios progress sur %s : %d/%d", correlation, loaded, total)

    // Calculer position par rapport a tout le fichier
    const positionAbsolue = infoUpload.positionUpload + loaded
    infoUpload.positionUpload = positionAbsolue

    // Transmettre information de maj
    if(infoUpload.progressUpdate) infoUpload.progressUpdate()
  }

  try {
    const reponse = await axios({
      url: '/upload/' + correlation + '/' + position,
      method: 'PUT',
      headers: {
        'content-type': 'application/data',
      },
      data: ciphertext,
      cancelToken: cancelTokenSource.token,
      onUploadProgress,
    })
    console.debug("Reponse upload %s position %d put block %O", correlation, position, reponse)
  } finally {
    // this.setState({positionUpload: position, positionAxios: 0, cancelTokenSource: ''})
    infoUpload.cancelTokenSource = ''
  }

}

async function downloadCacheFichier(url, progressCb, opts) {
  /* Download, dechiffre et conserve un fichier dans le cache storage */
  opts = opts || {}
  console.debug("Options : %O", opts)
  const password = opts.password,
        iv = opts.iv,
        tag = opts.tag,
        mimetype = opts.mimetype,
        filename = opts.filename

  if(downloadsEnCours[url]) {
    throw new Error("Download pour url %s deja en cours", url)
  }

  var blockCipher = null
  var dataProcessor = null
  if(password && iv && tag) {
    dataProcessor = {
      start: async response => {
        // On active le blockCipher si le fichier depasse le seuil pour utiliser subtle
        const size = Number(response.headers.get('content-length'))
        if(size > TAILLE_LIMITE_SUBTLE) {
          console.debug("Fichier taille %d, on va utiliser le block cipher javascript pur", size)
          blockCipher = await creerDecipher(password, iv, tag)
        } else {
          console.debug("Fichier taille %d sous seuil, on utilise subtle pour dechiffrer", size)
        }
      },
      update: data => {
        if(blockCipher) return blockCipher.update(data)
        return data
      },
      finish: () => {
        if(blockCipher) return blockCipher.finish()
      }
    }
  }

  const downloadToken = {annuler: false, termine: false}
  try {
    downloadsEnCours[url] = downloadToken

    const {reader: stream, headers, status} = await fetchAvecProgress(url, progressCb, dataProcessor, downloadToken)
    console.debug("Stream recu : %O", stream)

    const size = Number(headers.get('content-length'))
    const headerList = await Promise.all(headers.entries())
    const headersModifies = new Headers()
    console.debug("Headers originaux avant dechiffrage : %O", headerList)
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
    if(size > TAILLE_LIMITE_SUBTLE) {
      // Download et dechiffrage en stream
      console.debug("Dechiffrage mode stream")
      response = new Response(stream, {headers: headersModifies, status})
    } else {
      console.debug("Creation buffer %d bytes pour cipher/subtle", size)
      var buffer = new Uint8Array(size)
      var position = 0
      const reader = stream.getReader()
      while(true) {
        const {done, value} = await reader.read()
        console.debug("Chiffrage.worker reader : done=%s, value=%O", done, value)
        if(done) break
        buffer.set(value, position)
        position += value.length
      }

      console.debug("Dechiffrer avec subtle")
      progressCb(size-1, size, {flag: 'Dechiffrage en cours'})
      buffer = await dechiffrer(buffer, password, iv, tag)
      console.debug("Dechiffrage avec subtle termine")
      progressCb(size, size, {flag: 'Mise en cache'})
      response = new Response(buffer, {headers: headersModifies, status})
    }

    // const response = new Response(reader, {headers: headersModifies, status})
    // const response = new Response(buffer, {headers: headersModifies, status})

    const pathname = new URL(url).pathname
    console.debug("Fuuid a mettre dans le cache : %s", pathname)

    const cache = await caches.open(CACHE_NAME)
    console.debug("Cache instance : %O", cache)
    const promiseCache = cache.put(pathname, response)

    // Attendre que le download soit termine
    console.debug("Attendre que le download soit termine, response : %O", response)

    await promiseCache
    progressCb(size, size, {flag: 'Termine'})
    downloadToken.termine = true
    console.debug("Caching complete")
  } catch(err) {
    console.error("Erreur download/processing : %O", err)
    throw err
  } finally {
    delete downloadsEnCours[url]
  }
}

function annulerDownload(url) {
  console.warn("Annuler download %s", url)
  downloadsEnCours[url].annuler = true
}

Comlink.expose({chiffrer, annulerUpload, uploaderFichier, downloadCacheFichier, annulerDownload})
