import axios from 'axios'
import * as Comlink from 'comlink'
import multibase from 'multibase'

import {
  chiffrer, dechiffrer, creerCipher, creerDecipher,
  chiffrerCleSecreteSubtle, dechiffrerCleSecreteSubtle, importerClePriveeSubtle
} from '../chiffrage'
import {fetchAvecProgress} from './transfertFichiers'
import {CertificateStore, validerChaineCertificats, extraireExtensionsMillegrille} from '../forgecommon'
import { FormatteurMessageSubtle } from '../formatteurMessage'

const TAILLE_BUFFER = 1 * 1024 * 1024
const URL_UPLOAD = ''
const CACHE_NAME = 'fichiersDechiffres'
const TAILLE_LIMITE_SUBTLE = 100 * 1024 * 1024  // La limite de dechiffrage vient de tests sur iPhone 7

const uploadsEnCours = {}     // Key: correlation
const downloadsEnCours = {}   // Key: url
var certificateStore = null   // CertificateStore pour valider x.509
var clePriveeSubtleDecrypt = null  // Cle privee format subtle, pour dechiffrage
var clePriveeSubtleSign = null     // Cle privee format subtle, pour signature
var formatteurMessage = null  // Formatteur de message avec signature

async function initialiserCertificateStore(caCert, opts) {
  const DEBUG = opts.DEBUG
  if(DEBUG) console.debug("Initialisation du CertificateStore avec %O, opts=%O", caCert, opts)
  certificateStore = new CertificateStore(caCert, opts)
  if(DEBUG) console.debug("CertificateStore initialise %O", certificateStore)
}

async function initialiserFormatteurMessage(opts) {
  opts = opts || {}
  const clePriveePem = opts.clePriveePem,
        certificatPem = opts.certificatPem,
        DEBUG = opts.DEBUG

  if(clePriveePem) {
    if(DEBUG) console.debug("Charger cle privee PEM (en parametres)")
    // Note : on ne peut pas combiner les usages decrypt et sign
    clePriveeSubtleDecrypt = await importerClePriveeSubtle(clePriveePem, {usage: ['decrypt']})
    clePriveeSubtleSign = await importerClePriveeSubtle(clePriveePem, {
      usage: ['sign'], algorithm: 'RSA-PSS', hash: 'SHA-512'})
  } else {
    if(DEBUG) console.debug("Charger cle privee a partir de IndexedDB")
    throw new Error("TODO : Importer cle privee a partir de IndexedDB")
  }

  if(certificatPem) {
    if(DEBUG) console.debug("Utiliser chaine pem fournie : %O", certificatPem)
  } else {
    if(DEBUG) console.debug("Charger certificat a partir de IndexedDB")
    throw new Error("TODO : Charger certificat a partir de IndexedDB")
  }

  if(DEBUG) console.debug("Cle privee subtle chargee")
  formatteurMessage = new FormatteurMessageSubtle(certificatPem, clePriveeSubtleSign)
  await formatteurMessage.ready  // Permet de recevoir erreur si applicable
}

function verifierCertificat(chainePEM, opts) {
  /* Expose verifierChaine du certificate store */
  return certificateStore.verifierChaine(chainePEM, opts)
}

function formatterMessage(message, domaineAction, opts) {
  /* Expose formatterMessage du formatteur de messages */
  if(opts.DEBUG) console.debug("Formatter domaine=%s, message : %O", domaineAction, message)
  return formatteurMessage.formatterMessage(message, domaineAction, opts)
}

async function annulerUpload(correlation) {
  const infoUpload = uploadsEnCours[correlation]
  infoUpload.annuler = true
  if(infoUpload.cancelTokenSource) {
    // Toggle annulation dans Axios
    infoUpload.cancelTokenSource.cancel('Usager annule upload')
  }
}

async function uploaderFichier(correlation, size, reader, progressCb, opts) {
  // Params
  //   - progressCb     : function({loaded, total, flag, message})
  if( ! progressCb ) {
    progressCb = _=>{}  // Default avec aucun effet
  }

  opts = opts || {}
  // Options :
  //   - certificatPem : PEM encoded x.509 certificate pour chiffrage du password
  //   - DEBUG         : true pour activer console.debug
  //   - DANGER_EXPOSER_SECRET : true pour debugger avec cle secrete exposee

  const certificatPem = opts.certificatPem,
        DEBUG = opts.DEBUG,
        DANGER_EXPOSER_SECRET = opts.DANGER_EXPOSER_SECRET

  var clePublique = null
  if(certificatPem) {
    if(DEBUG) console.debug("Verification du certificat pour chiffrer la cle")
    clePublique = await _getPublicKeyFromCertificat(certificatPem, opts)
  } else {
    console.warn("Aucun certificat fourni, la cle secrete ne sera PAS chiffree")
  }

  if(DEBUG) console.debug("Worker : commencer chiffrage et upload correlation %s, taille %d", correlation, size)

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
        if(DEBUG) console.debug("NaN update : %O", infoUpload)
      } else {
        if(DEBUG) console.debug("Progress Update : chiffrage %d, upload %d => %d/%d",
          infoUpload.positionChiffrage, infoUpload.positionUpload, positionMoyenne, size)
      }

      progressCb({loaded: positionMoyenne, total: size})
    }
    infoUpload.progressUpdate = progressUpdate
  }

  const cipher = await creerCipher()
  const cb = async (value, position) => {
    if(DEBUG) console.debug("Callback position :%d, value: %O", position, value)
    if(infoUpload.annuler) {
      throw new Error("Upload annule par l'usager")
    }
    await _putFichierPartiel(correlation, position, infoUpload, value, opts)
  }

  try{
    uploadsEnCours[correlation] = infoUpload
    await _chiffrerFichier(cipher, reader, infoUpload, cb, opts)

    const resultat = await cipher.finish()
    if(DEBUG) console.debug("Upload termine, tranmission de la confirmation : %O", resultat)

    // Chiffrer le mot de passe avec la cle publique
    const passwordChiffreBuffer = await chiffrerCleSecreteSubtle(clePublique, resultat.password, {DEBUG})
    const passwordChiffre = String.fromCharCode.apply(null, multibase.encode('base64', passwordChiffreBuffer))

    // Preparer la transaction de maitre des cles
    const meta = resultat.meta
    var commandeMaitrecles = {
      'domaine': 'GrosFichiers',
      'identificateurs_document': {fuuid: meta.hachage_bytes},
      'hachage_bytes': meta.hachage_bytes,
      iv: meta.iv,
      tag: meta.tag,
      cle: passwordChiffre,
    }
    commandeMaitrecles = await formatterMessage(commandeMaitrecles, 'MaitreDesCles.sauvegarderCle', {DEBUG})

    const confirmationResultat = {commandeMaitrecles}
    if(opts.DANGER_EXPOSER_SECRET) {
      const password = String.fromCharCode.apply(null, multibase.encode('base64', resultat.password))
      console.warn(" !!! SECRET EXPOSE !!! %s", password)
      confirmationResultat['password'] = password
    }

    const reponse = await axios.post('/upload/' + correlation, confirmationResultat)
    return {status: reponse.status, commandeMaitrecles}
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

async function _getPublicKeyFromCertificat(certificatPem, opts) {
  /* Valide le certificat pour chiffrage et retourne la cle publique.
     Le certificat doit avoir le role 'maitrecles'. */
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(!certificateStore) throw new Error("CertificatStore non initialise pour verifier certificat de chiffrage")

  const infoCertificat = await validerChaineCertificats(
    certificatPem,
    {...opts, clientStore: certificateStore}
  )

  // if( ! certificateStore.verifierChaine(certificatPem) ) {
  //   throw new Error("Certificat de chiffrage invalide")
  // }
  //
  if(DEBUG) console.debug("Certificat forge : %O", infoCertificat)
  const certificatForge = await infoCertificat.cert
  const extensions = extraireExtensionsMillegrille(certificatForge)
  if(DEBUG) console.debug("Extensions MilleGrille du certificat : %O", extensions)

  if( ! extensions.roles.includes('maitrecles') ) {
    throw new Error("Le certificat de chiffrage n'est pas pour le maitre des cles")
  }
  if( ! extensions.niveauxSecurite.includes('4.secure') && ! extensions.niveauxSecurite.includes('3.protege') ) {
    throw new Error("Le certificat de chiffrage n'est pas de niveau 3.protege ou 4.secure")
  }

  const publicKeyForge = certificatForge.publicKey
  return publicKeyForge
}

async function _chiffrerFichier(cipher, reader, infoUpload, cb, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

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

      if(DEBUG) console.debug("Stream value : %O", value)
      value = cipher.update(value)
      if(DEBUG) console.debug("Cipher value : %O", value)
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
    if(DEBUG) console.debug("Upload dernier block : %O", tempBuffer)
    await cb(new Uint8Array(tempBuffer), positionFichier)
  }
}

async function _putFichierPartiel(correlation, position, infoUpload, ciphertext, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  const cancelTokenSource = axios.CancelToken.source()
  infoUpload.cancelTokenSource = cancelTokenSource

  const positionInitiale = infoUpload.positionUpload
  const onUploadProgress = progress => {
    const {loaded, total} = progress
    if(DEBUG) console.debug("Axios progress sur %s : %d/%d", correlation, loaded, total)

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
      onUploadProgress,
      cancelToken: cancelTokenSource.token,
    })
    if(DEBUG) console.debug("Reponse upload %s position %d put block %O", correlation, position, reponse)

    // Replacer la position d'upload
    infoUpload.positionUpload = positionInitiale + ciphertext.length
    if(infoUpload.progressUpdate) infoUpload.progressUpdate()

  } finally {
    // this.setState({positionUpload: position, positionAxios: 0, cancelTokenSource: ''})
    infoUpload.cancelTokenSource = ''
  }

}

async function downloadCacheFichier(url, progressCb, opts) {
  /* Download, dechiffre et conserve un fichier dans le cache storage */
  opts = opts || {}
  console.debug("Options : %O", opts)
  const passwordChiffre = opts.passwordChiffre,
        clePriveePem = opts.clePriveePem,
        iv = opts.iv,
        tag = opts.tag,
        mimetype = opts.mimetype,
        filename = opts.filename,
        DEBUG = opts.DEBUG

  var password = opts.password

  if(downloadsEnCours[url]) {
    throw new Error("Download pour url %s deja en cours", url)
  }

  var blockCipher = null
  var dataProcessor = null
  if((password || passwordChiffre) && iv && tag) {
    // Charger cle privee subtle, dechiffrer mot de passe
    if(passwordChiffre) {
      // Dechiffrer le mot de passe
      var cle = null
      if( clePriveePem ) {
        if(DEBUG) console.debug("Charger cle privee PEM sous format subtle")
        password = await dechiffrerCleSecreteSubtle(clePriveePem, passwordChiffre, {DEBUG})
      } else if(clePriveeSubtleDecrypt) {
        if(DEBUG) console.debug("Dechiffrer avec cle privee subtle deja chargee")
        password = await dechiffrerCleSecreteSubtle(clePriveeSubtleDecrypt, passwordChiffre, {DEBUG})
      } else {
        // Charger la cle a partir de IndexedDB
        throw new Error("Cle privee non chargee pour dechiffrage")
      }
    }

    dataProcessor = {

      start: async response => {
        // On active le blockCipher si le fichier depasse le seuil pour utiliser subtle
        const size = Number(response.headers.get('content-length'))
        if(size > TAILLE_LIMITE_SUBTLE) {
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

  const downloadToken = {annuler: false, termine: false}
  try {
    downloadsEnCours[url] = downloadToken

    const {reader: stream, headers, status} = await fetchAvecProgress(
      url,
      {progressCb, dataProcessor, downloadToken, DEBUG}
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
    if(size > TAILLE_LIMITE_SUBTLE) {
      // Download et dechiffrage en stream
      if(DEBUG) console.debug("Dechiffrage mode stream")
      response = new Response(stream, {headers: headersModifies, status})
    } else {
      if(DEBUG) console.debug("Creation buffer %d bytes pour cipher/subtle", size)
      var buffer = new Uint8Array(size)
      var position = 0
      const reader = stream.getReader()
      while(true) {
        const {done, value} = await reader.read()
        if(DEBUG) console.debug("Chiffrage.worker reader : done=%s, value=%O", done, value)
        if(done) break
        buffer.set(value, position)
        position += value.length
      }

      if(DEBUG) console.debug("Dechiffrer avec subtle")
      progressCb(size-1, size, {flag: 'Dechiffrage en cours'})
      buffer = await dechiffrer(buffer, password, iv, tag)
      if(DEBUG) console.debug("Dechiffrage avec subtle termine")
      progressCb(size, size, {flag: 'Mise en cache'})
      response = new Response(buffer, {headers: headersModifies, status})
    }

    // const response = new Response(reader, {headers: headersModifies, status})
    // const response = new Response(buffer, {headers: headersModifies, status})

    const pathname = new URL(url).pathname
    if(DEBUG) console.debug("Fuuid a mettre dans le cache : %s", pathname)

    const cache = await caches.open(CACHE_NAME)
    if(DEBUG) console.debug("Cache instance : %O", cache)
    const promiseCache = cache.put(pathname, response)

    // Attendre que le download soit termine
    if(DEBUG) console.debug("Attendre que le download soit termine, response : %O", response)

    await promiseCache
    progressCb(size, size, {flag: 'Termine'})
    downloadToken.termine = true
    if(DEBUG) console.debug("Caching complete")
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

Comlink.expose({
  initialiserCertificateStore, initialiserFormatteurMessage,
  chiffrer, annulerUpload, uploaderFichier,
  downloadCacheFichier, annulerDownload,
  verifierCertificat, formatterMessage,
})
