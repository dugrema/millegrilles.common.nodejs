import axios from 'axios'
import {expose as comlinkExpose} from 'comlink'
import multibase from 'multibase'
import stringify from 'json-stable-stringify'
import path from 'path'
import {pki as forgePki} from 'node-forge'

import {
  chiffrer, dechiffrer, creerCipher, creerDecipher,
  chiffrerCleSecreteSubtle, dechiffrerCleSecreteSubtle,
  importerClePubliqueSubtle, importerClePriveeSubtle,
  chiffrerDocument as _chiffrerDocument, dechiffrerDocument as _dechiffrerDocument,
  preparerCommandeMaitrecles, preparerCleSecreteSubtle as _preparerCleSecreteSubtle,
} from '../chiffrage'
import {fetchAvecProgress} from './transfertFichiers'
import {CertificateStore, validerChaineCertificats, extraireExtensionsMillegrille} from '../forgecommon'
import { FormatteurMessageSubtle, SignateurMessageSubtle } from '../formatteurMessage'
import { hacherCertificat } from '../hachage'

const TAILLE_BUFFER = 1 * 1024 * 1024
var URL_UPLOAD = '/fichiers'
const CACHE_NAME = 'fichiersDechiffres'
const TAILLE_LIMITE_SUBTLE = 100 * 1024 * 1024  // La limite de dechiffrage vient de tests sur iPhone 7

const uploadsEnCours = {}     // Key: correlation
const downloadsEnCours = {}   // Key: url
var certificateStore = null   // CertificateStore pour valider x.509
var certificatMillegrille = null   // Objet du certificat de la MilleGrille {cert, fingerprint}
var clePriveeSubtleDecrypt = null  // Cle privee format subtle, pour dechiffrage
var clePriveeSubtleSign = null     // Cle privee format subtle, pour signature
var formatteurMessage = null  // Formatteur de message avec signature

// Conserver cle de millegrille format subtle
// dict - cle = 'sign', 'decrypt'
var _cleMillegrilleSubtle = null
var _callbackCleMillegrille = null  // Callback sur etat de la cle de millegrille

async function initialiserCertificateStore(caCert, opts) {
  const DEBUG = opts.DEBUG
  if(DEBUG) console.debug("Initialisation du CertificateStore avec %O, opts=%O", caCert, opts)
  certificateStore = new CertificateStore(caCert, opts)
  if(DEBUG) console.debug("CertificateStore initialise %O", certificateStore)

  certificatMillegrille = {
    pem: caCert,
    cert: certificateStore.cert,
    fingerprint: await hacherCertificat(certificateStore.cert)
  }
}

function initialiserCallbackCleMillegrille(cb) {
  // console.debug("Initialisation du callback pour cle de MilleGrille")
  _callbackCleMillegrille = cb
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
  } else if(opts.clePriveeDecrypt && opts.clePriveeSign) {
    if(DEBUG) console.debug("Chargement cle privee Subtle")
    clePriveeSubtleDecrypt = opts.clePriveeDecrypt
    clePriveeSubtleSign = opts.clePriveeSign
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

function clearInfoSecrete() {
  formatteurMessage = null
  _cleMillegrilleSubtle = null
  clePriveeSubtleDecrypt = null
  clePriveeSubtleSign = null
  console.info("Information secrete retiree de la memoire")
}

function verifierCertificat(certificat, opts) {
  /* Expose verifierChaine du certificate store */
  if(typeof(chainePEM) === 'string') {
    certificat = forgePki.certificateFromPem(certificat)
  }
  return certificateStore.verifierChaine(certificat, opts)
}

function formatterMessage(message, domaineAction, opts) {
  opts = opts || {}
  opts.attacherCertificat = true  // Toujours attacher le certificat

  /* Expose formatterMessage du formatteur de messages */
  if(opts.DEBUG) console.debug("Formatter domaine=%s, message : %O", domaineAction, message)
  return formatteurMessage.formatterMessage(message, domaineAction, opts)
}

function signerMessageCleMillegrille(message, opts) {
  opts = opts || {}

  /* Expose formatterMessage du formatteur de messages */
  if(opts.DEBUG) console.debug("Signer message avec cle de MilleGrille: %O", message)
  const signateur = new SignateurMessageSubtle(_cleMillegrilleSubtle.clePriveeSign)
  return signateur.signer(message)
}

async function annulerUpload(correlation) {
  const infoUpload = uploadsEnCours[correlation]
  if(!infoUpload) return  // Ok, upload n'est pas en cours
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
  //   - urlFichiers   : url d'upload de fichier, e.g. /fichiers

  const certificatPem = opts.certificatPem,
        DEBUG = opts.DEBUG,
        DANGER_EXPOSER_SECRET = opts.DANGER_EXPOSER_SECRET

  const urlUpload = new URL(opts.urlFichiers || URL_UPLOAD)
  urlUpload.pathname = path.join(urlUpload.pathname, correlation)
  const pathUpload = urlUpload.href

  if(typeof(size) === 'string') size = Number(size)

  // var clePublique = null, fingerprint = null
  // if(certificatPem) {
  //   if(DEBUG) console.debug("Verification du certificat pour chiffrer la cle")
  //   const resultatCert = await _getPublicKeyFromCertificat(certificatPem, opts)
  //   clePublique = resultatCert.publicKey
  //   fingerprint = resultatCert.fingerprint
  // } else {
  //   console.warn("Aucun certificat fourni, la cle secrete ne sera PAS chiffree")
  // }

  // Valider le certificat pour chiffrage (maitre des cles)- lance une exception en cas d'erreur
  await _validerCertificatChiffrage(certificatPem)

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

        if(typeof(size) === 'string') size = Number(size)
        progressCb({loaded: positionMoyenne, total: size})
      }
    }
    infoUpload.progressUpdate = progressUpdate
  }

  const cipher = await creerCipher()
  const cb = async (value, position) => {
    if(DEBUG) console.debug("Callback position :%d, value: %O", position, value)
    if(infoUpload.annuler) {
      throw new Error("Upload annule par l'usager")
    }
    await _putFichierPartiel(pathUpload, correlation, position, infoUpload, value, opts)
  }

  try{
    uploadsEnCours[correlation] = infoUpload
    await _chiffrerFichier(cipher, reader, infoUpload, cb, opts)

    const resultat = await cipher.finish()
    if(DEBUG) console.debug("Upload termine, tranmission de la confirmation : %O", resultat)

    // // Chiffrer le mot de passe avec la cle publique
    // const passwordChiffreBuffer = await chiffrerCleSecreteSubtle(clePublique, resultat.password, {DEBUG})
    // const passwordChiffre = String.fromCharCode.apply(null, multibase.encode('base64', passwordChiffreBuffer))

    // Preparer la transaction de maitre des cles, chiffre le mot de passe
    const meta = resultat.meta
    var commandeMaitrecles = await preparerCommandeMaitrecles(
      [certificatPem, certificatMillegrille.pem],
      resultat.password, 'GrosFichiers',
      meta.hachage_bytes, meta.iv, meta.tag,
      {type: 'fichier'}
    )
    let partition = commandeMaitrecles._partition
    delete commandeMaitrecles['_partition']
    commandeMaitrecles = await formatterMessage(commandeMaitrecles, 'MaitreDesCles', {action: 'sauvegarderCle', partition, attacherCertificat: true})

    var transactionGrosFichiers = opts.transactionGrosfichiers
    const domaine = 'GrosFichiers',
          action = 'nouvelleVersion'
    if(transactionGrosFichiers) {
      transactionGrosFichiers.fuuid = meta.hachage_bytes
      transactionGrosFichiers = await formatterMessage(transactionGrosFichiers, domaine, {action, attacherCertificat: true})
      if(DEBUG) console.debug("Transaction GrosFichiers formattee : %O", transactionGrosFichiers)
    }

    const confirmationResultat = {commandeMaitrecles, transactionGrosFichiers}
    if(opts.DANGER_EXPOSER_SECRET) {
      const password = String.fromCharCode.apply(null, multibase.encode('base64', resultat.password))
      console.warn(" !!! SECRET EXPOSE %s", password)
      confirmationResultat['password'] = password
    }

    const reponse = await axios.post(pathUpload, confirmationResultat)
    return {status: reponse.status, reponse: reponse.data, commandeMaitrecles, transactionGrosFichiers}
  } catch(err) {
    // Tenter de faire un nettoyage cote serveur, fire and forget
    axios.delete(pathUpload)
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

async function _validerCertificatChiffrage(certificatPem, opts) {
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

  const fingerprint = await hacherCertificat(certificatForge)

  const resultat = {fingerprint}
  if(DEBUG) console.debug("Resultat _validerCertificatChiffrage : %O", resultat)

  return resultat
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

async function _putFichierPartiel(pathUploadBase, correlation, position, infoUpload, ciphertext, opts) {
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
    const urlUpload = new URL(pathUploadBase)
    urlUpload.pathname = path.join(urlUpload.pathname, ''+position)
    const pathUpload = urlUpload.href
    if(DEBUG) console.debug("Path upload part fichier : %s", pathUpload)
    const reponse = await axios({
      url: pathUpload,
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
  progressCb = progressCb || function() {}  // Par defaut fonction vide

  // console.debug("downloadCacheFichier Options : %O", opts)
  const passwordChiffre = opts.passwordChiffre,
        clePriveePem = opts.clePriveePem,
        iv = opts.iv,
        tag = opts.tag,
        mimetype = opts.mimetype,
        filename = opts.filename,
        fuuid = opts.fuuid,
        DEBUG = opts.DEBUG

  var password = opts.password  // Cle secrete dechiffree, si presente

  if(downloadsEnCours[url]) {
    throw new Error(`Download pour url ${url} deja en cours`)
  }

  var blockCipher = null
  var dataProcessor = null
  if((password || passwordChiffre) && iv && tag) {
    // Charger cle privee subtle, dechiffrer mot de passe
    if(!password) {
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
        if(size > TAILLE_LIMITE_SUBTLE && passwordChiffre) {
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
  } else {
    if(DEBUG) console.debug("Aucun dechiffrage requis pour %s", url)
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
    if(blockCipher) {  // size > TAILLE_LIMITE_SUBTLE) {
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

    // const response = new Response(reader, {headers: headersModifies, status})
    // const response = new Response(buffer, {headers: headersModifies, status})

    if(DEBUG) console.debug("Conserver %s dans cache", url)
    let pathname
    if(fuuid) {
      pathname = '/' + fuuid
    } else if(!pathname) {
      pathname = url
      try { pathname = new URL(url).pathname } catch(err) {
        if(DEBUG) console.debug("Pathname a utiliser pour le cache : %s", pathname)
      }
    }
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
    if(progressCb) progressCb(-1, -1, {flag: 'Erreur', err: ''+err, stack: err.stack})
    throw err
  } finally {
    delete downloadsEnCours[url]
  }
}

function annulerDownload(url) {
  // console.warn("Annuler download %s", url)
  downloadsEnCours[url].annuler = true
}

async function chiffrerDocument(doc, domaine, certificatChiffragePem, identificateurs_document, opts) {
    opts = opts || {}
    const DEBUG = opts.DEBUG

  // Valider le certificat - lance une exception si invalide
  const infoCertificatChiffrage = _validerCertificatChiffrage(certificatChiffragePem)

  // Combiner le certificat fourni avec celui de la millegrille
  const certificatsPem = [certificatChiffragePem, certificatMillegrille.pem]

  const resultat = await _chiffrerDocument(doc, domaine, certificatsPem, identificateurs_document, opts)

  // Signer la commande de maitre des cles
  const commandeMaitrecles = await formatterMessage(resultat.commandeMaitrecles, 'MaitreDesCles.sauvegarderCle', {DEBUG})
  resultat.commandeMaitrecles = commandeMaitrecles

  return resultat
}

function dechiffrerDocument(ciphertext, messageCle, opts) {
  // Wrapper pour dechiffrer document, insere la cle privee locale
  return _dechiffrerDocument(ciphertext, messageCle, clePriveeSubtleDecrypt, opts)
}

// async function preparerCommandeMaitrecles(certificatPem, password, domaine, hachage_bytes, iv, tag, identificateurs_document, opts) {
//   opts = opts || {}
//   const DEBUG = opts.DEBUG,
//         format = opts.format || 'mgs2'
//
//   // Verifier elements obligatoires
//   if(typeof(certificatPem) !== 'string') throw new Error(`Certificat PEM mauvais format ${certificatPem}`)
//
//   if(typeof(domaine) !== 'string') throw new Error(`Domaine mauvais format ${domaine}`)
//   if(typeof(hachage_bytes) !== 'string') throw new Error(`hachage_bytes mauvais format : ${hachage_bytes}`)
//   if(typeof(iv) !== 'string') throw new Error(`iv mauvais format : ${iv}`)
//   if(typeof(tag) !== 'string') throw new Error(`tag mauvais format : ${tag}`)
//
//   // Chiffrer le mot de passe avec le certificat fourni
//   const {publicKey, fingerprint} = await _getPublicKeyFromCertificat(certificatPem, opts)
//   var passwordChiffre = await chiffrerCleSecreteSubtle(publicKey, password, {DEBUG})
//   passwordChiffre = String.fromCharCode.apply(null, multibase.encode('base64', passwordChiffre))
//
//   if(DEBUG) console.debug("Password chiffre pour %s : %s", fingerprint, passwordChiffre)
//   const cles = {[fingerprint]: passwordChiffre}
//
//   // Inserer version chiffree pour la millegrille
//   if(certificatMillegrille) {
//     const publicKey = certificatMillegrille.cert.publicKey
//     const fingerprint = certificatMillegrille.fingerprint
//     var passwordChiffre = await chiffrerCleSecreteSubtle(publicKey, password, {DEBUG})
//     passwordChiffre = String.fromCharCode.apply(null, multibase.encode('base64', passwordChiffre))
//     cles[fingerprint] = passwordChiffre
//   }
//
//   if(DEBUG) console.debug("Info password chiffres par fingerprint : %O", cles)
//
//   var commandeMaitrecles = {
//     domaine, identificateurs_document,
//     hachage_bytes, format,
//     iv, tag, cles,
//   }
//
//   commandeMaitrecles = await formatterMessage(commandeMaitrecles, 'MaitreDesCles.sauvegarderCle', {DEBUG})
//
//   return commandeMaitrecles
// }
//
// async function chiffrerDocument(doc, domaine, certificatChiffragePem, identificateurs_document, opts) {
//   opts = opts || {}
//   const DEBUG = opts.DEBUG
//
//   if(DEBUG) console.debug("Chiffrer document %O", doc)
//
//   // if(DEBUG) console.debug("Verification du certificat pour chiffrer la cle")
//   // const {publicKey: clePublique, fingerprint} = await _getPublicKeyFromCertificat(certificatChiffragePem, opts)
//
//   var _doc = stringify(doc)  // string
//   _doc = new TextEncoder().encode(_doc)  // buffer
//
//   const infoDocumentChiffre = await chiffrer(_doc)
//   const meta = infoDocumentChiffre.meta
//
//   if(DEBUG) console.debug("Document chiffre : %O", infoDocumentChiffre)
//
//   const ciphertextString = String.fromCharCode.apply(null, multibase.encode('base64', infoDocumentChiffre.ciphertext))
//
//   // const passwordChiffreBuffer = await chiffrerCleSecreteSubtle(clePublique, infoDocumentChiffre.password, {DEBUG})
//   // const passwordChiffre = String.fromCharCode.apply(null, multibase.encode('base64', passwordChiffreBuffer))
//
//   // if(DEBUG) console.debug("Password chiffre : %O", passwordChiffre)
//
//   const commandeMaitrecles = await preparerCommandeMaitrecles(
//     certificatChiffragePem, infoDocumentChiffre.password, domaine,
//     meta.hachage_bytes, meta.iv, meta.tag, identificateurs_document,
//     opts
//   )
//
//   return {ciphertext: ciphertextString, commandeMaitrecles}
// }

async function chargerCleMillegrilleSubtle(clePrivee) {
  // console.debug("Charger cle millegrille : %O", clePrivee)
  // var cleMillegrilleSubtle = null
  if(typeof(clePrivee) === 'string') {
    // Probablement format PEM
  } else if(clePrivee.n) {
    // Ok, deja format forge
    clePrivee = forgePki.privateKeyFromPem(clePrivee)
  } else if(clePrivee.clePriveeDecrypt && clePrivee.clePriveeSigner) {
    // Formats subtle
    _cleMillegrilleSubtle = {
      clePriveeDecrypt: clePrivee.clePriveeDecrypt,
      clePriveeSign: clePrivee.clePriveeSigner,
    }
  } else {
    throw new Error("Format de cle privee inconnu")
  }

  try {
    // console.debug("Importer cle privee subtle - decrypt")
    if( ! _cleMillegrilleSubtle ) {
      const clePriveeDecrypt = await importerClePriveeSubtle(clePrivee)
      const clePriveeSign = await importerClePriveeSubtle(clePrivee, {
        usage: ['sign'], algorithm: 'RSA-PSS', hash: 'SHA-512'})

      _cleMillegrilleSubtle = {
        decrypt: clePriveeDecrypt,
        sign: clePriveeSign,
      }
    }

    try {
      // console.debug("Callback etat")
      _callbackCleMillegrille(true)
    } catch(err) {
      // OK
    }

  } catch(err) {
    console.error("Erreur preparation cle subtle : %O", err)
    throw err
  }

}

async function clearCleMillegrilleSubtle() {
  _cleMillegrilleSubtle = null
  try {
    _callbackCleMillegrille(false)
  } catch(err) {
    // OK
  }
}

async function rechiffrerAvecCleMillegrille(secretsChiffres, pemRechiffrage, opts) {
  /*
    secretsChiffres : correlation = buffer
    pemRechiffrage : certificat a utiliser pour rechiffrer
  */
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(!_cleMillegrilleSubtle || !_cleMillegrilleSubtle.decrypt) {
    throw new Error("Cle de MilleGrille non chargee")
  }

  // Importer la cle publique en format Subtle a partir du pem de certificat
  const certificat = forgePki.certificateFromPem(pemRechiffrage)
  var clePublique = forgePki.publicKeyToPem(certificat.publicKey)
  const regEx = /\n?\-{5}[A-Z ]+\-{5}\n?/g
  clePublique = clePublique.replaceAll(regEx, '')
  clePublique = await importerClePubliqueSubtle(clePublique)
  if(DEBUG) console.debug("Cle publique extraite du pem : %O", clePublique)

  const promises = Object.keys(secretsChiffres).map(async correlation => {
    var buffer = secretsChiffres[correlation]
    buffer = await dechiffrerCleSecreteSubtle(_cleMillegrilleSubtle.decrypt, buffer)
    buffer = await chiffrerCleSecreteSubtle(clePublique, buffer)
    if(DEBUG) console.debug("Cle %s rechiffree", correlation)
    return {[correlation]: buffer}
  })

  var resultats = await Promise.all(promises)
  if(DEBUG) console.debug("Resultats rechiffrage : %O", resultats)

  // Concatener toutes les reponses
  const secretsRechiffres = resultats.reduce((secretsRechiffres, item)=>{
    return {...secretsRechiffres, ...item}
  }, {})

  return secretsRechiffres
}

async function preparerCleSecreteSubtle(cleSecreteChiffree, iv) {
  return _preparerCleSecreteSubtle(cleSecreteChiffree, iv, clePriveeSubtleDecrypt)
}

comlinkExpose({
  initialiserCertificateStore, initialiserFormatteurMessage,
  initialiserCallbackCleMillegrille,
  chargerCleMillegrilleSubtle, clearCleMillegrilleSubtle,
  chiffrer, annulerUpload, uploaderFichier,
  downloadCacheFichier, annulerDownload,
  verifierCertificat, formatterMessage,
  chiffrerDocument, dechiffrerDocument,
  chiffrerCleSecreteSubtle, dechiffrerCleSecreteSubtle,
  rechiffrerAvecCleMillegrille, signerMessageCleMillegrille,
  clearInfoSecrete, preparerCleSecreteSubtle,

  dechiffrer,
})
