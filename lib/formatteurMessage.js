const debug = require('debug')('millegrilles:common:formatteurMessage')
const stringify = require('json-stable-stringify')
const multibase = require('multibase')
const {pki: forgePki, md: forgeMd, asn1: forgeAsn1, util: forgeUtil, hmac: forgeHmac, mgf: forgeMgf, pss: forgePss} = require('node-forge')
const {v4: uuidv4} = require('uuid')

const {hacher, calculerDigest, hacherCertificat} = require('./hachage')
const {encoderIdmg} = require('./idmg')
const {detecterSubtle} = require('./chiffrage')

const BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
const VERSION_SIGNATURE = 0x1

const {subtle: _subtle} = detecterSubtle()

function splitPEMCerts(certs) {
  var splitCerts = certs.split(BEGIN_CERTIFICATE).map(c=>{
    return (BEGIN_CERTIFICATE + c).trim()
  })
  return splitCerts.slice(1)
}

function hacherMessage(message) {

  // Copier le message sans l'entete
  const copieMessage = {}
  for(let key in message) {
    if ( key !== 'en-tete' && ! key.startsWith('_') ) {
      copieMessage[key] = message[key]
    }
  }

  // Stringify en json trie
  const messageString = stringify(copieMessage)
  // Encoder en UTF_8
  debug("hacherMessage: messageString = %s", messageString)

  // Retourner promise de hachage
  return hacher(messageString, {hashingCode: 'sha2-256', encoding: 'base64'})

}

class FormatteurMessage {

  constructor(chainePem, cle) {
    if( typeof(chainePem) === 'string' ) {
      this.chainePem = splitPEMCerts(chainePem)
    } else {
      this.chainePem = chainePem
    }

    // Charger une instance de certificat
    this.cert = forgePki.certificateFromPem(this.chainePem[0])

    // Le IDMG est place dans le champ organizationName du subject
    // Note: on assume que le certificat a deja ete valide.
    this.idmg = this.cert.issuer.getField("O").value

    // Permettre de conserver le contexte et attendre initialisation au besoin
    const this_inst = this
    var promisesInit = []

    // Calculer le fingerprint du certificat - il sera insere dans l'en-tete
    promisesInit.push(
      hacherCertificat(this.cert)
        .then(fingerprint=>{
          // console.debug("Certificat utilise pour signature : %s", fingerprint)
          this_inst.fingerprint = fingerprint
        })
    )

    // Creer une instance de signateur
    promisesInit.push(
      this.initialiserSignateur(cle)
        .then(signateur=>{
          this.signateurMessage = signateur
        })
    )

    // Supporter attribut pour indiquer que la preparation est completee
    this._ready = false
    this._promisesInit = promisesInit
    Promise.all(promisesInit).then(_=>{
      this._promisesInit = null
      this._ready = true
    })
  }

  async ready() {
    if(this._promisesInit) {
      await Promise.all(promisesInit)
      return true
    }
    return this._ready
  }

  async initialiserSignateur(cle) {
    return new SignateurMessage(cle)
  }

  async formatterMessage(message, domaineAction, opts) {
    // Formatte le message
    var messageCopy = {...message}

    messageCopy = this._formatterInfoMessage(messageCopy, domaineAction, opts)

    // Hacher le message
    const hachageMessage = await hacherMessage(messageCopy)
    messageCopy['en-tete'].hachage_contenu = hachageMessage

    // Signer le message
    const signature = await this.signateurMessage.signer(messageCopy)
    messageCopy['_signature'] = signature

    return messageCopy
  }

  _formatterInfoMessage(message, domaineAction, opts) {
    opts = opts || {}

    const version = opts.version || 1
    const uuidTransaction = opts.uuidTransaction || uuidv4()

    const dateUTC = (Date.now() / 1000)  // + new Date().getTimezoneOffset() * 60
    const tempsLecture = Math.trunc(dateUTC)

    var entete = message['en-tete'] || {}
    entete = {...entete}  // Copie
    message['en-tete'] = entete

    entete.domaine = domaineAction
    entete.idmg = this.idmg
    entete.uuid_transaction = uuidTransaction
    entete.estampille = tempsLecture
    entete.fingerprint_certificat = this.fingerprint
    entete.hachage_contenu = ''
    entete.version = version

    if(opts.attacherCertificat) {
      message['_certificat'] = this.chainePem
    }

    return message
  }
}

class FormatteurMessageSubtle extends FormatteurMessage {

  // Override avec signateur subtle
  async initialiserSignateur(cle) {
    return new SignateurMessageSubtle(cle)
  }

}

class SignateurMessage {

  constructor(pemCle) {
    this.cle = forgePki.privateKeyFromPem(pemCle)
  }

  async signer(message) {
    const copieMessage = {}
    for(let key in message) {
      if ( ! key.startsWith('_') ) {
        copieMessage[key] = message[key]
      }
    }
    // Stringify en json trie
    const messageString = stringify(copieMessage)

    // Calculer digest du message
    const digestView = await calculerDigest(messageString, 'sha2-512')
    const digestInfo = {digest: _=>forgeUtil.createBuffer(digestView, 'raw')}

    // Signer avec la cle
    let pss = forgePss.create({
      md: forgeMd.sha512.create(),
      mgf: forgeMgf.mgf1.create(forgeMd.sha512.create()),
      saltLength: 64
    })
    // const signature = forgeUtil.encode64(this.cle.sign(digestInfo, pss));
    var signatureStringBuffer = this.cle.sign(digestInfo, pss)
    const versionBuffer = forgeUtil.createBuffer()
    versionBuffer.putByte(VERSION_SIGNATURE)
    versionBuffer.putBytes(signatureStringBuffer)
    // console.debug("Version + Signature buffer digest : %O", versionBuffer)

    signatureStringBuffer = versionBuffer.getBytes()
    // console.debug("Signature string buffer : %O", signatureStringBuffer)

    const signatureBuffer = Buffer.from(signatureStringBuffer, 'binary')
    // console.debug("Signature buffer : %O", signatureBuffer)

    const mbValeur = multibase.encode('base64', signatureBuffer)
    const mbString = String.fromCharCode.apply(null, mbValeur)

    return mbString
  }

}

class SignateurMessageSubtle {

  constructor(cleSubtle) {
    this.cle = cleSubtle
  }

  async signer(message) {
    const copieMessage = {}
    for(let key in message) {
      if ( ! key.startsWith('_') ) {
        copieMessage[key] = message[key]
      }
    }
    // Stringify en json trie
    const messageString = stringify(copieMessage)

    const clePrivee = this.cle

    // Calcul taille salt:
    // http://bouncy-castle.1462172.n4.nabble.com/Is-Bouncy-Castle-SHA256withRSA-PSS-compatible-with-OpenSSL-RSA-PSS-padding-with-SHA256-digest-td4656843.html
    // Salt - changer pour 64, maximum supporte sur le iPhone
    const modulusLength = clePrivee.algorithm.modulusLength
    const saltLength = 64 // (modulusLength - 512) / 8 - 2

    const paramsSignature = {
      name: clePrivee.algorithm.name,
      saltLength,
    }

    const encoder = new TextEncoder()
    const contenuAb = encoder.encode(messageString)

    var signature = await _subtle.sign(paramsSignature, clePrivee, contenuAb)

    // Ajouter version
    const bufferVersion = new ArrayBuffer(1)
    const viewBuffer = new Uint8Array(bufferVersion)
    viewBuffer.set([VERSION_SIGNATURE], 0)
    // console.debug("Signature buffer info : %O", signature)
    signature = Buffer.concat([Buffer.from(bufferVersion), Buffer.from(signature)])

    const mbValeur = multibase.encode('base64', new Uint8Array(signature))
    const mbString = String.fromCharCode.apply(null, mbValeur)

    return mbString
  }

}

module.exports = {
  FormatteurMessage, FormatteurMessageSubtle, hacherMessage, SignateurMessage,
  splitPEMCerts, SignateurMessageSubtle,
}
