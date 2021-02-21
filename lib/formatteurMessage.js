const debug = require('debug')('millegrilles:common:formatteurMessage')
const stringify = require('json-stable-stringify')
const multibase = require('multibase')
const {pki: forgePki, md: forgeMd, asn1: forgeAsn1, util: forgeUtil, hmac: forgeHmac, mgf: forgeMgf, pss: forgePss} = require('node-forge')
const {v4: uuidv4} = require('uuid')

const {hacher, calculerDigest} = require('./hachage')
const {encoderIdmg} = require('./idmg')

const BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"

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

  constructor(chainePem, clePem) {
    if( typeof(chainePem) === 'string' ) {
      this.chainePem = splitPEMCerts(chainePem)
    } else {
      this.chainePem = chainePem
    }

    // console.debug("Chaine PEM chargee : %O", this.chainePem)

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
          console.debug("Certificat utilise pour signature : %s", fingerprint)
          this_inst.fingerprint = fingerprint
        })
    )

    // Creer une instance de signateur
    this.signateurMessage = new SignateurMessage(clePem)

    // Supporter attribut pour indiquer que la preparation est completee
    this.ready = Promise.all(promisesInit)
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

    const dateUTC = (new Date().getTime() / 1000) + new Date().getTimezoneOffset() * 60
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
    const VERSION_SIGNATURE = 1
    signatureStringBuffer = forgeUtil.createBuffer(VERSION_SIGNATURE).getBytes() + signatureStringBuffer

    const signatureBuffer = Buffer.from(signatureStringBuffer, 'binary')

    const mbValeur = multibase.encode('base64', signatureBuffer)
    const mbString = String.fromCharCode.apply(null, mbValeur)

    return mbString
  }

}

function hacherCertificat(cert) {
  const derBytes = forgeAsn1.toDer(forgePki.certificateToAsn1(cert)).getBytes()
  const digest = new Uint8Array(Buffer.from(derBytes, 'binary'))

  // Retourner promise
  return hacher(digest, {hashingCode: 'sha2-256'})
}

module.exports = {
  hacherMessage, FormatteurMessage, SignateurMessage, hacherCertificat,
}