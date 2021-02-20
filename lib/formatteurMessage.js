const debug = require('debug')('millegrilles:common:formatteurMessage')
const stringify = require('json-stable-stringify')
const {pki: forgePki, md: forgeMd, asn1: forgeAsn1, util: forgeUtil, hmac: forgeHmac, mgf: forgeMgf, pss: forgePss} = require('node-forge')

const {hacher, calculerDigest} = require('./hachage')
const {encoderIdmg} = require('./idmg')

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

  constructor(certPem, clePem) {
    // Charger une instance de certificat
    this.cert = forgePki.certificateFromPem(certPem)

    // Le IDMG est place dans le champ organizationName du subject
    // Note: on assume que le certificat a deja ete valide.
    this.idmg = this.cert.issuer.getField("O").value

    // Calculer le fingerprint du certificat - il sera insere dans l'en-tete
    const this_inst = this
    hacherCertificat(this.cert)
      .then(fingerprint=>{this_inst.fingerprint = fingerprint})

    // Creer une instance de signateur
    this.signateurMessage = new SignateurMessage(clePem)
  }

  formatterMessage(message) {

  }

}

class SignateurMessage {

  constructor(pemCle) {
    this.cle = forgePki.privateKeyFromPem(pemCle)
  }

  async signer(message) {
    // const sign = crypto.createSign('SHA512');
    //
    // // Stringify en json trie
    // let transactionJson = stringify(transaction);
    //
    // // Creer algo signature et signer
    // sign.write(transactionJson);
    // let parametresSignature = {
    //   "key": this.cle,
    //   "padding": crypto.constants.RSA_PKCS1_PSS_PADDING,
    //   saltLength: 64,  // 64 bytes pour supporter iPhone max
    // }
    // signature = sign.sign(parametresSignature, 'base64');
    //
    // return signature;
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
    const signature = forgeUtil.encode64(this.cle.sign(digestInfo, pss));

    return forgeUtil.encode64(signature)
  }

}

function hacherCertificat(cert) {
  const derBytes = forgeAsn1.toDer(forgePki.certificateToAsn1(cert)).getBytes()

  // Retourner promise
  return hacher(derBytes, {hashingCode: 'sha2-256'})
}

module.exports = {
  hacherMessage, FormatteurMessage, SignateurMessage,
}
