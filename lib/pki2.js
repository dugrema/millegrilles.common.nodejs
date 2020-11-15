const debug = require('debug')('millegrilles:common:pki2')
const crypto = require('crypto')
const forge = require('node-forge')
const stringify = require('json-stable-stringify')
const path = require('path')
const forgecommon = require('./forgecommon')

function preparerCertificateStore(caPem) {
  const ca = forge.pki.certificateFromPem(caPem)
  const store = new forgecommon.CertificateStore(ca)
  return store
}

// Verifie la signature d'un message
// Retourne vrai si le message est valide, faux si invalide.
function verifierSignatureMessage(message, certificatChaine, store) {
  let fingerprint = message['en-tete']['fingerprint_certificat'];
  let signatureBase64 = message['_signature'];
  let signature = Buffer.from(signatureBase64, 'base64');

  // Verifier la chaine de certificats inclue avec le message
  if(store.verifierChaine(certificatChaine)) {
    certificatChaine = [forge.pki.certificateFromPem(certificatChaine[0])]
  }
  const certificat = certificatChaine[0]

  let messageFiltre = {};
  for(let cle in message) {
    if( ! cle.startsWith('_') ) {
      messageFiltre[cle] = message[cle];
    }
  }

  // Stringify en ordre (stable)
  messageFiltre = stringify(messageFiltre);

  let keyLength = certificat.publicKey.n.bitLength();
  // Calcul taille salt:
  // http://bouncy-castle.1462172.n4.nabble.com/Is-Bouncy-Castle-SHA256withRSA-PSS-compatible-with-OpenSSL-RSA-PSS-padding-with-SHA256-digest-td4656843.html
  // Changement a 64 pour supporter iPhone
  let saltLength = 64  // (keyLength - 512) / 8 - 2;

  var pss = forge.pss.create({
    md: forge.md.sha512.create(),
    mgf: forge.mgf.mgf1.create(forge.md.sha512.create()),
    saltLength,
    // optionally pass 'prng' with a custom PRNG implementation
  });
  var md = forge.md.sha512.create();
  md.update(messageFiltre, 'utf8');

  try {
    var publicKey = certificat.publicKey
    let valide = publicKey.verify(md.digest().getBytes(), signature, pss)
    return valide
  } catch (err) {
    debug("Erreur verification signature")
    debug(err)
    return false
  }

}

module.exports = {preparerCertificateStore, verifierSignatureMessage}
