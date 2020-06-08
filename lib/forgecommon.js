const {pki, md, asn1} = require('node-forge')
const base58 = require('base-58')

const BEGIN_PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----",
      END_PUBLIC_KEY    = "-----END PUBLIC KEY-----",
      BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----",
      END_PRIVATE_KEY   = "-----END PRIVATE KEY-----"

// Calcule le IDMG a partir d'un certificat PEM
function calculerIdmg(certificatPEM) {
  const cert = pki.certificateFromPem(certificatPEM)

  const fingerprint = md.sha512.sha224.create()
    .update(asn1.toDer(pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .toHex()
  const buffer = Buffer.from(fingerprint, 'hex')
  const idmg = base58.encode(buffer)

  return idmg
}

function chiffrerPrivateKeyPEM(privateKeyPEM, motDePasse) {

  const privateKey = pki.privateKeyFromPem(privateKeyPEM);
  var pem = pki.encryptRsaPrivateKey(privateKey, motDePasse);
  // console.debug(pem);

  return pem

}

function enveloppePEMPublique(clePubliqueStr) {
  return [BEGIN_PUBLIC_KEY, clePubliqueStr, END_PUBLIC_KEY].join('\n')
}

function enveloppePEMPrivee(clePriveeStr) {
  return [BEGIN_PRIVATE_KEY, clePriveeStr, END_PRIVATE_KEY].join('\n')
}


class CertificateStore {
  constructor(parsedCACert) {
    this.caStore = pki.createCaStore([parsedCACert])
  }

  verifierChaine(chainePEM) {

    // Charger PEMs vers format forge
    const chaineCerts = chainePEM.map(item=>{
      return pki.certificateFromPem(item)
    })

    let valide = true;
    try {
      pki.verifyCertificateChain(this.caStore, chaineCerts);
    } catch (err) {
      valide = false;
      console.warn('Certificate verification failure: %s', JSON.stringify(err, null, 2));
    }

    return valide
  }

}

function matchCertificatKey(certificatPEM, keyPEM) {
  const cert = pki.certificateFromPem(certificatPEM)
  const key = pki.privateKeyFromPem(keyPEM)

  // console.debug("Cert, cle")
  // console.debug(cert.publicKey.n)
  // console.debug(key.n)

  const cleCertMatch = cert.publicKey.n.compareTo(key.n) === 0
  // console.debug("Match : %s", cleCertMatch)

  return cleCertMatch
}

function genererRandomSerial() {
  const serial = '' + Math.floor(Math.random() * 10000000000000000000)
  if(serial.length < 2) {
    serial = '0' + serial
  }
  return serial
}

module.exports = {
  calculerIdmg, chiffrerPrivateKeyPEM, enveloppePEMPublique, enveloppePEMPrivee,
  matchCertificatKey, CertificateStore, genererRandomSerial
}
