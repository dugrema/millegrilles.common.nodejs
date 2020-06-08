const {pki, md, asn1, pss, mgf, util} = require('node-forge')
const base58 = require('base-58')
const stringify = require('json-stable-stringify')

const BEGIN_PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----",
      END_PUBLIC_KEY    = "-----END PUBLIC KEY-----",
      BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----",
      END_PRIVATE_KEY   = "-----END PRIVATE KEY-----",
      BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"

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

function splitPEMCerts(certs) {
  var splitCerts = certs.split(BEGIN_CERTIFICATE).map(c=>{
    return BEGIN_CERTIFICATE + c
  })
  return splitCerts.slice(1)
}

class CertificateStore {
  constructor(caCert, opts) {
    if(!opts) opts = {}

    let parsedCA;
    if(opts.isPEM) {
      parsedCA = pki.certificateFromPem(caCert)
    } else {
      parsedCA = caCert
    }

    this.caStore = pki.createCaStore([parsedCA])
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

function signerContenuString(clePrivee, contenuString) {

  // Creer algo signature et signer
  const signMd = md.sha512.create()
  signMd.update(contenuString, 'utf-8')

  var pssInstance = pss.create({
    md: md.sha512.create(),
    mgf: mgf.mgf1.create(md.sha512.create()),
    saltLength: 20
  });

  const signature = util.encode64( clePrivee.sign(signMd, pssInstance) )

  return signature;
}

function verifierSignatureString(clePublique, contenuString, signature, opts) {
  if(!opts) opts = {}

  const pssInstance = pss.create({
    md: md.sha512.create(),
    mgf: mgf.mgf1.create(md.sha512.create()),
    saltLength: 20
  });

  const signatureBytes = util.decode64(signature)

  var signMd = md.sha512.create();
  signMd.update(contenuString, 'utf8');
  try {
    if(opts.isPEM) {
      const cert = pki.certificateFromPem(clePublique)
      clePublique = cert.publicKey
    }

    return clePublique.verify(signMd.digest().getBytes(), signatureBytes, pssInstance)
  } catch(err) {
    console.error(err)
    return false
  }
}

function chargerClePrivee(clePriveePEM, opts) {
  if(!opts) opts = {}

  if(opts.password) {
    debug("Cle chiffree")
    const cleForge = pki.decryptRsaPrivateKey(clePriveePEM, opts.password)
    return cleForge
  } else {
    return pki.privateKeyFromPem(clePriveePEM)
  }
}

function chargerCertificatPEM(certificatPEM, opts) {
  return pki.certificateFromPem(certificatPEM)
}

function validerCertificatFin(chainePEM, opts) {
  if(!opts) opts = {}

  // Calculer idmg
  const certCa = chainePEM[2]
  const idmg = calculerIdmg(certCa)

  // Verifier chaine de certificats du client
  const clientStore = new CertificateStore(certCa, {isPEM: true})
  const chaineOk = clientStore.verifierChaine(chainePEM)

  if(!chaineOk) throw new Error("Chaine de certificats invalide")

  const certClient = chargerCertificatPEM(chainePEM[0])

  // S'assurer que le certificat client correspond au IDMG (O=IDMG)
  const organization = certClient.subject.getField('O').value
  const idmgIssuer = certClient.issuer.getField('O').value

  if(organization !== idmg) {
    throw new Error("Certificat fin (O=" + organization + ") ne corespond pas au IDMG calcule " + idmg)
  }

  if(opts.messageSigne) {
    // Verifier la signature du message
    const signature = opts.messageSigne['_signature']
    const copieMessage = {...opts.messageSigne}
    delete copieMessage['_signature']
    const stableJsonStr = stringify(copieMessage)
    const signatureOk = verifierSignatureString(certClient.publicKey, stableJsonStr, signature)

    if(!signatureOk) throw new Error("Signature invalide")
  }

  return {cert: certClient, idmg: idmgIssuer}
}

module.exports = {
  calculerIdmg, chiffrerPrivateKeyPEM, enveloppePEMPublique, enveloppePEMPrivee,
  matchCertificatKey, CertificateStore, genererRandomSerial, splitPEMCerts,
  signerContenuString, verifierSignatureString, chargerClePrivee, chargerCertificatPEM,
  validerCertificatFin,
}
