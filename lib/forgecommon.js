const debug = require('debug')('millegrilles:forgecommon')
const {pki, md, asn1, pss, mgf, util} = require('node-forge')
const base58 = require('base-58')
const stringify = require('json-stable-stringify')

const BEGIN_PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----",
      END_PUBLIC_KEY    = "-----END PUBLIC KEY-----",
      BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----",
      END_PRIVATE_KEY   = "-----END PRIVATE KEY-----",
      BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----",
      VERSION_IDMG      = 1


// Calcule le IDMG a partir d'un certificat PEM
function calculerIdmg(certificatPEM, opts) {
  if(!opts) opts = {}
  const version = opts.version || VERSION_IDMG

  const cert = pki.certificateFromPem(certificatPEM)

  // Calcul date expiration (epoch secs / 1000. Noter que getTime() retourne les millisecs)
  const date_expiration = cert.validity.notAfter
  const dateExpEpoch_1000 = Math.ceil(date_expiration.getTime() / 1000000)
  // debug("Expiration certificat epoch secs / 1000 : %s", dateExpEpoch_1000.toString(16))

  const arrayBufferIdmg = new ArrayBuffer(33)
  const viewUint8Idmg = new Uint8Array(arrayBufferIdmg)

  const fingerprint = md.sha512.sha224.create()
    .update(asn1.toDer(pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .toHex()
  const fingerprintBuffer = new Uint8Array(Buffer.from(fingerprint, 'hex'))

  const bufferExpiration = new ArrayBuffer(4)
  const view32Uint = new Uint32Array(bufferExpiration)
  view32Uint[0] = dateExpEpoch_1000

  // Set version courante dans le premier byte
  viewUint8Idmg[0] = version

  // Set fingerprint SHA512/224 dans bytes 1 a 28
  viewUint8Idmg.set(fingerprintBuffer, 1)

  // Set date expiration du cert dans 4 derniers bytes
  viewUint8Idmg.set(new Uint8Array(bufferExpiration), 29)

  const idmg = base58.encode(viewUint8Idmg)

  return idmg
}

function calculerHachageCertificatPEM(certificatPEM, opts) {
  if(!opts) opts = {}
  const version = opts.version || VERSION_IDMG

  const cert = pki.certificateFromPem(certificatPEM)

  const fingerprint = md.sha256.create()
    .update(asn1.toDer(pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .toHex()
  const fingerprintBuffer = new Uint8Array(Buffer.from(fingerprint, 'hex'))
  const hachage = base58.encode(fingerprintBuffer)

  return hachage
}

// function byteToHexString(uint8arr) {
//   if (!uint8arr) {
//     return '';
//   }
//
//   var hexStr = '';
//   for (var i = 0; i < uint8arr.length; i++) {
//     var hex = (uint8arr[i] & 0xff).toString(16);
//     hex = (hex.length === 1) ? '0' + hex : hex;
//     hexStr += hex;
//   }
//
//   return hexStr.toUpperCase();
// }

// Verifie la correspondance entre un IDMG et un certificat PEM
function verifierIdmg(idmg, certificatPEM) {
  // const cert = pki.certificateFromPem(certificatPEM)
  const bufferIdmg = base58.decode(idmg)
  const viewBufferIdmg = new Uint8Array(bufferIdmg)
  const version = viewBufferIdmg[0]

  if(version === 1) {
    const idmgCalcule = calculerIdmg(certificatPEM, {version})
    if(idmg !== idmgCalcule) {
      throw new Error("IDMG mismatch")
    }
  } else {
    throw new Error("Version IDMG non supportee : " + version)
  }
}

function chiffrerPrivateKey(privateKey, motDePasse) {
  var pem = pki.encryptRsaPrivateKey(privateKey, motDePasse);
  return pem
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
    return (BEGIN_CERTIFICATE + c).trim()
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

function chargerClePubliquePEM(certificatPEM, opts) {
  return pki.publicKeyFromPem(certificatPEM)
}

function validerCertificatFin(chainePEM, opts) {
  if(!opts) opts = {}

  if(chainePEM.length > 3) {
    throw new Error("Chaine de certificat > 3, le cross-signing n'est pas supporte pour l'authentification web")
  }

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

  if(organization !== idmg) {
    throw new Error("Certificat fin (O=" + organization + ") ne corespond pas au IDMG calcule " + idmg)
  }

  // Prendre le IDMG du issuer comme reference
  const idmgIssuer = certClient.issuer.getField('O').value
  if(idmgIssuer !== idmg) {
    throw new Error("Certificat intermediaire (O=" + idmgIssuer + ") ne corespond pas au IDMG calcule " + idmg)
  }

  if(opts.messageSigne) {
    // Verifier la signature du message
    const signatures = opts.messageSigne['_signatures']
    let signature;
    if(!signatures) {
      signature = opts.messageSigne['_signature']
    } else {
      signature = signatures[idmgIssuer]
    }
    const copieMessage = {...opts.messageSigne}
    delete copieMessage['_signature']
    delete copieMessage['_signatures']
    const stableJsonStr = stringify(copieMessage)
    const signatureOk = verifierSignatureString(certClient.publicKey, stableJsonStr, signature)

    if(!signatureOk) throw new Error("Signature invalide")
  }

  return {cert: certClient, idmg: idmgIssuer}
}

module.exports = {
  calculerIdmg, verifierIdmg, chiffrerPrivateKeyPEM, enveloppePEMPublique, enveloppePEMPrivee,
  matchCertificatKey, CertificateStore, genererRandomSerial, splitPEMCerts,
  signerContenuString, verifierSignatureString, chargerClePrivee, chargerCertificatPEM,
  validerCertificatFin, chiffrerPrivateKey, calculerHachageCertificatPEM,
  chargerClePubliquePEM,
}
