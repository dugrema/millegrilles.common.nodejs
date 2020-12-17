const debug = require('debug')('millegrilles:forgecommon')
const crypto = require('crypto')
const {pki, md, asn1, pss, mgf, util} = require('node-forge')
const base58 = require('base-58')
const stringify = require('json-stable-stringify')
const {v4: uuidv4} = require('uuid')

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

function sauvegarderPrivateKeyToPEM(privateKey) {
  // Exporte une cle privee Forge en format PKCS8 pour importer dans subtle

  var rsaPrivateKey = pki.privateKeyToAsn1(privateKey);
  // wrap an RSAPrivateKey ASN.1 object in a PKCS#8 ASN.1 PrivateKeyInfo
  var privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);
  // convert a PKCS#8 ASN.1 PrivateKeyInfo to PEM
  var pem = pki.privateKeyInfoToPem(privateKeyInfo);
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


  verifierChaine(chainePEM, opts) {
    // opts:
    //   - validityCheckDate : new Date() object
    if(!opts) opts = {}

    // Charger PEMs vers format forge
    const chaineCerts = chainePEM.map(item=>{
      return pki.certificateFromPem(item)
    })

    // if(opts.validityCheckDate) console.debug("Date validation certificats %s", opts.validityCheckDate)

    let valide = true;
    try {
      pki.verifyCertificateChain(this.caStore, chaineCerts, opts);
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


  const signatureBytes = util.decode64(signature)

  var signMd = md.sha512.create();
  signMd.update(contenuString, 'utf8');
  try {
    if(opts.isPEM) {
      const cert = pki.certificateFromPem(clePublique)
      clePublique = cert.publicKey
    }

    // Calcul taille salt:
    // http://bouncy-castle.1462172.n4.nabble.com/Is-Bouncy-Castle-SHA256withRSA-PSS-compatible-with-OpenSSL-RSA-PSS-padding-with-SHA256-digest-td4656843.html
    // const modulusLength = clePublique.n.bitLength()
    // debug("Public key (modulus : %d) pour verifier signature : %O", modulusLength, clePublique)

    // Changer salt a 64, c'est le max supporte sur iPhone
    const saltLength = 64  //(modulusLength - 512) / 8 - 2

    const pssInstance = pss.create({
      md: md.sha512.create(),
      mgf: mgf.mgf1.create(md.sha512.create()),
      saltLength, //: 20
    });

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

function extraireClePubliquePEM(certificatPEM, opts) {
  const cert = pki.certificateFromPem(certificatPEM)
  const clePublique = cert.publicKey
  return pki.publicKeyToPem(clePublique)
}

function chargerClePubliquePEM(certificatPEM, opts) {
  return pki.publicKeyFromPem(certificatPEM)
}

function validerChaineCertificats(chainePEM, opts) {
  if(chainePEM.length > 3) {
    throw new Error("Chaine de certificat > 3, le cross-signing n'est pas supporte pour l'authentification web")
  }
  if(!opts) opts = {}

  // Calculer idmg
  const certCa = chainePEM[2]
  const idmg = opts.idmg || calculerIdmg(certCa)

  // Verifier chaine de certificats du client
  const clientStore = opts.clientStore || new CertificateStore(certCa, {isPEM: true})
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

  return {cert: certClient, idmg: idmgIssuer, idmgCa: idmg, clientStore}
}

function verifierChallengeCertificat(certClient, messageSigne) {
  // Verifier la signature du message
  const signature = messageSigne['_signature']
  if(!signature) throw new Error("Signature introuvable")

  const copieMessage = {...messageSigne}
  delete copieMessage['_signature']
  delete copieMessage['_signatures']
  const stableJsonStr = stringify(copieMessage)
  const signatureOk = verifierSignatureString(certClient.publicKey, stableJsonStr, signature)

  return signatureOk
}

function extraireInformationCertificat(pem) {
  const cert = pki.certificateFromPem(pem)
  var clePublique = pki.publicKeyToPem(cert.publicKey)
  clePublique = clePublique.split('\n').join('').replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '')
  const fingerprintBytes = md.sha1.create()
    .update(asn1.toDer(pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .getBytes()

  const fingerprint = fingerprintBytes.toString('hex')
  const fingerprintBase64 = util.encode64(fingerprintBytes)

  var fingerprintSha256Base64 = md.sha256.create()
    .update(asn1.toDer(pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .getBytes()
  fingerprintSha256Base64 = util.encode64(fingerprintSha256Base64)

  // Extraire niveaux de securite des extensions du certificat
  var niveauxSecurite = ''
  try {
    const niveauxSecuriteList = cert.extensions.filter(ext=>{return ext.id === '1.2.3.4.0'}).map(item=>{return item.value.split(',')})
    niveauxSecurite = niveauxSecuriteList.reduce((array, item)=>{return [...array, ...item]}, [])
  } catch(err) {console.debug("Erreur lecture niveaux de securite du certificat: %O", err)}

  // Extraire roles des extensions du certificat
  var roles = ''
  try {
    const rolesList = cert.extensions.filter(ext=>{return ext.id === '1.2.3.4.1'}).map(item=>{return item.value.split(',')})
    roles = rolesList.reduce((array, item)=>{return [...array, ...item]}, [])
  } catch(err) {console.debug("Erreur lecture roles du certificat: %O", err)}

  return({cert, fingerprint, fingerprintSha256Base64, clePubliquePem: clePublique, fingerprintBase64, roles, niveauxSecurite})
}

class SignateurTransaction {

  constructor(chainePem, cle) {
    this.chainePem = chainePem
    this.cle = this._chargerCle(cle)

    const info = validerChaineCertificats(chainePem)
    this.idmg = info.idmgCa
    this.clientStore = info.clientStore

    const infoCert = extraireInformationCertificat(chainePem[0])
    this.fingerprintSha256Base64 = 'sha256_b64:' + infoCert.fingerprintSha256Base64
  }

  verifierCertificat(chainePem) {
    validerChaineCertificats(chainePem, {
      clientStore: this.clientStore,
      idmg: this.idmg,
    })
  }

  _chargerCle(cle) {
    return chargerClePrivee(cle)
  }

  formatterInfoTransaction(domaine, opts) {
    if(!opts) opts = {}

    // Ces valeurs n'ont de sens que sur le serveur.
    // Calculer secondes UTC (getTime retourne millisecondes locales)
    // debug("Formatter info transaction opts");
    // debug(opts);
    let version = 6;
    var uuidTransaction;
    version = opts.version || version;
    uuidTransaction = opts.uuidTransaction || uuidv4()

    let dateUTC = (new Date().getTime()/1000) // + new Date().getTimezoneOffset()*60;
    let tempsLecture = Math.trunc(dateUTC);
    let infoTransaction = {
      'domaine': domaine,
      'idmg': this.idmg,
      'uuid_transaction': uuidTransaction,
      'estampille': tempsLecture,
      'fingerprint_certificat': this.fingerprintSha256Base64,
      'hachage_contenu': '',  // Doit etre calcule a partir du contenu
      'version': version
    };

    return infoTransaction;
  }

  _calculerHachage(transaction) {
    let hachage_transaction = 'N/A';
    const hash = crypto.createHash('sha256');

    // Copier transaction sans l'entete
    let copie_transaction = {};
    for(let elem in transaction) {
      if (elem !== 'en-tete' && !elem.startsWith('_')) {
        copie_transaction[elem] = transaction[elem];
      }
    }

    // Stringify en json trie
    let transactionJson = stringify(copie_transaction);

    // Creer algo signature et signer
    hash.write(transactionJson, 'utf-8');

    hachage_transaction = hash.digest('base64')

    return 'sha256_b64:' + hachage_transaction

    // const contenuTransaction = {}
    // for(let key in transaction) {
    //   if(key !== 'en-tete' && ! key.startsWith('_')) {
    //     contenuTransaction[key] = transaction[key]
    //   }
    // }
    //
    // const contenuString = stringify(contenuTransaction)
    //
    // var digest = md.sha256.create()
    //   .update(contenuString, 'utf-8')
    //   .digest()
    //
    // const digestBase64 = util.encode64(digest.getBytes())
    // return digestBase64
  }

  async preparerTransaction(transaction, domaine, opts) {
    // Calculer hachage contenu

    // S'assurer que la signature (si presente) n'est pas inclue dans le calcul
    delete transaction['_signature']

    const hachage = this._calculerHachage(transaction)

    transaction['en-tete'] = this.formatterInfoTransaction(domaine)
    transaction['en-tete']['hachage_contenu'] = hachage
    // transaction['_certificat'] = this.chainePem

    // Calculer signature
    console.debug("Stringify transaction : %O", transaction)
    const contenuString = stringify(transaction)
    const signature = await this._signer(contenuString)
    transaction['_signature'] = signature
    transaction['_certificat'] = this.chainePem

    return transaction
  }

  async _signer(contenuString) {
    return signerContenuString(this.cle, contenuString)
  }
}

function comparerArraybuffers(buf1, buf2) {
  // https://stackoverflow.com/questions/21553528/how-to-test-for-equality-in-arraybuffer-dataview-and-typedarray
  if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
}

module.exports = {
  calculerIdmg, verifierIdmg, chiffrerPrivateKeyPEM, enveloppePEMPublique, enveloppePEMPrivee,
  matchCertificatKey, CertificateStore, genererRandomSerial, splitPEMCerts,
  signerContenuString, verifierSignatureString, chargerClePrivee, chargerCertificatPEM,
  chiffrerPrivateKey, calculerHachageCertificatPEM, chargerClePubliquePEM,
  validerChaineCertificats, verifierChallengeCertificat, sauvegarderPrivateKeyToPEM,
  extraireClePubliquePEM, extraireInformationCertificat, SignateurTransaction,
  comparerArraybuffers,
}
