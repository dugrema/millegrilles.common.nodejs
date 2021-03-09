const {pki, md, asn1, util: pkiUtil, oids: pkiOids } = require('node-forge')
const {genererRandomSerial} = require('./forgecommon')
const {encoderIdmg} = require('./idmg')

const JOUR_EPOCH_MS = 24 * 60 * 60 * 1000,     // Jour en ms : 24h * 60min * 60secs * 1000ms
      CERT_NAV_DUREE = 6 * 7 * JOUR_EPOCH_MS,  // 6 semaines (6 * 7 jours)
      CERT_COMPTE_SIMPLE_DUREE = 3 * 366 * JOUR_EPOCH_MS,  // 3 ans
      CERT_COMPTE_COMPLET_DUREE = 18 * 31 * JOUR_EPOCH_MS  // 18 mois

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
async function genererCertificatMilleGrille(clePriveePEM, clePubliquePEM) {

  // console.debug("Creation nouveau certificat de MilleGrille")
  // console.debug("Cle Publique : %s", clePubliquePEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const clePrivee = pki.privateKeyFromPem(clePriveePEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 20)

  var attrs = [{
    name: 'commonName',
    value: 'MilleGrille'
  }]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)  // Self, genere un certificat self-signed (racine)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: true,
    pathLenConstraint: 5,
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: true,
  }])

  // Signer certificat
  // cert.md = md.sha512.create()
  await cert.sign(clePrivee, md.sha512.create())

  // Exporter sous format PEM
  var pem = pki.certificateToPem(cert)

  var idmg = await encoderIdmg(pem)

  return {cert, pem, idmg}

}

// Genere une requete de signature pour un certificat intermediaire
// Permet de faire signer un navigateur avec une cle de MilleGrille cote client
// Note : ne pas utiliser sur navigateur (trop lent)
function genererCSRIntermediaire(opts) {
  if(!opts) opts = {}

  console.debug("Creation nouveau CSR intermediaire, key pair")
  const keys = pki.rsa.generateKeyPair(2048)

  const csr = pki.createCertificationRequest()

  csr.publicKey = keys.publicKey

  const clePrivee = opts.clePrivee || keys.privateKey

  // Signer requete
  csr.sign(clePrivee)

  // Exporter sous format PEM
  const csrPem = pki.certificationRequestToPem(csr)
  const clePriveePem = pki.privateKeyToPem(clePrivee)

  return {clePriveePem, csrPem}

}

function genererKeyPair() {
  const keypair = pki.rsa.generateKeyPair(2048)
  const clePubliquePEM = pki.publicKeyToPem(keypair.publicKey)
  return {clePrivee: keypair.privateKey, clePublique: keypair.publicKey, clePubliquePEM}
}

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
// cleSignateur : peut etre une cle privee Forge ou Subtle (type sign)
async function genererCertificatIntermediaire(idmg, certificatRacine, cleSignateur, infoPublique) {

  // console.debug("Creation nouveau certificat intermediaire")
  // console.debug("Info Publique")
  // console.debug(infoPublique)

  var commonName = idmg

  const cert = pki.createCertificate()
  if(infoPublique.clePubliquePEM) {
    const clePublique = pki.publicKeyFromPem(infoPublique.clePubliquePEM)
    cert.publicKey = clePublique
  } else if(infoPublique.csrPEM) {
    const csr = pki.certificationRequestFromPem(infoPublique.csrPEM)
    const valide = csr.verify()
    if(!valide) throw new Error("CSR invalide")
    cert.publicKey = csr.publicKey
    commonName = csr.subject.getField('CN').value
  } else {
    throw new Error("Cle publique ou CSR absent")
  }

  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()

  const expiration = cert.validity.notBefore.getTime() + CERT_COMPTE_SIMPLE_DUREE
  cert.validity.notAfter = new Date(expiration)

  var attrs = [{
    name: 'commonName',
    value: commonName
  },{
    name: 'organizationalUnitName',
    value: infoPublique.OU || 'intermediaire'
  },{
    name: 'organizationName',
    value: idmg
  }]
  cert.setSubject(attrs)
  cert.setIssuer(certificatRacine.subject.attributes)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: true,
    pathLenConstraint: 4,
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: certificatRacine.generateSubjectKeyIdentifier().data,
  }])

  // Signer certificat

  // Detecter type de cle privee - forge ou subtle
  var pem = null
  if( cleSignateur.privateKeyFromAsn1 ) {
    // Forge
    cert.sign(cleSignateur, md.sha512.create())
  } else {
    // Subtle
    pem = await signerCertificatCleSubtle(cert, cleSignateur)
  }

  return {cert, pem}
}

async function signerCertificatCleSubtle(certificatForge, cleSubtle) {
  // Utilise une cle cryptoSubtle pour signer un certificate builder node-forge

  // Extraire le type de hachage utilise par la cle
  const paramsSignature = { "name": cleSubtle.algorithm.name }
  const hachage = cleSubtle.algorithm.hash.name.toLowerCase().replace('-', '')
  // console.debug("hachage : %s", hachage)

  // Source csr.sign : https://github.com/digitalbazaar/forge/blob/master/lib/x509.js
  var algorithmOid = pkiOids[hachage + 'WithRSAEncryption']
  if(!algorithmOid) {
    var error = new Error('Could not compute certification request digest. ' +
      'Unknown message digest algorithm OID.')
    error.algorithm = certificatForge.md.algorithm
    throw error
  }
  certificatForge.signatureOid = certificatForge.siginfo.algorithmOid = algorithmOid

  // get TBSCertificate, convert to DER
  certificatForge.tbsCertificate = pki.getTBSCertificate(certificatForge)
  var certAsn1Bytes = asn1.toDer(certificatForge.tbsCertificate)

  const contenuDigestHex = certAsn1Bytes.toHex()
  const contenuAb = new Uint8Array(Buffer.from(contenuDigestHex, 'hex'))
  // console.debug("Subtle Contenu digest, hex: %s, AB: \n%O", contenuDigestHex, contenuAb)
  const resultatSubtle = await window.crypto.subtle.sign(paramsSignature, cleSubtle, contenuAb)
  // console.debug("Resultat subtle :\n%O", resultatSubtle)

  certificatForge.signature = new pkiUtil.ByteStringBuffer(resultatSubtle).getBytes()

  return pki.certificateToPem(certificatForge)
}

// Genere un nouveau certificat de navigateur
async function genererCsrNavigateur(nomUsager, clePubliqueNavigateur, cleNavigateur) {

  console.debug("Creation CSR de fin")
  console.debug("Cle Publique : %s", clePubliqueNavigateur)

  console.debug("Creation nouveau CSR intermediaire, key pair")
  const csr = pki.createCertificationRequest()

  csr.publicKey = clePubliqueNavigateur

  var attrs = [{
    name: 'commonName',
    value: nomUsager
  }]
  csr.setSubject(attrs)

  // Signer requete
  csr.sign(cleNavigateur, md.sha512.create())

  // Exporter sous format PEM
  const csrPem = pki.certificationRequestToPem(csr)

  return csrPem
}

async function genererCertificatNavigateur(idmg, nomUsager, csrNavigateurPEM, certificatIntermediairePEM, cleSignateur) {

  console.debug("Creation nouveau certificat de fin")
  console.debug("CSR navigateur : %s", csrNavigateurPEM)

  const certificatIntermediaire = pki.certificateFromPem(certificatIntermediairePEM)
  const csrNavigateur = pki.certificationRequestFromPem(csrNavigateurPEM)

  if(!csrNavigateur.verify()) {
    throw new Error("CSR invalide")
  }

  const clePubliqueNavigateur = csrNavigateur.publicKey

  const cert = pki.createCertificate()
  cert.publicKey = clePubliqueNavigateur
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()

  const expiration = cert.validity.notBefore.getTime() + CERT_NAV_DUREE
  cert.validity.notAfter = new Date(expiration)

  // console.debug("CERT VALIDITY")
  // console.debug(cert.validity.notBefore)
  // console.debug(cert.validity.notAfter)

  var attrs = [{
    name: 'commonName',
    value: nomUsager
  },{
    name: 'organizationalUnitName',
    value: 'navigateur'
  },{
    name: 'organizationName',
    value: idmg
  }]
  cert.setSubject(attrs)
  cert.setIssuer(certificatIntermediaire.subject.attributes)
  cert.setExtensions([{
    name: 'basicConstraints',
    critical: true,
    cA: false,
  }, {
    name: 'subjectKeyIdentifier'
  }, {
    name: 'authorityKeyIdentifier',
    keyIdentifier: certificatIntermediaire.generateSubjectKeyIdentifier().data,
  },{
    name: 'keyUsage',
    keyCertSign: false,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }])

  // Signer certificat
  // cert.md = md.sha512.create()
  await cert.sign(cleSignateur, md.sha512.create())

  // Exporter sous format PEM
  var pem = pki.certificateToPem(cert)

  return {cert, pem}

}

module.exports = {
  genererCertificatMilleGrille,
  genererCSRIntermediaire, genererCertificatIntermediaire,
  genererCsrNavigateur, genererCertificatNavigateur, genererKeyPair,
}
