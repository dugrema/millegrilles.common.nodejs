const {pki, md, asn1} = require('node-forge')
const {calculerIdmg, genererRandomSerial} = require('./forgecommon')

const JOUR_EPOCH_MS = 24 * 60 * 60 * 1000,     // Jour en ms : 24h * 60min * 60secs * 1000ms
      CERT_NAV_DUREE = 6 * 7 * JOUR_EPOCH_MS,  // 6 semaines (6 * 7 jours)
      CERT_COMPTE_SIMPLE_DUREE = 3 * 366 * JOUR_EPOCH_MS,  // 3 ans
      CERT_COMPTE_COMPLET_DUREE = 18 * 31 * JOUR_EPOCH_MS  // 18 mois

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
async function genererCertificatMilleGrille(clePriveePEM, clePubliquePEM) {

  console.debug("Creation nouveau certificat de MilleGrille")
  console.debug("Cle Publique : %s", clePubliquePEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const clePrivee = pki.privateKeyFromPem(clePriveePEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  var attrs = [{
    name: 'commonName',
    value: 'Racine'
  },{
    name: 'organizationName',
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

  var idmg = calculerIdmg(pem)

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
async function genererCertificatIntermediaire(idmg, certificatRacine, cleSignateur, infoPublique) {

  console.debug("Creation nouveau certificat intermediaire")
  console.debug("Info Publique")
  console.debug(infoPublique)

  const cert = pki.createCertificate()
  if(infoPublique.clePubliquePEM) {
    const clePublique = pki.publicKeyFromPem(infoPublique.clePubliquePEM)
    cert.publicKey = clePublique
  } else if(infoPublique.csrPEM) {
    const csr = pki.certificationRequestFromPem(infoPublique.csrPEM)
    const valide = csr.verify()
    if(!valide) throw new Error("CSR invalide")
    cert.publicKey = csr.publicKey
  } else {
    throw new Error("Cle publique ou CSR absent")
  }

  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()

  const expiration = cert.validity.notBefore.getTime() + CERT_COMPTE_SIMPLE_DUREE
  cert.validity.notAfter = new Date(expiration)

  var attrs = [{
    name: 'commonName',
    value: idmg
  },{
    name: 'organizationalUnitName',
    value: 'MilleGrille'
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
  // cert.md = md.sha512.create()
  await cert.sign(cleSignateur, md.sha512.create())

  // Exporter sous format PEM
  var pem = pki.certificateToPem(cert)

  return {cert, pem}

}

// Genere un nouveau certificat de navigateur
async function genererCsrNavigateur(idmg, nomUsager, clePubliqueNavigateur, cleNavigateur) {

  console.debug("Creation CSR de fin")
  console.debug("Cle Publique : %s", clePubliqueNavigateur)

  console.debug("Creation nouveau CSR intermediaire, key pair")
  const csr = pki.createCertificationRequest()

  csr.publicKey = clePubliqueNavigateur

  var attrs = [{
    name: 'commonName',
    value: nomUsager
  },{
    name: 'organizationalUnitName',
    value: 'Navigateur'
  },{
    name: 'organizationName',
    value: idmg
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
  genererCsrNavigateur, genererCertificatNavigateur, genererKeyPair
}
