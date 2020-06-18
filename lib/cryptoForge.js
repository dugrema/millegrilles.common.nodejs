const {pki, md, asn1} = require('node-forge')
const {calculerIdmg, genererRandomSerial} = require('./forgecommon')

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
function genererCSRIntermediaire() {

  console.debug("Creation nouveau CSR intermediaire, key pair")

  const keys = pki.rsa.generateKeyPair(2048)

  const csr = pki.createCertificationRequest()

  csr.publicKey = keys.publicKey
  const clePrivee = keys.privateKey

  // Signer requete
  csr.sign(clePrivee)

  // Exporter sous format PEM
  const csrPem = pki.certificationRequestToPem(csr)

  return {clePrivee, csrPem}

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
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

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

// Genere un nouveau certificat de MilleGrille a partir d'un keypair
async function genererCertificatFin(idmg, certificatIntermediaire, cleSignateurPEM, clePubliquePEM) {

  console.debug("Creation nouveau certificat de fin")
  console.debug("Cle Publique : %s", clePubliquePEM)

  const clePublique = pki.publicKeyFromPem(clePubliquePEM)
  const cleSignateur = pki.privateKeyFromPem(cleSignateurPEM)

  const cert = pki.createCertificate()
  cert.publicKey = clePublique
  cert.serialNumber = genererRandomSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1)

  var attrs = [{
    name: 'commonName',
    value: 'navigateur'
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
  genererCertificatFin
}
