const debug = require('debug')('millegrilles:common:pki')
const crypto = require('crypto')
const forge = require('node-forge')
const stringify = require('json-stable-stringify')
const fs = require('fs')
const path = require('path')
const tmp = require('tmp')
const forgecommon = require('./forgecommon')

const REPERTOIRE_CERTS_TMP = tmp.dirSync().name
debug("Repertoire temporaire certs : %s", REPERTOIRE_CERTS_TMP);

const PEM_CERT_DEBUT = '-----BEGIN CERTIFICATE-----'
const PEM_CERT_FIN = '-----END CERTIFICATE-----'

class MilleGrillesPKI {
  // Classe qui supporte des operations avec certificats et cles privees.

  constructor(certs) {
    this.idmg = null

    // Cle pour cert
    this.cle = null
    this.password = null  // Mot de passe pour la cle, optionnel

    // Liste de certificats de la chaine
    this.chaineCertificatsList = null

    // Contenu format texte PEM
    this.chainePEM = null
    this.hotePEM = null  // Chaine XS pour connexion middleware
    this.hoteCA = null
    this.ca = null

    this.caIntermediaires = []

    // Objets node-forge
    this.certPEM = null
    this.cleForge = null  // Objet cle charge en memoire (forge)
    this.cert = null      // Objet certificat charge en memoire (forge)
    this.caForge = null   // CA (certificat de MilleGrille)
    this.caStore = null   // CA store pour valider les chaines de certificats

    this.cacheCertsParFingerprint = {}

    this.algorithm = 'aes256'
    this.rsaAlgorithm = 'RSA-OAEP'
  }

  async chargerPEMs(certs) {

    // Cle pour cert
    this.cle = certs.key
    this.password = certs.password  // Mot de passe pour la cle, optionnel

    // Contenu format texte PEM
    this.chainePEM = certs.cert
    this.hotePEM = certs.hote || certs.cert  // Chaine XS pour connexion middleware
    this.hoteCA = certs.hoteMillegrille || certs.millegrille
    this.ca = certs.millegrille

    // Preparer repertoire pour sauvegarder PEMS
    fs.mkdir(REPERTOIRE_CERTS_TMP, {recursive: true, mode: 0o700}, e=>{
      if(e) {
        throw new Error(e)
      }
    });

    // Charger le certificat pour conserver commonName, fingerprint
    await this.chargerCertificats(certs)
    this._verifierCertificat()

    let cle = this.cle
    if(this.password) {
      debug("Cle chiffree")
      this.cleForge = forge.pki.decryptRsaPrivateKey(cle, this.password)
      // Re-exporter la cle en format PEM dechiffre (utilise par RabbitMQ)
      this.cle = forge.pki.privateKeyToPem(this.cleForge)
    } else {
      this.cleForge = forge.pki.privateKeyFromPem(cle)
    }

  }

  _verifierCertificat() {
    this.getFingerprint()
  }

  async chargerCertificats(certPems) {

    // Charger certificat local
    var certs = splitPEMCerts(certPems.cert);
    this.chaineCertificatsList = certs
    debug(certs);
    this.certPEM = certs[0];

    let parsedCert = this.chargerCertificatPEM(this.certPEM);

    this.idmg = parsedCert.issuer.getField("O").value;
    debug("IDMG %s", this.idmg);

    this.fingerprint = getCertificateFingerprint(parsedCert);
    this.cert = parsedCert;
    this.commonName = parsedCert.subject.getField('CN').value;

    // Sauvegarder certificats intermediaires
    const certsChaineCAList = certs.slice(1);
    const certsIntermediaires = [];
    for(let idx in certsChaineCAList) {
      var certIntermediaire = certsChaineCAList[idx];
      let intermediaire = this.chargerCertificatPEM(certIntermediaire);
      certsIntermediaires.push(intermediaire);
    }
    this.caIntermediaires = certsIntermediaires;

    // Creer le CA store pour verifier les certificats.
    let parsedCACert = this.chargerCertificatPEM(this.ca);
    this.caForge = parsedCACert
    this.caStore = forge.pki.createCaStore([parsedCACert]);

  }

  chargerCertificatPEM(pem) {
    let parsedCert = forge.pki.certificateFromPem(pem);
    return parsedCert;
  }

  getFingerprint() {
    return this.fingerprint;
  }

  getCommonName() {
    return this.commonName;
  }

  signerTransaction(transaction) {

    let signature = 'N/A';
    const sign = crypto.createSign('SHA512');

    // Stringify en json trie
    let transactionJson = stringify(transaction);

    // Creer algo signature et signer
    sign.write(transactionJson);
    let parametresSignature = {
      "key": this.cle,
      "padding": crypto.constants.RSA_PKCS1_PSS_PADDING
    }
    signature = sign.sign(parametresSignature, 'base64');

    return signature;
  }

  hacherTransaction(transaction) {
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

    return hachage_transaction;

    // const contenuTransaction = {}
    // for(let key in transaction) {
    //   if(key !== 'en-tete' && ! key.startsWith('_')) {
    //     contenuTransaction[key] = transaction[key]
    //   }
    // }
    //
    // const contenuString = stringify(contenuTransaction)
    //
    // var digest = forge.md.sha256.create()
    //   .update(contenuString, 'utf-8')
    //   .digest()
    //
    // const digestBase64 = forge.util.encode64(digest.getBytes())
    // return digestBase64
  }

  preparerMessageCertificat() {
    // Retourne un message qui peut etre transmis a MQ avec le certificat
    // utilise par ce noeud. Sert a verifier la signature des transactions.
    const certificatBuffer = this.certPEM;

    let transactionCertificat = {
        evenement: 'pki.certificat',
        fingerprint: this.fingerprint,
        certificat_pem: certificatBuffer,
    }

    return transactionCertificat;
  }

  crypterContenu(certificat, contenu) {
    // Crypte un dict en JSON et retourne la valeur base64 pour
    // le contenu et la cle secrete cryptee.
    return this._creerCipherKey(certificat).then(({cipher, encryptedSecretKey, iv}) => {
      let contenuString = JSON.stringify(contenu);
      let contenuCrypte = cipher.update(contenuString, 'utf8', 'base64');
      contenuCrypte += cipher.final('base64');

      return {contenuCrypte, encryptedSecretKey, iv};
    });
  }

  async decrypterAsymetrique(contenuSecret) {
    debug("CONTENU SECRET CHIFFRE : " + contenuSecret)
    let cleSecrete = forge.util.decode64(contenuSecret);

    // Decrypter la cle secrete avec notre cle privee
    var decryptedSecretKey = this.cleForge.decrypt(cleSecrete, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create()
      }
    });
    return decryptedSecretKey;
  }

  _creerCipherKey(certificat) {
    let promise = new Promise((resolve, reject) => {
      this.genererKeyAndIV((err, {key, iv})=>{
        if(err) {
          reject(err);
        }

        var cipher = crypto.createCipheriv(this.algorithm, key, iv);

        // Encoder la cle secrete
        var encryptedSecretKey = this.crypterContenuAsymetric(certificat.publicKey, key);
        iv = iv.toString('base64');

        resolve({cipher, encryptedSecretKey, iv});

      });
    });

    return promise;
  }

  crypterContenuAsymetric(publicKey, contentToEncrypt) {
    var keyByteString = forge.util.bytesToHex(contentToEncrypt);
    var encryptedContent = publicKey.encrypt(keyByteString, this.rsaAlgorithm, {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create()
      }
    });

    encryptedContent = forge.util.encode64(encryptedContent);
    return encryptedContent;
  }

  async creerCipherChiffrageAsymmetrique(certificats) {

    const keyIv = await new Promise((resolve, reject) => {
      this.genererKeyAndIV((err, keyIv)=>{
        if(err) return reject(err)
        resolve(keyIv)
      })
    })

    const cipher = crypto.createCipheriv(this.algorithm, keyIv.key, keyIv.iv)

    // Encoder la cle secrete
    const iv = keyIv.iv.toString('base64')

    const certClesChiffrees = {}
    certificats.forEach(certs=>{
      const certPem = certs[0]
      const cert = this.chargerCertificatPEM(certPem)
      const fingerprint = getCertificateFingerprintB64(cert)
      var encryptedSecretKey = this.crypterContenuAsymetric(cert.publicKey, keyIv.key);
      certClesChiffrees[fingerprint] = encryptedSecretKey
    })

    return({cipher, certClesChiffrees, iv})
  }

  async dechiffrerContenuAsymetric(cleSecrete, iv, contenuChiffre) {
    debug("dechiffrerContenuAsymetric: Cle secrete: %s\nIV: %s, contenuChiffre: %O", cleSecrete, iv, contenuChiffre)
    const cleSecreteDechiffree = await this.decrypterAsymetrique(cleSecrete)
    // debug("Cle secrete dechiffree : %O", cleSecreteDechiffree)

    const cleSecreteDechiffreeBytes = Buffer.from(cleSecreteDechiffree, 'hex')
    const ivBytes = Buffer.from(iv, 'base64')
    const bytesChiffreSymmetrique = Buffer.from(contenuChiffre.secret_chiffre, 'base64')

    // console.log("Creer decipher secretKey: " + cleSecreteBuffer.toString('base64') + ", iv: " + ivBuffer.toString('base64'));
    var decipher = crypto.createDecipheriv('aes-256-cbc', cleSecreteDechiffreeBytes, ivBytes);
    // console.debug("Decrypter " + contenuCrypte.toString('base64'));
    let contenuDecrypteString = decipher.update(bytesChiffreSymmetrique, 'base64',  'utf8')
    contenuDecrypteString += decipher.final('utf8')

    // Retirer 16 premiers bytes - emplacement du IV
    contenuDecrypteString = contenuDecrypteString.slice(16)
    // debug("Contenu dechiffre : %O", contenuDecrypteString)

    return contenuDecrypteString

    // const cleSecreteDechiffreeBytes = forge.util.hexToBytes(cleSecreteDechiffree)
    // const ivBytes = forge.util.decode64(iv)
    // const bytesChiffreSymmetrique = forge.util.createBuffer(contenuChiffre.secret_chiffre, 'base64') // Buffer.from(contenuChiffre.secret_chiffre, 'base64')

    // var decipher = forge.cipher.createDecipher('AES-CBC', cleSecreteDechiffreeBytes)
    // decipher.start({iv: ivBytes})
    // decipher.update(bytesChiffreSymmetrique)
    // var result = decipher.finish()
    //
    // if(result) {
    //   //const resultat = decipher.output.toByteArray()
    //   //const resultat = decipher.output.toHex()
    //   const resultatDecode = new TextDecoder().decode(Buffer.from(decipher.output.bytes()))
    //   debug("Resultat dechiffre : %O", resultatDecode)
    // } else {
    //   throw new Error("Dechiffrage incorrect")
    // }

  }

  async creerCipherChiffrageAsymmetrique(certificats) {

    const keyIv = await new Promise((resolve, reject) => {
      this.genererKeyAndIV((err, keyIv)=>{
        if(err) return reject(err)
        resolve(keyIv)
      })
    })

    const cipher = crypto.createCipheriv(this.algorithm, keyIv.key, keyIv.iv)

    // Encoder la cle secrete
    const iv = keyIv.iv.toString('base64')

    const certClesChiffrees = {}
    certificats.forEach(certs=>{
      const certPem = certs[0]
      const cert = this.chargerCertificatPEM(certPem)
      const fingerprint = getCertificateFingerprintB64(cert)
      var encryptedSecretKey = this.crypterContenuAsymetric(cert.publicKey, keyIv.key);
      certClesChiffrees[fingerprint] = encryptedSecretKey
    })

    return({cipher, certClesChiffrees, iv})
  }

  genererKeyAndIV(cb) {
    var lenBuffer = 16 + 32;
    crypto.pseudoRandomBytes(lenBuffer, (err, pseudoRandomBytes) => {
      // Creer deux buffers, iv (16 bytes) et password (24 bytes)
      var iv = pseudoRandomBytes.slice(0, 16);
      var key = pseudoRandomBytes.slice(16, pseudoRandomBytes.length);
      cb(err, {key: key, iv: iv});
    });
  }

  async genererRandomBytes(nbBytes, opts) {
    if(!opts) opts = {}
    return new Promise((resolve, reject)=>{
      crypto.pseudoRandomBytes(nbBytes, (err, pseudoRandomBytes) => {
        // Creer deux buffers, iv (16 bytes) et password (24 bytes)
        if(err) reject(err)
        else {
          if(opts.base64) {
            // Encoder les bytes en base64
            const b64Content = pseudoRandomBytes.toString('base64')
            resolve(b64Content)
          } else {
            resolve(pseudoRandomBytes)
          }
        }
      });
    })
  }

  extraireClePubliqueFingerprint(certificat) {

    const fingerprint = getCertificateFingerprint(certificat);

    const clePubliquePEM = forge.pki.publicKeyToPem(certificat.publicKey);

    var clePublique = clePubliquePEM
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '');

    // Remplacer les \n pour mettre la cle sur une seule ligne
    clePublique = clePublique.split('\n').join('');

    return {clePublique, fingerprint};
  }

  // Sauvegarde un message de certificat en format JSON
  async sauvegarderMessageCertificat(message, fingerprint) {
    let fichierExiste = fingerprint && await new Promise((resolve, reject)=>{
      if(fingerprint) {
        // Verifier si le fichier existe deja
        let fichier = path.join(REPERTOIRE_CERTS_TMP, fingerprint + '.json');
        fs.access(fichier, fs.constants.F_OK, (err) => {
          let existe = ! err;
          resolve(existe);
        });
      } else {
        resolve(false);
      }
    });

    if( ! fichierExiste ) {
      let json_message = JSON.parse(message);
      let certificat_pem = json_message.certificat_pem || json_message.resultats.certificat_pem;

      let certificat = this.chargerCertificatPEM(certificat_pem);
      let fingerprintCalcule = getCertificateFingerprint(certificat);
      let fichier = path.join(REPERTOIRE_CERTS_TMP, fingerprintCalcule + '.json');

      // Sauvegarder sur disque
      fs.writeFile(fichier, message, ()=>{
        debug("Fichier certificat %s.json sauvegarde", fingerprintCalcule);
      });
    } else {
      debug("Fichier certificat existe deja : %s.json", fingerprint);
    }
  }

  // Charge la chaine de certificats pour ce fingerprint
  async getCertificate(fingerprint) {
    let certificat = this.cacheCertsParFingerprint[fingerprint];
    if( ! certificat ) {
      // Verifier si le certificat existe sur le disque
      certificat = await new Promise((resolve, reject)=>{
        let fichier = path.join(REPERTOIRE_CERTS_TMP, fingerprint + '.json');
        let pem = fs.readFile(fichier, (err, data)=>{
          if(err) {
            return reject(err);
          }

          if(!data) {
            return resolve(); // No data
          }

          try {
            let messageJson = JSON.parse(data.toString());
            let pem = messageJson.certificat_pem;
            let intermediaires = messageJson.certificats_intermediaires;

            if( ! intermediaires ) {
              // On va tenter d'introduire le certificat de MilleGrille local
              intermediaires = this.caIntermediaires;
            }

            let certificat = this.chargerCertificatPEM(pem);

            let chaine = [certificat, ...intermediaires];

            let fingerprintCalcule = getCertificateFingerprint(certificat);
            if(fingerprintCalcule !== fingerprint) {
              // Supprimer fichier invalide
              fs.unlink(fichier, ()=>{});
              return reject('Fingerprint ' + fingerprintCalcule + ' ne correspond pas au fichier : ' + fingerprint + '.json. Fichier supprime.');
            }

            // Valider le certificat avec le store
            let valide = true;
            try {
              forge.pki.verifyCertificateChain(this.caStore, chaine);
            } catch (err) {
              valide = false;
              debug('Certificate verification failure: %s', JSON.stringify(err, null, 2));
            }

            if(valide) {
              this.cacheCertsParFingerprint[fingerprintCalcule] = chaine;
            } else {
              certificat = null;
            }

            resolve(chaine);

          } catch(err) {
            console.error(new Date() + " Erreur traitement certificat");
            console.error(data);
            return reject(new Error('Erreur traitement certificat'));
          }

        });
      })
      .catch(err=>{
        if(err.code === 'ENOENT') {
          // Fichier non trouve, ok.
        } else {
          console.error(new Date() + " Erreur acces fichier cert");
          console.error(err);
        }
      });
    }
    return certificat;
  }

  // Verifie la signature d'un message
  // Retourne vrai si le message est valide, faux si invalide.
  async verifierSignatureMessage(message) {
    let fingerprint = message['en-tete']['certificat'];
    let signatureBase64 = message['_signature'];
    let signature = Buffer.from(signatureBase64, 'base64');
    let certificatChaine = await this.getCertificate(fingerprint)
    if( ! certificatChaine && message['_certificat']) {
      // Verifier la chaine de certificats inclue avec le message
      const chaineInclue = message['_certificat']
      const store = new forgecommon.CertificateStore(this.ca)
      if(store.verifierChaine(chaineInclue)) {
        certificatChaine = [this.chargerCertificatPEM(chaineInclue[0])]
      }
    }
    if( ! certificatChaine ) {
      debug("Certificat inconnu : " + fingerprint);
      throw new CertificatInconnu("Certificat inconnu : " + fingerprint);
    }
    const certificat = certificatChaine[0];

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

  // Calcule le IDMG a partir d'un certificat PEM
  calculerIdmg(certificatPEM) {
    const cert = forge.pki.certificateFromPem(certificatPEM)

    const fingerprint = forge.md.sha512.sha224.create()
      .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
      .digest()
      .toHex()
    const buffer = Buffer.from(fingerprint, 'hex')
    const idmg = base58.encode(buffer)

    return idmg
  }

  signerContenuString(contenuString) {
    return forgecommon.signerContenuString(this.cleForge, contenuString)
  }

  getChainePems() {
    const pems = this.chainePEM
    return splitPEMCerts(pems)
  }

}

function getCertificateFingerprint(cert) {
  const fingerprint = forge.md.sha1.create()
    .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .toHex();
  return fingerprint
}

function getCertificateFingerprintB64(cert) {
  const digest = forge.md.sha1.create()
    .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
    .digest()

  const fingerprintBase64 = forge.util.encode64(digest.getBytes())
  return fingerprintBase64
}

function splitPEMCerts(certs) {
  var splitCerts = certs.split(PEM_CERT_DEBUT).map(c=>{
    return PEM_CERT_DEBUT + c
  })
  return splitCerts.slice(1)
}

class CertificatInconnu extends Error {
  constructor(message) {
    super(message);
    this.inconnu = true;
  }
}

module.exports = MilleGrillesPKI
