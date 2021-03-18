/*
Module d'authentification web
*/
const debug = require('debug')('millegrilles:common:authentification')
const {randomBytes} = require('crypto')
const authenticator = require('authenticator')
const {genererChallenge, verifierChallenge} = require('./webauthn')
// const {verifierMotdepasse} = require('./validerAuthentification')
const { validerChaineCertificats, splitPEMCerts } = require('./forgecommon')
const { verifierSignatureMessage } = require('./validateurMessage')


const CONST_CHALLENGE_CERTIFICAT = 'challengeCertificat',
      CONST_AUTH_PRIMAIRE = 'authentificationPrimaire',
      CONST_AUTH_SECONDAIRE = 'authentificationSecondaire',
      CONST_CERTIFICAT_AUTH_CHALLENGE = 'certAuthChallenge',
      CONST_WEBAUTHN_CHALLENGE = 'webauthnChallenge'

async function verifierUsager(req, res, next) {
  /*
  Verifier l'existence d'un usager par methode http.
  Retourne des methodes d'authentification lorsque l'usager existe.
  Genere les challenges en session.

  Requires :
    - req.body
    - req.session
    - req.comptesUsagers
  */

  const nomUsager = req.body.nomUsager,
        fingerprintPk = req.body.fingerprintPk
  debug("Verification d'existence d'un usager : %s\nBody: %O", nomUsager, req.body)

  if( ! nomUsager ) {
    console.error("verifierUsager: Requete sans nom d'usager")
    return res.sendStatus(400)
  }

  const infoUsager = await req.comptesUsagers.chargerCompte(nomUsager, fingerprintPk)
  const compteUsager = infoUsager

  debug("Compte usager recu")
  debug(infoUsager)

  if(compteUsager) {
    // Usager connu
    const {methodesDisponibles} = await auditMethodes(req, req.body, {compteUsager})
    debug("Usager %s connu, transmission challenge login pour methodes : %O", nomUsager, methodesDisponibles)

    const reponse = {
      // Filtrer methodes webauthn, vont etre restructurees en un challenge
      methodesDisponibles: Object.keys(methodesDisponibles).filter(item=>!item.startsWith('webauthn.')),
      challengeCertificat: {
        date: new Date().getTime(),
        data: Buffer.from(randomBytes(32)).toString('base64'),
      }
    }

    req.session[CONST_CHALLENGE_CERTIFICAT] = reponse.challengeCertificat

    if(compteUsager.webauthn) {
      // Generer un challenge U2F
      debug("Information cle usager : %O", compteUsager.webauthn)
      const challengeWebauthn = await genererChallenge(methodesDisponibles)

      // Conserver challenge pour verif
      req.session[CONST_WEBAUTHN_CHALLENGE] = challengeWebauthn.challenge

      reponse.challengeWebauthn = challengeWebauthn
    }

    if(req.session[CONST_AUTH_PRIMAIRE]) {
      reponse[CONST_AUTH_PRIMAIRE] = req.session[CONST_AUTH_PRIMAIRE]
    }
    if(req.session[CONST_AUTH_SECONDAIRE]) {
      reponse[CONST_AUTH_SECONDAIRE] = req.session[CONST_AUTH_SECONDAIRE]
    }

    // Attacher le nouveau certificat de l'usager si disponible
    if(compteUsager.certificat) {
      reponse.certificat = compteUsager.certificat
    }

    res.send(reponse)
  } else {
    // Usager inconnu
    debug("Usager inconnu")
    res.sendStatus(401)
  }
}

async function genererChallengeWebAuthn(socket, params) {
  params = params || {}
  const nomUsager = socket.nomUsager,
        session = socket.handshake.session
  debug("genererChallenge2FA: Preparation challenge usager : %s, params: %O", nomUsager, params)

  if( ! nomUsager ) {
    console.error("verifierUsager: Requete sans nom d'usager")
    return cb({err: "Usager inconnu"})
  }

  // const nomUsager = req.nomUsager
  const comptesUsagers = socket.comptesUsagers
  const compteUsager = await comptesUsagers.chargerCompte(nomUsager)

  debug("Compte usager recu : %O", compteUsager)

  if(compteUsager) {
    // Usager connu, session ouverte

    const {methodesDisponibles} = await auditMethodes(socket.handshake, params, {compteUsager, socket})
    debug("Usager %s connu, transmission challenge login pour methodes : %O", nomUsager, methodesDisponibles)

    const reponse = {
      methodesDisponibles: Object.keys(methodesDisponibles).filter(item=>!item.startsWith('webauthn.')),
    }

    if(compteUsager.activations_par_fingerprint_pk) {
      // Trouver les fingerprint_pk qui sont disponibles (date OK et associe: false)
      const activationsDisponibles = Object.keys(compteUsager.activations_par_fingerprint_pk)
        .reduce((acc, fingerprintPk)=>{
            const info = compteUsager.activations_par_fingerprint_pk[fingerprintPk]
            if(info.associe === false) {
              acc = [...acc, fingerprintPk]
            }
            return acc
          }, [])
      reponse.activationsDisponibles = activationsDisponibles
    }

    // Generer challenge pour le certificat de navigateur ou cle de millegrille
    // Ces methodes sont toujours disponibles
    reponse.challengeCertificat = {
      date: new Date().getTime(),
      data: Buffer.from(randomBytes(32)).toString('base64'),
    }
    socket[CONST_CERTIFICAT_AUTH_CHALLENGE] = reponse.challengeCertificat

    if(compteUsager.webauthn) {
      // Generer un challenge U2F
      const challengeWebauthn = await genererChallenge(methodesDisponibles)
      if(challengeWebauthn.allowCredentials && challengeWebauthn.allowCredentials.length > 0) {
        // Conserver challenge pour verif
        socket[CONST_WEBAUTHN_CHALLENGE] = challengeWebauthn
        reponse.challengeWebauthn = challengeWebauthn
      }
    }

    // if(compteUsager.motdepasse) {
    //   reponse.motdepasseDisponible = true
    // }
    //
    // if(compteUsager.totp) {
    //   reponse.totpDisponible = true
    // }

    if(session[CONST_AUTH_PRIMAIRE]) {
      reponse[CONST_AUTH_PRIMAIRE] = session[CONST_AUTH_PRIMAIRE]
    }
    if(session[CONST_AUTH_SECONDAIRE]) {
      reponse[CONST_AUTH_SECONDAIRE] = session[CONST_AUTH_SECONDAIRE]
    }

    return reponse
  } else {
    return {err: "Erreur - compte usager n'est pas disponible"}
  }
}

async function genererChallengeCertificat(socket) {
  /* Mode standalone, e.g. apps */
  const nomUsager = socket.nomUsager,
        session = socket.handshake.session
  debug("genererChallengeCertificat: Preparation challenge usager : %s", nomUsager)

  // Generer challenge pour le certificat de navigateur ou cle de millegrille
  // Ces methodes sont toujours disponibles
  const reponse = {}
  reponse.challengeCertificat = {
    date: new Date().getTime(),
    data: Buffer.from(randomBytes(32)).toString('base64'),
  }
  socket[CONST_CERTIFICAT_AUTH_CHALLENGE] = reponse.challengeCertificat

  return reponse
}

function auditMethodesDisponibles(compteUsager, opts) {
  opts = opts || {}

  // Creer une liste de methodes disponibles et utilisees
  // Comparer pour savoir si on a une combinaison valide
  const methodesDisponibles = {certificat: true}

  // Methodes disponibles
  if(compteUsager.totp) methodesDisponibles.totp = true
  if(compteUsager.motdepasse) methodesDisponibles.motdepasse = true
  if(compteUsager.webauthn) {
    // Mettre chaque methode comme cle - permet de facilement retirer la/les
    // creds deja utilisees pour demander une 2e verification
    compteUsager.webauthn.forEach(item=>{
      methodesDisponibles['webauthn.' + item.credId] = true
    })
  }
  if(compteUsager['est_proprietaire']) {
    // Pour le compte proprietaire, on permet d'utiliser la cle de millegrille
    methodesDisponibles.cleMillegrille = true
  }

  return methodesDisponibles
}

function auditMethodesUtilisees(session, params, opts) {
  opts = opts || {}
  const socket = opts.socket

  // Verifier methode d'authentification - refuser si meme que la methode primaire
  const methodePrimaire = session[CONST_AUTH_PRIMAIRE],
        methodeSecondaire = session[CONST_AUTH_SECONDAIRE],
        challengeSession = socket[CONST_CERTIFICAT_AUTH_CHALLENGE] || session[CONST_CERTIFICAT_AUTH_CHALLENGE]

  const methodesUtilisees = {}

  // Indiquer les methodes primaires et secondaires utilisees, considerer deja verifiees
  if(methodePrimaire) {
    methodesUtilisees[methodePrimaire] = {verifie: true}
    if(methodeSecondaire) {
      methodesUtilisees[methodeSecondaire] = {verifie: true}
    }
  }

  if(params.cleMillegrille) {
    methodesUtilisees.cleMillegrille = {
      valeur: params.cleMillegrille,
      challengeSession, verifie: false
    }
  }
  if(params.motdepasse) {
    methodesUtilisees.motdepasse = {
      valeur: params.motdepasse,
      verifie: false
    }
  }
  if(params.tokenTotp) {
    methodesUtilisees.totp = {
      valeur: params.tokenTotp,
      verifie: false
    }
  }
  if(params.date && params.data && params._certificat && params._signature) {
    methodesUtilisees.certificat = {
      valeur: params, challengeSession, certificat: params._certificat,
      verifie: false,
    }
  }
  if(params.webauthn) {
    methodesUtilisees['webauthn.' + params.webauthn.id64] = {
      valeur: params.webauthn,
      verifie: false,
    }
  }

  return methodesUtilisees
}

async function auditMethodes(req, params, opts) {
  debug("Audit methodes d'authentification, params : %O", params)

  /* Audit des methodes d'authentifications utilisees et disponibles pour l'usager */
  opts = opts || {}
  const socket = opts.socket || {},
        session = opts.session || req.session || socket.session,
        nomUsager = session.nomUsager

  debug("auditMethodes usager %s session : %O", nomUsager, session)

  var compteUsager = opts.compteUsager
  if(!compteUsager) {
    const comptesUsagers = socket.comptesUsagers || req.comptesUsagers
    compteUsager = await comptesUsagers.chargerCompte(nomUsager)
  }
  debug("Audit methodes authentification pour compteUsager : %O", compteUsager)

  const methodesUtilisees = auditMethodesUtilisees(session, params, {socket})
  const methodesDisponibles = auditMethodesDisponibles(compteUsager)

  // Retrirer la methode primaire des methodes disponibles
  var nombreVerifiees = 0
  Object.keys(methodesUtilisees).forEach(item=>{
    if(methodesUtilisees[item].verifie) {
      nombreVerifiees++
      delete methodesDisponibles[item]
    }
  })

  debug("Methode d'authentification disponibles : %O\nMethodes utilisees: %O", methodesDisponibles, methodesUtilisees)

  return {methodesDisponibles, methodesUtilisees, nombreVerifiees}
}

async function upgradeProtegeCertificat(socket, params) {
  console.debug("Params recus : %O", params)

  // const compteUsager = await comptesUsagersDao.chargerCompte(socket.nomUsager)

  const challengeSession = socket[CONST_CERTIFICAT_AUTH_CHALLENGE],
        idmg = socket.amqpdao.pki.idmg

  const resultat = await verifierSignatureCertificat(
    idmg, socket.nomUsager, params._certificat, challengeSession, params)

  console.debug("upgradeProtegeCertificat: Resultat = %O", resultat)

  return resultat.valide
}

async function upgradeProteger(socket, params) {
  params = params || {}

  // debug("upgradeProteger, params : %O", params)
  const comptesUsagersDao = socket.comptesUsagers
  const compteUsager = await comptesUsagersDao.chargerCompte(socket.nomUsager)
  const certMillegrilleForge = socket.amqpdao.pki.caForge,
        idmg = socket.amqpdao.pki.idmgActifs

  const {methodesDisponibles, methodesUtilisees, nombreVerifiees} = await auditMethodes(
    socket.handshake, params, {socket, compteUsager})
  debug("Methode d'authentification disponibles : %O\nMethodes utilisees: %O",
    methodesDisponibles, methodesUtilisees)

  // La methode a base de certificat ne compte pas comme 2e methode disponible :
  // le certificat n'a pas necessairement ete distribue ou il peut etre expire
  const methodesDiponiblesSansCert = Object.keys(methodesDisponibles).filter(item=>item!=='certificat')

  const methodesVerifiees = [], methodesReverifiees = []
  var authentificationValide = false

  if( methodesUtilisees.cleMillegrille && methodesUtilisees.cleMillegrille.verifie ) {
    // Authentification avec cle de millegrille - donne acces avec 1 seul facteur
    authentificationValide = true
  } else {
    // Verifier si on peut valider toutes les methodes utilisees
    for(let methode in methodesUtilisees) {
      const params = methodesUtilisees[methode]
      var resultat = null
      if( ! params.verifie ) {
        try {
          if(methode.startsWith('webauthn.')) {
            resultat = false
            try {
              const {counter} = await verifierChallenge(socket[CONST_WEBAUTHN_CHALLENGE].challenge, compteUsager, params.valeur)
              resultat = true
            } catch(err) {
              debug("upgradeProteger : Erreur validation webauthn %s: %O", methode, err)
              resultat = false
            }
          } else {
            switch(methode) {
              case 'cleMillegrille':
                debug("Params cle millegrille : %O", params)
                resultat = await verifierSignatureMillegrille(certMillegrilleForge, params.challengeSession, params.valeur)
                break
              case 'totp':
                resultat = await verifierTotp(comptesUsagersDao, compteUsager, params.valeur)
                break
              case 'motdepasse':
                resultat = await verifierMotdepasse(comptesUsagersDao, compteUsager, params.valeur)
                break
              case 'certificat':
                resultat = await verifierSignatureCertificat(
                  idmg, socket.nomUsager, params.certificat, params.challengeSession, params.valeur)
                break
            }
          }

          // Si la verification est invalide, une exception est lancee
          debug("Resultat verification : %O", resultat)
          if( resultat ) {
            params.verifie = true
            params.reverifiee = true
          }

        } catch(err) {
          debug("Methode authentification refusee : %s - %O", methode, err)
        }

      }
    }

    // Verifier si on a au moins deux methodes verifiees
    for(let methode in methodesUtilisees) {
      const params = methodesUtilisees[methode]
      if(params.verifie) {
        methodesVerifiees.push(methode)
      }
      if(params.reverifiee) {
        methodesReverifiees.push(methode)
      }
    }

  }

  debug("Methode verifiees : %O, reverifiees : %O", methodesVerifiees, methodesReverifiees)

  // Pour upgrade protege, permettre si on a 2 methodes valides, ou 1 seule et 0 disponibles
  if(methodesVerifiees.length >= 2 && methodesReverifiees.length >= 1) {
    debug(`Authentification ok, ${methodesVerifiees.length} methodes valides, reverifiees par ${''+methodesReverifiees}`)
    authentificationValide = true
  }
  // else if(methodesReverifiees.length === 1 && methodesDiponiblesSansCert.length === 0) {
  //   debug(`Authentification ok, 1 seule methode valide mais 0 disponibles`)
  //   authentificationValide = true
  // }

  debug("Authentification valide : %s", authentificationValide)

  if(authentificationValide === true) {
    const promiseUpgrade = new Promise(resolve=>{
      socket.upgradeProtege(ok=>{
        socket.emit('modeProtege', {'etat': ok})

        const session = socket.handshake.session
        // Conserver dans la session qu'on est alle en mode protege
        // Permet de revalider le mode protege avec le certificat de navigateur
        if(!session.authentificationSecondaire) {
          session.authentificationSecondaire = methodesReverifiees[0]
        }
        session.save()

        return resolve(ok)
      })
    })

    // Emettre le certificat de navigateur pour s'assurer qu'il existe sur le noeud
    var fullchain = null
    if(params.certificatNavigateur) {
      fullchain = splitPEMCerts(params.certificatNavigateur.fullchain)
    }
    if(fullchain) {
      debug("Authentification valide, info certificat : %O", fullchain)
      await comptesUsagers.emettreCertificatNavigateur(fullchain)
    }

    return await promiseUpgrade

  } else {
    return false
  }

  // var sessionActive = false
  // if(session.sessionValidee2Facteurs || session[CONST_AUTH_PRIMAIRE] !== 'certificat') {
  //    sessionActive = await demandeChallengeCertificat(socket)
  // }
  //
  // if(sessionActive) {
  //   // Termine
  //   return sessionActive
  // }
  //
  // if(compteUsager.u2f) {
  //   const challengeAuthU2f = generateLoginChallenge(compteUsager.u2f)
  //
  //   // TODO - Verifier challenge
  //   socket.emit('challengeAuthU2F', challengeAuthU2f, (reponse) => {
  //     debug("Reponse challenge : %s", reponse)
  //     socket.upgradeProtege(ok=>{
  //       console.debug("Upgrade protege ok : %s", ok)
  //       socket.emit('modeProtege', {'etat': true})
  //
  //       // Conserver dans la session qu'on est alle en mode protege
  //       // Permet de revalider le mode protege avec le certificat de navigateur
  //       session.sessionValidee2Facteurs = true
  //       session.save()
  //     })
  //   })
  // } else {
  //   // Aucun 2FA, on fait juste upgrader a protege
  //   socket.upgradeProtege(ok=>{
  //     console.debug("Upgrade protege ok : %s", ok)
  //     socket.emit('modeProtege', {'etat': true})
  //
  //     // Conserver dans la session qu'on est alle en mode protege
  //     // Permet de revalider le mode protege avec le certificat de navigateur
  //     session.sessionValidee2Facteurs = true
  //     session.save()
  //   })
  // }

}

async function verifierMotdepasse(comptesUsagersDao, compteUsager, motdepasse) {
  const nomUsager = compteUsager.nomUsager
  debug("Requete secret mot de passe pour %s", compteUsager)

  const motdepasseChiffre = compteUsager.motdepasse
  await comptesUsagersDao.verifierMotdepasseUsager(nomUsager, motdepasseChiffre, motdepasse)

  return true
}


async function verifierSignatureCertificat(idmg, nomUsager, chainePem, challengeSession, challengeBody) {
  debug("verifierSignatureCertificat : idmg=%s", idmg)
  const { cert: certificat, idmg: idmgChaine } = await validerChaineCertificats(chainePem)

  const commonName = certificat.subject.getField('CN').value,
        organizationalUnit = certificat.subject.getField('OU').value

  if(!idmg || idmg !== idmgChaine) {
    console.error("Le certificat ne correspond pas a la millegrille : idmg %s !== %s", idmg, idmgChaine)
  } else if(nomUsager !== commonName) {
    console.error("Le certificat ne correspond pas a l'usager %s, CN: %s", nomUsager, commonName)
  } else if(organizationalUnit !== 'Navigateur') {
    console.error("Certificat fin n'est pas un certificat de Navigateur. OU=" + organizationalUnit)
  } else if( challengeBody.date !== challengeSession.date ) {
    console.error(`Challenge certificat mismatch date : session ${challengeSession.date} et body ${challengeBody.date}`)
  } else if( challengeBody.data !== challengeSession.data ) {
    console.error(`Challenge certificat mismatch data session ${challengeSession.data} et body ${challengeBody.data}`)
  } else {

    debug("Verification authentification par certificat pour idmg %s, signature :\n%s", idmg, challengeBody['_signature'])

    // Verifier les certificats et la signature du message
    // Permet de confirmer que le client est bien en possession d'une cle valide pour l'IDMG
    debug("authentifierCertificat, cert :\n%O\nchallengeJson\n%O", certificat, challengeBody)
    const valide = await verifierSignatureMessage(challengeBody, certificat)
    debug("Validation certificat, resultat : %O", valide)

    if(valide) {
      return { valide, certificat, idmg }
    }

  }

  throw new Error("Signature avec certificat invalide")
}

async function verifierSignatureMillegrille(certificatMillegrille, challengeSession, challengeBody) {
  // Validation de la signature de la cle de MilleGrille

  if( challengeBody.date !== challengeSession.date ) {
    console.error("Challenge certificat mismatch date")
  } else if( challengeBody.data !== challengeSession.data ) {
    console.error("Challenge certificat mismatch data")
  } else {

    // Verifier les certificats et la signature du message
    // Permet de confirmer que le client est bien en possession d'une cle valide pour l'IDMG
    debug("Verification authentification par certificat de millegrille, cert :\n%O\nchallenge\n%O", certificatMillegrille, challengeBody)
    const valide = await verifierSignatureMessage(challengeBody, certificatMillegrille)
    debug("Resultat verifier signature : %O", valide)

    if( valide ) {
      return { valide, certificatMillegrille }
    }

  }

  throw new Error("Signature avec cle de Millegrille invalide")
}

async function verifierTotp(comptesUsagersDao, compteUsager, tokenTotp) {
  debug("Requete secret TOTP pour %s", compteUsager.nomUsager)
  const infoUsagerTotp = compteUsager.totp
  const secretTotp = await comptesUsagersDao.requeteCleTotp(infoUsagerTotp)
  // debug("Recu secret TOTP : %O", secretTotp)
  const cleTotp = secretTotp.totp

  const valide = authenticator.verifyToken(cleTotp, tokenTotp)
  debug("Verifier totp : %O", valide)
  if( valide && valide.delta === 0 ) {
    return true
  }

  throw new Error("Code TOTP invalide")
}

module.exports = {
  verifierUsager, auditMethodes, auditMethodesDisponibles, genererChallengeWebAuthn,
  upgradeProteger, upgradeProtegeCertificat,
  verifierMotdepasse, verifierSignatureCertificat, verifierSignatureMillegrille, verifierTotp,
  genererChallengeCertificat,
}
