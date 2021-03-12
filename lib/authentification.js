/*
Module d'authentification web
*/
const debug = require('debug')('millegrilles:common:authentification')
const {randomBytes} = require('crypto')
const {genererChallenge} = require('./webauthn')

const CONST_CHALLENGE_WEBAUTHN = 'challengeWebauthn',
      CONST_CHALLENGE_CERTIFICAT = 'challengeCertificat',
      CONST_AUTH_PRIMAIRE = 'authentificationPrimaire'

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
    // Usager connu, session ouverte
    debug("Usager %s connu, transmission challenge login", nomUsager)

    const reponse = {}

    if(compteUsager.certificat) {
      reponse.certificat = compteUsager.certificat
    }

    // Generer challenge pour le certificat de navigateur ou de millegrille
    //if(req.body.certificatNavigateur) {
      reponse.challengeCertificat = {
        date: new Date().getTime(),
        data: Buffer.from(randomBytes(32)).toString('base64'),
      }
      req.session[CONST_CHALLENGE_CERTIFICAT] = reponse.challengeCertificat
    //}

    if(compteUsager.webauthn) {
      // Generer un challenge U2F
      debug("Information cle usager")
      debug(compteUsager.webauthn)
      const challengeWebauthn = await genererChallenge(compteUsager)

      // Conserver challenge pour verif
      req.session[CONST_CHALLENGE_WEBAUTHN] = challengeWebauthn.challenge

      reponse.challengeWebauthn = challengeWebauthn
    }

    if(compteUsager.motdepasse) {
      reponse.motdepasseDisponible = true
    }

    if(compteUsager.totp) {
      reponse.totpDisponible = true
    }

    if(req.session[CONST_AUTH_PRIMAIRE]) {
      reponse[CONST_AUTH_PRIMAIRE] = req.session[CONST_AUTH_PRIMAIRE]
    }

    res.send(reponse)
  } else {
    // Usager inconnu
    debug("Usager inconnu")
    res.sendStatus(401)
  }
}

function auditMethodesDisponibles(compteUsager, opts) {
  opts = opts || {}

  // Creer une liste de methodes disponibles et utilisees
  // Comparer pour savoir si on a une combinaison valide
  const methodesDisponibles = {}

  // Methodes disponibles
  if(compteUsager.tokenTotp) methodesDisponibles.tokenTotp = true
  if(compteUsager.motdepasse) methodesDisponibles.motdepasse = true
  if(compteUsager.webauthn) {
    compteUsager.webauthn.forEach(item=>{
      methodesDisponibles['webauthn.' + item.credId] = true
    })
  }

  return methodesDisponibles
}

function auditMethodesUtilisees(session, params, opts) {
  opts = opts || {}
  const socket = opts.socket

  // Verifier methode d'authentification - refuser si meme que la methode primaire
  const methodePrimaire = session[CONST_AUTH_PRIMAIRE],
        webauthnCredId = session.webauthnCredId,
        challengeSession = socket[CONST_CERTIFICAT_AUTH_CHALLENGE] || session[CONST_CERTIFICAT_AUTH_CHALLENGE]

  const methodesUtilisees = {}

  if(webauthnCredId && methodePrimaire === 'webauthn') {
    // webauthn supporte plusieurs credentials a la fois
    methodesUtilisees['webauthn.' + webauthnCredId] = {verifie: true}
  } else {
    methodesUtilisees[methodePrimaire] = {verifie: true}
  }

  if(params.challengeCleMillegrille) {
    methodesUtilisees.cleMillegrille = {valeur: params.challengeCleMillegrille, verifie: false}
  }
  if(params.motdepasse) {
    methodesUtilisees.motdepasse = {valeur: params.motdepasse, verifie: false}
  }
  if(params.tokenTotp) {
    methodesUtilisees.tokenTotp = {valeur: params.tokenTotp, verifie: false}
  }
  if(params.date && params.data && params._certificat && params._signature) {
    methodesUtilisees.certificat = {
      valeur: params, challengeSession, certificat: params._certificat,
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
        session = opts.session || req.session || socket.session

  var compteUsager = opts.compteUsager || {}
  if(!compteUsager) {
    const comptesUsagers = socket.comptesUsagers || req.comptesUsagers
    compteUsager = await comptesUsagers.chargerCompte(session.nomUsager)
  }
  debug("Audit methodes authentification pour compteUsager : %O", compteUsager)

  const methodesUtilisees = auditMethodesUtilisees(session, params, {socket})
  const methodesDisponibles = auditMethodesDisponibles(compteUsager)

  // Retrirer la methode primaire des methodes disponibles
  Object.keys(methodesUtilisees).forEach(item=>{
    if(methodesUtilisees[item].verifie) {
      delete methodesDisponibles[item]
    }
  })

  debug("Methode d'authentification disponibles : %O\nMethodes utilisees: %O", methodesDisponibles, methodesUtilisees)

  return {methodesDisponibles, methodesUtilisees}
}

module.exports = {verifierUsager, auditMethodes, auditMethodesDisponibles}
