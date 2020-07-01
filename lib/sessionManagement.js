const debug = require('debug')('millegrilles:coupdoeil:sessionManagement');
const {
    generateRegistrationChallenge,
    parseRegisterRequest,
    generateLoginChallenge,
    parseLoginRequest,
    verifyAuthenticatorAssertion,
} = require('@webauthn/server');
const crypto = require('crypto');

class SessionManagement {

  constructor(fctRabbitMQParIdmg) {
    this.fctRabbitMQParIdmg = fctRabbitMQParIdmg;
    this.timer;
    this.session_timeout = process.env.COUPDOEIL_SESSION_TIMEOUT || (60 * 1000);
    this.session_timeout = Number(this.session_timeout);
    this.transferTokens = {};
    this.challenges = {};
    this.pinTemporaireDevice = {};  // PIN utilise pour ajouter un device

    // Certificat du maitre des cles. Permet de transmettre des fichiers
    // de maniere securisee.
    this.certMaitreDesCles = null;
  }

  start() {
    // Cleanup des sessions expirees aux 5 minutes
  }

  clean() {
    let expiredTokens = [], expiredChallenges = [];
    let tempsCourant = (new Date()).getTime();

    for(var tokenKey in this.transferTokens) {
      let token = this.transferTokens[tokenKey];
      if(token.expiration < tempsCourant) {
        expiredTokens.push(tokenkey)
      }
    };
    tempsCourant.forEach(tokenKey=>{
      debug("Expiration token transfert " + tokenKey);
      delete this.transferTokens[tokenKey];
    });

    for(var challengeIdmg in this.challenges) {
      let token = this.challenges[challengeIdmg];
      if(token.expiration < tempsCourant) {
        expiredTokens.push(challengeIdmg)
      }
    };
    tempsCourant.forEach(challengeIdmg=>{
      delete this.challenges[challengeIdmg];
    });

  }

  createTokenTransfert(idmg) {
    var token = crypto.randomBytes(20).toString('hex');
    this.transferTokens[token] = {
      expiration: (new Date()).getTime() + 60000,
      idmg,
    };
    return token;
  }

  consommerToken(tokenKey) {
    // Consomme un token de transfert de fichier
    // Retourne true si le token est valide
    var token = this.transferTokens[tokenKey];
    if(token) {
      delete this.transferTokens[tokenKey]; // Delete si token utilise ou expire
      if(token.expiration>=(new Date()).getTime())  {
        debug("Token consomme " + tokenKey);
        return token;
      }
    }
    return false;
  }

  conserverChallenge(idmg, challenge) {
    this.challenges[idmg] = {
      expiration: (new Date()).getTime() + 60000,
      challenge,
    };
  }

  consommerChallenge(idmg) {
    const challengeEnveloppe = this.challenges[idmg];
    if(challengeEnveloppe) {
      delete this.challenges[idmg];
      return challengeEnveloppe.challenge;
    }
    return false;
  }

  createPinTemporaireDevice(idmg) {
    var pin = ''+crypto.randomBytes(4).readUInt32BE();
    pin = pin.substring(0, 6);
    this.pinTemporaireDevice[idmg] = {
      'pin': pin,
      'expiration': (new Date()).getTime() + 120000
    };
    return pin;
  }

  consommerPinTemporaireDevice(idmg, pin) {
    var infoPin = this.pinTemporaireDevice[idmg];
    delete this.pinTemporaireDevice[idmg]; // On enleve le PIN a la premiere tentative

    if(infoPin && pin === infoPin.pin && infoPin.expiration>=(new Date()).getTime())  {
      // console.info("PIN Temporaire Device correct");
      return true;
    }
    return false;
  }

  // Authentification de l'usager avec la MilleGrille fournie en parametre
  // Retourne la connexion a RabbitMQ si l'authentification reussi.
  // Lance une erreur en cas d'echec
  promotionSecurite(socket, params) {
    debug("Authentifier");
    // console.debug(params);

    return new Promise((resolve, reject)=>{
      // Lier a l'instance de RabbitMQ correspondant a l'identificateur de MilleGrille
      const idMillegrille = params.idMillegrille;
      const idmg = idMillegrille;  // TODO: Faire lookup
      const rabbitMQ = this.fctRabbitMQParIdmg(idmg);

      if(!rabbitMQ) {
        // La MilleGrille est inconnue
        reject(new Error("L'identificateur MilleGrille '" + idMillegrille + "' n'est pas connu"));

      // } else if(params.methode === 'effectuerEmpreinte') {
      //   debug("Effectuer l'empreinte de la MilleGrille");
      //   this.effectuerEmpreinte(rabbitMQ, socket, params)
      //   .then(()=>resolve(rabbitMQ)).catch(err=>reject(err));
      // } else if(params.methode === 'ajouterTokenUSB') {
      //   debug("Ajouter un token a la MilleGrille avec un PIN");
      //   this.ajouterTokenUSB(rabbitMQ, socket, params)
      //   .then(()=>resolve(rabbitMQ)).catch(err=>reject(err));
      // } else if(params.methode === 'genererCertificat') {
      //   debug("Generer un certificat de navigateur pour la MilleGrille avec un PIN");
      //   this.genererCertificat(rabbitMQ, socket, params)
      //   .then(()=>resolve(rabbitMQ))
      //   .catch(err=>{
      //     console.warn("Erreur challenge certificat, essayer USB");
      //     this.creerChallengeUSB(rabbitMQ, socket).then(()=>resolve(rabbitMQ)).catch(err=>reject(err));
      //   })
      // } else if(params.methode === 'certificatLocal') {
      //   debug("Authentification par certificat");
      //   let fingerprint = params.fingerprint;
      //   let certificat = params.certificat;
      //   this.creerChallengeCertificat(rabbitMQ, socket, fingerprint, certificat)
      //     .then(()=>resolve(rabbitMQ))
      //     .catch(err=>{
      //       console.warn("Erreur challenge certificat, essayer USB");
      //       this.creerChallengeUSB(rabbitMQ, socket).then(()=>resolve(rabbitMQ)).catch(err=>reject(err));
      //     });
      } else if (params.methode === 'tokenUSB') {
        debug("Authentification par securityKey USB");
        this.creerChallengeUSB(rabbitMQ, socket).then(()=>resolve(rabbitMQ)).catch(err=>reject(err));
      } else {
        // Erreur d'Authentification
        socket.emit('erreur.login', {'erreur': 'methode inconnue', 'methode': params.methode});
        socket.disconnect();
        return reject(new Error("Erreur d'authentification, methode inconnue: " + params.methode));
      }
    });
  }

  async creerChallengeUSB(rabbitMQ, socket) {
    // Authentifier le socket

    var docCles = null;
    const domaineAction = 'MaitreDesComptes.infoProprietaire'
    const requete = {}
    debug("Requete info proprietaire")
    const compteProprietaire = await rabbitMQ.transmettreRequete(domaineAction, requete, {decoder: true})
    debug("Reponse compte proprietaire")
    debug(compteProprietaire)

    if(!compteProprietaire.cles) {
        socket.emit('erreur.login', {'erreur': 'cles_absentes'});
        socket.disconnect();
        return;
    }
    const challenge_genere = await generateLoginChallenge(compteProprietaire.cles);
    debug("Challenge login")

    return await new Promise((resolve, reject) => {
      socket.emit('challengeU2f', challenge_genere, reply => {
        debug("challengeU2f appele")
        // console.log(reply);

        const { challenge, keyId } = parseLoginRequest(reply)
        if (!challenge) {
          debug("Challenge pas recu")
          return reject('Challenge pas initialise')
        }

        if (challenge_genere.challenge !== challenge) {
          return reject('Challenge mismatch')
        }

        // Trouve la bonne cle a verifier dans la collection de toutes les cles
        var cle_match
        let cle_id_utilisee = reply.rawId

        let cles = compteProprietaire.cles
        for(var i_cle in cles) {
          let cle = cles[i_cle]
          let credID = cle.credID
          credID = credID.substring(0, cle_id_utilisee.length);

          if(credID === cle_id_utilisee) {
            cle_match = cle;
            break;
          }
        }

        if(!cle_match) {
          return reject("Cle inconnue: " + cle_id_utilisee);
        }

        const loggedIn = verifyAuthenticatorAssertion(reply, cle_match);

        socket.emit('confirmationModeProtege', {actif: loggedIn});
        debug("Mode protege actif : %s", loggedIn)
        if(loggedIn) {
          resolve(loggedIn);
        } else {
          reject('Invalid authenticator assertion');
        }
      })
    })
    .catch( err => {
      socket.emit('erreur.login', {'erreur': ''+err});
    });
  }

  recevoirReponseChallengeCertificat(socket, challenge, reponse) {
    debug("Reponse challenge certificat");
    // console.debug(reponse);
    const bufferReponse = Buffer.from(reponse.reponseChallenge, 'base64');
    // console.debug(bufferReponse.toString('utf-8'));
    // console.debug("Challenge original")
    // console.debug(challenge);
    // console.debug(challenge.toString('hex'));

    const challengeOriginalHex = challenge.toString('hex');
    const reponseHex = bufferReponse.toString('utf-8');

    if(challengeOriginalHex === reponseHex) {
      // Ok
      // console.debug("Reponse challenge ok");
      return true;
    } else {
      console.warn("Challenge et reponse differents");
      return false;
    }
  }

  creerChallengeCertificat(rabbitMQ, socket, fingerprint, pemCertificat) {
    debug("Requete verification " + fingerprint);
    const pki = rabbitMQ.pki;

    let requete = {'fingerprint': fingerprint};
    return rabbitMQ.transmettreRequete(
      'Pki.confirmerCertificat', requete, {decoder: true})
    .then( contenuResponseCertVerif => {
      // debug(contenuResponseCertVerif);

      if(contenuResponseCertVerif.valide && contenuResponseCertVerif.roles) {
        // Certificat est valide, on verifie que c'est bien un certificat de navigateur
        const roles = contenuResponseCertVerif.roles;
        let estRoleNavigateur = false;
        for(let idx in roles) {
          let role = roles[idx];
          estRoleNavigateur = estRoleNavigateur || (role === 'coupdoeil.navigateur');
        }
        // console.log(estRoleNavigateur);

        if(estRoleNavigateur === true) {
          // C'est bien un certificat de navigateur. On genere un challenge
          // avec la cle publique.
          const certificat = pki.chargerCertificatPEM(pemCertificat);
          // console.log(certificat);

          return new Promise((resolve, reject) => {
            pki.genererKeyAndIV((err, randVal)=>{
              if(err) {
                return reject('Erreur generation random secret')
              }

              // Crypter un challenge pour le navigateur
              const challenge = randVal.key;
              let challengeCrypte = pki.crypterContenuAsymetric(certificat.publicKey, challenge);
              socket.emit('challengeCertificat', {challengeCrypte}, reponse => {
                const loggedIn = this.recevoirReponseChallengeCertificat(socket, challenge, reponse);
                socket.emit('login', loggedIn);
                if(loggedIn) {
                  resolve();
                } else {
                  reject("Not logged in");
                }
              });
            });
          });

        } else {
          throw new Error('Role certificat doit inclure coupdoeil.navigateur');
        }

      } else {
        throw new Error('Certificat invalide');
      }
    })
    .catch(err=>{
      console.info("Erreur authentification par certificat");
      console.info(err);
      // socket.emit('erreur.login', {'erreur': ''+err});
      // socket.disconnect();
      throw new Error("Erreur authentification par certificat");
    });

  }

  genererCertificat(rabbitMQ, socket, opts) {
    if(!opts) opts = {};
    const {pin, clePublique, sujet} = opts;

    const pki = rabbitMQ.pki;
    const idmg = pki.idmg;

    // Verifier que le pin est correct
    let pinCorrect = this.consommerPinTemporaireDevice(idmg, pin);

    if(pinCorrect) {
      // console.log("generercertificat: sujet %s, clePublique %s", sujet, clePublique);

      // Creer la transaction pour creer le certificat de navigateur
      const transaction = {
        'sujet': sujet,
        'cle_publique': clePublique,
      };

      return rabbitMQ.transmettreTransactionFormattee(
        transaction, 'MaitreDesCles.genererCertificatNavigateur'
      )
      .then( msg => {
        // console.log("Recu certificat pour navigateur");
        let messageContent = decodeURIComponent(escape(msg.content));
        let certificatInfo = JSON.parse(messageContent);
        // console.log(messageContent);

        // Transmettre nouveau certificat, confirmer le login avec succes
        socket.emit('certificatGenere', certificatInfo);
        socket.emit('login', true);
      })
      .catch( err => {
        console.error("Erreur message");
        console.error(err);
        socket.emit('erreur.login', "Erreur creation certificat")
        socket.emit('login', false);
      });

    } else {
      console.warn("generercertificat pin incorrect: " + pin);
      socket.emit("erreur", "PIN invalide");
      return Promise.resolve();
    }
  }

  // Ajoute un socket et attend l'evenement d'authentification
  addSocketConnection(socket) {

    // Authentification privee
    // Doit s'assurer que la connexion est pour le bon IDMG
    // et que c'est le proprietaire
    const estProprietaire = socket.request.headers['est-proprietaire']
    const idmgClient = socket.request.headers['idmg-compte'] || socket.request.headers['idmg']
    debug("Request headers socket WSS :\n%O", socket.request.headers)
    const rabbitMQ = this.fctRabbitMQParIdmg(idmgClient);

    return new Promise(async (resolve, reject)=>{
      const params = {
        idMillegrille: idmgClient
      }

      if(!estProprietaire) {
        debug("Usager n'est pas proprietaire")
        socket.emit('erreur.login', {'erreur': 'erreur pas proprietaire'});
        return reject(new Error("Usager n'est pas proprietaire de la millegrille sur socket " + socket.id))
      } else if(!rabbitMQ) {
        // La MilleGrille est inconnue
        debug("MilleGrille non initialisee")
        socket.emit('erreur.login', {'erreur': 'erreur init rabbitmq'});
        return reject(new Error("L'identificateur MilleGrille '" + idmgClient + "' n'est pas connu"))
      } else {
        debug("Connexion Socket.IO prete")
        socket.emit("pret", {login: true})
        return resolve(rabbitMQ)
      }
    })

  }

}

module.exports = {SessionManagement};
