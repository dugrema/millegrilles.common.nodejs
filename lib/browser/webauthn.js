const multibase = require('multibase')
const base64url = require('base64url')

async function repondreRegistrationChallenge(nomUsager, attestationChallenge, opts) {
  opts = opts || {}
  const DEBUG = opts.DEBUG

  if(DEBUG) console.debug('repondreRegistrationChallenge nomUsager: %s, attestation: %O', nomUsager, attestationChallenge)
  // Parse options, remplacer base64 par buffer
  const challenge = multibase.decode(attestationChallenge.challenge)
  const attestation = attestationChallenge.attestation
  const userId = multibase.decode(attestationChallenge.user.id)

  const publicKey = {
    ...attestationChallenge,
    challenge,
    user: {
      ...attestationChallenge.user,
      id: userId,
      name: nomUsager,
      displayName: nomUsager,
    }
  }

  console.debug("Registration options avec buffers : %O", publicKey)

  const newCredential = await navigator.credentials.create({publicKey})
  console.debug("New credential : %O", newCredential)

  // Transmettre reponse
  const credentialResponse = newCredential.response
  const jsonData = base64url.encode(credentialResponse.clientDataJSON)
  const attestationObject = base64url.encode(new Uint8Array(credentialResponse.attestationObject))
  const data = {
    id: newCredential.id,
    response: {
      attestationObject,
      clientDataJSON: jsonData,
    }
  }

  return data
}

module.exports = {
  repondreRegistrationChallenge
}
