const { openDB } = require('idb')

async function getCertificats(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB, 1, {
    upgrade(db) {
      db.createObjectStore('cles')
    },
  })

  // console.debug("Database %O", db)
  const tx = await db.transaction('cles', 'readonly')
  const store = tx.objectStore('cles')
  const certificat = (await store.get('certificat'))
  const fullchain = (await store.get('fullchain'))
  await tx.done

  return {certificat, fullchain}
}

async function getClesPrivees(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB, 1, {
    upgrade(db) {
      db.createObjectStore('cles')
    },
  })

  // console.debug("Database %O", db)
  const tx = await db.transaction('cles', 'readonly')
  const store = tx.objectStore('cles')
  const dechiffrer = (await store.get('dechiffrer'))
  const signer = (await store.get('signer'))
  await tx.done

  return {dechiffrer, signer}
}

async function getCsr(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB, 1, {
    upgrade(db) {
      db.createObjectStore('cles')
    },
  })

  // console.debug("Database %O", db)
  const tx = await db.transaction('cles', 'readonly')
  const store = tx.objectStore('cles')
  const csr = (await store.get('csr'))
  await tx.done

  return {csr}
}

async function resetCertificatPem(nomUsager, opts) {
  if(!opts) opts = {}

  const nomDB = 'millegrilles.' + nomUsager

  const db = await openDB(nomDB)
  console.debug("Reset du cerfificat de navigateur usager (%s)", nomUsager)

  const txUpdate = db.transaction('cles', 'readwrite');
  const storeUpdate = txUpdate.objectStore('cles');
  return Promise.all([
    storeUpdate.delete('certificat'),
    storeUpdate.delete('fullchain'),
    storeUpdate.delete('csr'),
    storeUpdate.delete('signer'),
    storeUpdate.delete('dechiffrer'),
    storeUpdate.delete('public'),
    txUpdate.done,
  ])

}


module.exports = {
  getCertificats, getClesPrivees, getCsr, resetCertificatPem,
}
