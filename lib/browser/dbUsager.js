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

module.exports = {
  getCertificats, getClesPrivees, getCsr,
}
