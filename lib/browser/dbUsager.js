const { openDB: _openDB } = require('idb')

const STORE_CLES_CONTENU = 'clesContenu',
      STORE_CLES_USAGER = 'cles'

function openDB(nomDB, opts) {
  opts = opts || {}

  //if(opts.upgrade) {
    return _openDB(nomDB, 3, {
      upgrade(db, oldVersion) {
        createObjectStores(db, oldVersion)
      },
    })
  // } else {
  //   console.debug("Ouverture DB sans upgrade usager : %s", nomDB)
  //   return _openDB(nomDB)
  // }
}

function createObjectStores(db, oldVersion) {
  console.debug("dbUsagers upgrade, DB object (version %s): %O", oldVersion, db)
  switch(oldVersion) {
    case 0:
    case 1:
      db.createObjectStore(STORE_CLES_USAGER)
    case 2:
      db.createObjectStore(STORE_CLES_CONTENU)
    case 3: // Plus recent, rien a faire
      break
    default:
      console.warn("createObjectStores Default..., version %O", oldVersion)
      db.createObjectStore(STORE_CLES_USAGER)
      db.createObjectStore(STORE_CLES_CONTENU)
  }
}

async function getCleContenu(nomUsager, hachage_bytes) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // console.debug("getCleContenu : usager:%s hachage_bytes:%s", nomUsager, hachage_bytes)

  // const tx = await db.transaction(TABLE_CLES_SECRETES, 'readonly')
  var cleContenu = null
  try {
    const store = db.transaction(STORE_CLES_CONTENU, 'readonly').objectStore(STORE_CLES_CONTENU)
    cleContenu = await store.get(hachage_bytes)
  } catch(err) {
    console.warn("Erreur getCleContenu : %O", err)
    return
  }

  // console.debug("getCleContenu : usager:%s hachage_bytes:%s = %O", nomUsager, hachage_bytes, cleContenu)

  return cleContenu
}

async function saveCleContenu(nomUsager, hachage_bytes, cleContenu) {
  const nomDB = 'millegrilles.' + nomUsager

  // console.debug("Save cle usager %s, fuuid %s", nomUsager, hachage_bytes)

  const db = await openDB(nomDB, 2, {
    upgrade(db) {createObjectStores(db)},
    blocked() {console.debug("dbUsager.saveCleContenu, upgrade DB blocked")},
    blocking() {console.debug("dbUsager.saveCleContenu blocking")},
    terminated() {console.debug("dbUsager.saveCleContenu terminated")},
  })

  const storeUpdate = db.transaction(STORE_CLES_CONTENU, 'readwrite').objectStore(STORE_CLES_CONTENU);
  return storeUpdate.put(cleContenu, hachage_bytes)
}

async function clearClesContenu(nomUsager) {
  const nomDB = 'millegrilles.' + nomUsager

  const db = await openDB(nomDB)
  // console.debug("Reset des cles de contenu sauvegardees localement", nomUsager)

  await db.clear(STORE_CLES_CONTENU)
}

async function getCertificats(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // console.debug("Database %O", db)
  const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
  const store = tx.objectStore(STORE_CLES_USAGER)
  const certificat = (await store.get('certificat'))
  const fullchain = (await store.get('fullchain'))
  await tx.done

  return {certificat, fullchain}
}

async function getClesPrivees(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // console.debug("Database %O", db)
  const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
  const store = tx.objectStore(STORE_CLES_USAGER)
  const dechiffrer = (await store.get('dechiffrer'))
  const signer = (await store.get('signer'))
  await tx.done

  return {dechiffrer, signer}
}

async function getCsr(nomUsager) {

  const nomDB = 'millegrilles.' + nomUsager
  const db = await openDB(nomDB)

  // console.debug("Database %O", db)
  const tx = await db.transaction(STORE_CLES_USAGER, 'readonly')
  const store = tx.objectStore(STORE_CLES_USAGER)
  const csr = (await store.get('csr'))
  await tx.done

  return {csr}
}

async function resetCertificatPem(nomUsager, opts) {
  if(!opts) opts = {}

  const nomDB = 'millegrilles.' + nomUsager

  const db = await openDB(nomDB)
  console.debug("Reset du cerfificat de navigateur usager (%s)", nomUsager)

  const txUpdate = db.transaction(STORE_CLES_USAGER, 'readwrite');
  const storeUpdate = txUpdate.objectStore(STORE_CLES_USAGER);
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
  openDB,
  getCertificats, getClesPrivees, getCsr, resetCertificatPem,
  getCleContenu, saveCleContenu, clearClesContenu,
  createObjectStores,
}
