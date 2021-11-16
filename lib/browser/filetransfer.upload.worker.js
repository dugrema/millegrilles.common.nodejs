const path = require('path')
const axios = require('axios')
const {expose: comlinkExpose} = require('comlink')
const {v4: uuidv4} = require('uuid')
const { creerCipher, preparerCommandeMaitrecles } = require('../chiffrage')
const { getAcceptedFileReader, streamAsyncIterable } = require('../stream')
const { splitPEMCerts } = require('../formatteurMessage')

// Globals
// Structure uploads : {file: AcceptedFile, status=1, }
var _uploadsPending = [],
    _uploadEnCours = null,
    _uploadsCompletes = []

// Workers
var _chiffrage = null

// Callback etat : (nbFichiersPending, pctFichierEnCours, {encours: uuid, complete: uuid})
var _callbackEtatUpload = null,
    _certificat = null,
    _domaine = 'GrosFichiers',
    _pathServeur = '/fichiers'

const BATCH_SIZE = 1 * 1024 * 1024  // 1 MB
const STATUS_NOUVEAU = 1,
      STATUS_ENCOURS = 2,
      STATUS_SUCCES = 3,
      STATUS_ERREUR = 4,
      STATUS_NONCONFIRME = 5

function getEtatCourant() {
    const etat = {
        uploadsPending: _uploadsPending.map(filtrerEntreeFichier),
        uploadEnCours: filtrerEntreeFichier(_uploadEnCours),
        uploadsCompletes: _uploadsCompletes.map(filtrerEntreeFichier)
    }
    console.debug("Retourner etat : %O", etat)
    return etat
}

function filtrerEntreeFichier(entree) {
    if(!entree) return null
    const entreeCopy = {...entree}
    delete entreeCopy.file
    delete entreeCopy.cancelTokenSource
    return entreeCopy
}

async function ajouterFichiersUpload(acceptedFiles, opts) {
    opts = opts || {}
    const cuuid = opts.cuuid    // Collection de destination

    for(let i=0; i<acceptedFiles.length; i++) {
        const file = acceptedFiles[i]
        console.debug("Ajouter upload : %O", file)

        let dateFichier = null
        try {
          dateFichier = Math.floor(file.lastModified / 1000)
        } catch(err) {
          console.warn("Erreur chargement date fichier : %O", err)
        }
    
        const transaction = {
          nom: file.name,
          mimetype: file.type,
          taille: file.size,
          dateFichier,
        }
        if(cuuid) transaction['cuuid'] = cuuid
        
        _uploadsPending.push({
          file,
          size: file.size,
          status: STATUS_NOUVEAU,
          correlation: uuidv4(),
          transaction,
          position: 0,              // Position du byte de debut de la batch actuelle
          batchLoaded: 0,           // Bytes charges par la batch actuelle
          pctFichierEnCours: 0,     // Pct de progres total du fichier en cours
          cancelTokenSource: null,  // Cancel token pour axios
          complete: false,
        })
    }

    console.info("Uploads pending : %O", _uploadsPending)
    emettreEtat()
    traiterUploads()  // Demarrer traitement si pas deja en cours
}

async function traiterUploads() {
    if(_uploadEnCours) return  // Rien a faire

    let complete = ''
    for(_uploadEnCours = _uploadsPending.shift(); _uploadEnCours; _uploadEnCours = _uploadsPending.shift()) {
        console.debug("Traitement fichier %O", _uploadEnCours)
        _uploadEnCours.status = STATUS_ENCOURS
        emettreEtat({complete}).catch(err=>(console.warn("Erreur maj etat : %O", err)))
        try {
            // Uploader le fichier. Le status est modifie selon la reponse du POST (HTTP 201 ou 202)
            await uploadFichier()
        } catch(err) {
            console.error("Erreur PUT fichier : %O", err)
            _uploadEnCours.status = STATUS_ERREUR
        } finally {
            if(!_uploadEnCours.annuler) {
                _uploadsCompletes.push(_uploadEnCours)
            }
            complete = _uploadEnCours.correlation
            _uploadEnCours.complete = true

            _uploadEnCours = null
            emettreEtat({complete}).catch(err=>(console.warn("Erreur maj etat : %O", err)))
        }
    }

}

/** Effectue l'upload d'un fichier. */
async function uploadFichier() {

    const correlation = _uploadEnCours.correlation

    console.debug("Traiter upload en cours : %O", _uploadEnCours)
    const transformHandler = await preparerTransform()
    const transform = data => transformHandler.update(data)
    
    const reader = streamAsyncIterable(getAcceptedFileReader(_uploadEnCours.file), {batchSize: BATCH_SIZE, transform})

    try {
        var position = 0
        for await (let batchContent of reader) {
            const pathUpload = path.join(_pathServeur, ''+correlation, ''+position)
            position += batchContent.length
            const cancelTokenSource = axios.CancelToken.source()

            _uploadEnCours.cancelTokenSource = cancelTokenSource
            _uploadEnCours.batchTotal = batchContent.length
        
            const reponse = await axios({
                url: pathUpload,
                method: 'PUT',
                headers: { 'content-type': 'application/data' },
                data: batchContent,
                onUploadProgress,
                cancelToken: cancelTokenSource.token,
            })

            _uploadEnCours.position = position
            _uploadEnCours.batchLoaded = 0  // Position ajustee, on reset loaded immediatement (evite promenage % progres)
            _uploadEnCours.pctFichierEnCours = Math.floor(position/_uploadEnCours.size * 100)
            console.debug("Reponse upload %s position %d Pct: %d put block %O", correlation, position, _uploadEnCours.pctFichierEnCours, reponse)
            emettreEtat().catch(err=>(console.warn("Erreur maj etat : %O", err)))
        }

        // Preprarer commande maitre des cles
        const resultatChiffrage = await transformHandler.finish()
        const {hachage_bytes, iv, tag} = resultatChiffrage.meta
        console.debug("Resultat chiffrage : %O", resultatChiffrage)
        const identificateurs_document = { fuuid: hachage_bytes }
        const commandeMaitreDesCles = await preparerCommandeMaitrecles(
            [_certificat, [_certificat[2]]], resultatChiffrage.password, _domaine, hachage_bytes, iv, tag, identificateurs_document)
        console.debug("Commande maitre des cles : %O", commandeMaitreDesCles)
        _uploadEnCours.commandeMaitreDesCles = commandeMaitreDesCles

        _uploadEnCours.transaction.fuuid = hachage_bytes

        // Emettre la commande POST pour conserver le fichier
        const reponsePost = await terminerTraitementFichier(_uploadEnCours)
        if(reponsePost.status === 201) {
            console.debug("Fichier %s complete", correlation)
            _uploadEnCours.status = STATUS_SUCCES
        } else if(reponsePost.status === 202 ) {
            console.debug("Fichier %s valide mais sans confirmation (pending)", correlation)
            _uploadEnCours.status = STATUS_NONCONFIRME
        }

    } catch(err) {
        if(_uploadEnCours) {
            const correlation = _uploadEnCours.correlation
            console.error("Erreur traitement fichier, DELETE %s : %O", correlation, err)
            const pathConfirmation = path.join(_pathServeur, correlation)
            await axios({
                method: 'DELETE', 
                url: pathConfirmation, 
            })
        } else {
            console.warn("Erreur traitement upload fichier mais aucun fichier en cours : %O", err)
        }
    }
}

async function terminerTraitementFichier(uploadEnCours) {
    const partitionMaitreDesCles = uploadEnCours.commandeMaitreDesCles._partition
    delete uploadEnCours.commandeMaitreDesCles._partition
    const maitreDesClesSignees = await _chiffrage.formatterMessage(
        uploadEnCours.commandeMaitrecles, 'MaitreDesCles', {partition: partitionMaitreDesCles, action: 'sauvegarderCle'})
    uploadEnCours.commandeMaitreDesCles = maitreDesClesSignees
    
    const transactionSignee = await _chiffrage.formatterMessage(
        uploadEnCours.transaction, 'GrosFichiers', {action: 'nouvelleVersion'})
    uploadEnCours.transaction = transactionSignee

    console.debug("Etat fichier uploadEnCours : %O", uploadEnCours)

    const confirmationResultat = {
        commandeMaitrecles: maitreDesClesSignees, 
        transactionGrosFichiers: transactionSignee,
    }

    const pathConfirmation = path.join(_pathServeur, uploadEnCours.correlation)
    const reponse = await axios({
        method: 'POST', 
        url: pathConfirmation, 
        data: confirmationResultat,
    })

    return {
        status: reponse.status, 
        reponse: reponse.data, 
        commandeMaitrecles: maitreDesClesSignees, 
        transactionGrosFichiers: transactionSignee
    }
}

async function preparerTransform() {
    return creerCipher()
}

function onUploadProgress(progress) {
    const {loaded, total} = progress
    console.debug("Axios progress sur %s : %d/%d", _uploadEnCours.correlation, loaded, total)
    _uploadEnCours.batchLoaded = loaded
    _uploadEnCours.batchTotal = total
    if( !isNaN(loaded) && !isNaN(total) ) {
        const pctProgres = Math.floor(loaded / total * 100)
        _uploadEnCours.pctBatchProgres = pctProgres
    }
    emettreEtat().catch(err=>(console.warn("Erreur maj etat : %O", err)))
}

async function annulerUpload(correlation) {
    if(_uploadEnCours && (!correlation || _uploadEnCours.correlation === correlation)) {
        console.debug("Annuler l'upload en cours (%s)", correlation)
        _uploadEnCours.annuler = true
        if(_uploadEnCours.cancelTokenSource) {
            // Toggle annulation dans Axios
            _uploadEnCours.cancelTokenSource.cancel('Usager annule upload')
        }
    } else {
        console.debug("Retirer upload %s de la liste des pendings", correlation)
        const pending = _uploadsPending.filter(item=>item.correlation!==correlation)
        _uploadsPending = pending
    }
}
  
async function emettreEtat(flags) {
    flags = flags || {}
    if(_callbackEtatUpload) {
        console.debug("Emettre etat")

        // const flags = {}
        let pctFichierEnCours = 0
        if(_uploadEnCours) {
            flags.encours = _uploadEnCours.correlation
            const size = isNaN(_uploadEnCours.size)?0:_uploadEnCours.size
            const position = isNaN(_uploadEnCours.position)?0:_uploadEnCours.position
            const batchLoaded = isNaN(_uploadEnCours.batchLoaded)?0:_uploadEnCours.batchLoaded
            const courant = position + batchLoaded
            if(courant <= size) {
                pctFichierEnCours = Math.floor(courant/size*100)
            } else {
                // Erreur, on set pctFichierEnCours si disponible
                pctFichierEnCours = _uploadEnCours.pctFichierEnCours || 0
            }
        }

        _callbackEtatUpload(
            _uploadsPending.length, 
            pctFichierEnCours, 
            flags,
        )
    }
}

function setCallbackUpload(cb) {
    _callbackEtatUpload = cb
}

function setCertificat(certificat) {
    if( typeof(certificat) === 'string' ) {
        certificat = splitPEMCerts(certificat)
    }
    _certificat = certificat
}

function setDomaine(domaine) {
    _domaine = domaine
}

function setChiffrage(chiffrage) {
    console.debug("ChiffrageWorker : %O", chiffrage)
    _chiffrage = chiffrage
}

function clearCompletes(opts) {
    opts = opts || {}
    const {status, correlation} = opts
    console.debug("Clear completes : %O", opts)
    if(correlation) {
        const nouvelleListe = _uploadsCompletes.filter(item=>item.correlation!==correlation)
        _uploadsCompletes = nouvelleListe
    } else if(status) {
        const nouvelleListe = _uploadsCompletes.filter(item=>item.status!==status)
        _uploadsCompletes = nouvelleListe
    } else {
        _uploadsCompletes.clear()
    }

    emettreEtat()
}

function retryErreur(opts) {
    opts = opts || {}
    const correlation = opts.correlation
    const correlationsRetry = []
    
    let critere = null
    if(correlation) {
        console.debug("Retry correlation %s", correlation)
        critere = item => item.correlation === correlation
    } else {
        // Defaut, en erreur seulement (4)
        console.debug("Filtre erreur (status 4) de %O", _uploadsCompletes)
        critere = item => {
            console.debug("Comparer item %O", item)
            return item.status === 4
        }
    }

    _uploadsCompletes
        .filter(critere)
        .forEach(item=>{
            correlationsRetry.push(item.correlation)
            const updatedItem = {
                ...item, 
                complete: false, 
                status: 1, position: 0, 
                batchLoaded: 0, pctBatchProgres: 0,
            }
            console.debug("Resoumettre %O", updatedItem)
            _uploadsPending.push(updatedItem)
        })

    const completes = _uploadsCompletes.filter(item=>!correlationsRetry.includes(item.correlation))
    console.debug("Update liste completes: %O", completes)
    _uploadsCompletes = completes
    emettreEtat()
    traiterUploads()  // Demarrer traitement si pas deja en cours
}

comlinkExpose({
    getEtatCourant,
    ajouterFichiersUpload, annulerUpload, clearCompletes, retryErreur,
    setCallbackUpload, setCertificat, setDomaine, setChiffrage,
})