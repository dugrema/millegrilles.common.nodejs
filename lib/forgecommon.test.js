const { validerChaineCertificats } = require('./forgecommon')
const { hacher } = require('./hachage')

const certs = require('../samples/certificat_pems')

describe('hachage', ()=>{

  test('hachage contenu base64', async ()=>{
    const contenu = 'gYBUpFO+78449A8uR/gfr0ePW2eNRrC0zr+VmfQg3RVXoBvUmbIny0M3ohetnCl1svGTikD165C72f/IF+v6m7UoBFnHq61XnV+s2DLngt4='
    const resultat = await hacher(contenu)
    console.debug("Resultat hachage : %O", resultat)

    expect(resultat).toBe('z8VvDvSDPGw56Rzf143ETiYuR2kn8AmVTdLCQNEGjRTBY7tw5nBmZFnjh4wtuA3pPX52VdeEz7CM7VaXFZ9guAKc9eF')
  });

})

describe('validation certificats', ()=>{

  test('valider chaine', async ()=>{
    const samplePem = certs.CERT_MAITRECLES
    const resultat = await validerChaineCertificats(samplePem)
    console.debug("Resultat validation : %O", resultat)
  })

})
