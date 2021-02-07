const { calculerHachageBytes } = require('./forgecommon')

describe('hachage', ()=>{

  test('hachage contenu base64', async ()=>{
    const contenu = 'gYBUpFO+78449A8uR/gfr0ePW2eNRrC0zr+VmfQg3RVXoBvUmbIny0M3ohetnCl1svGTikD165C72f/IF+v6m7UoBFnHq61XnV+s2DLngt4='
    const resultat = await calculerHachageBytes(contenu)
    console.debug("Resultat hachage : %O", resultat)

    expect(resultat).toBe('sha512_b64:D4ze0WD02LX1wZVz7a/Iey2BxkUAdHBVajvhzCxu02wIq81qzCSbEUfdjEwoGlolY7q646x1M13XKEh3q0ASWA==')
  });

})
