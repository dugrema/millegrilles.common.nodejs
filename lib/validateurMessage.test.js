const {pki} = require('node-forge')

const validateurMessage = require('./validateurMessage')

const MESSAGE_1 = {
    "allo": true,
    "en-tete": {
        "idmg": "DUMMY",
        "uuid_transaction": "86cdc7a0-7464-11eb-b661-8d9c3f81d76e",
        "estampille": 1613926067,
        "version": 6,
        "domaine": "Domaine.test",
        "hachage_contenu": "mEiAcD18IXkmUeneUYOVwRvGBKt+foKqzudR0qdN/QNT7YQ",
        "fingerprint_certificat": "zQme3bKbUD9WMbRZqv7qAoxybERFvAjymDixCiqhrfjwDHD"
    },
    "_signature": "mAZTPlNXHyUtIxqJFKNywomL4tuBFz5JyTZNdKdvD8yR2ogIrpk7ofI4xr8+FEH40FvRZ+fB++EEZ4dkgKR7i6FyrHvOn0T+RHxwLBkSUXGevwVjGRWQniA9F+vylWwujFgiDSzIh5GyqaGszVHIXsSSUfAbWIZSZ3KtH2j3dx7e5ImvFYIOPTcxke8JPYAnhyYj4LnhVq0E3O0ZmtIEYc3LOkzD+r7rAmiXnEeGiNTvd1FWamPacxDJ0AloTBLdnFadxIENh15o2u9YV2e+JJ02+CmNAy+NfGWnWQnhBGp03MZ0tzNKDIv56sYJUMobAwQHHXhIXfSn/PUla7ss7G8I",
    "_certificat": [
    "-----BEGIN CERTIFICATE-----\nMIIEEzCCAvugAwIBAgIUTKhREB7RyahKoBIHZMqAQ+amvPMwDQYJKoZIhvcNAQEL\nBQAwgZoxPzA9BgNVBAoMNnoyUkFDV0hBRlNxZ2hxOEVhVGc1SFNHS05QQnIzdUJm\ncGNwTG1CVEphOVNFSzlNbWJENmNBMjEWMBQGA1UECwwNSW50ZXJtZWRpYWlyZTE/\nMD0GA1UEAww2ejJSQUNXSEFGU3FnaHE4RWFUZzVIU0dLTlBCcjN1QmZwY3BMbUJU\nSmE5U0VLOU1tYkQ2Y0EyMB4XDTIxMDIyMTE2NDU0N1oXDTIxMDMyNDE2NDc0N1ow\naDE/MD0GA1UECgw2ejJSQUNXSEFGU3FnaHE4RWFUZzVIU0dLTlBCcjN1QmZwY3BM\nbUJUSmE5U0VLOU1tYkQ2Y0EyMREwDwYDVQQLDAhkb21haW5lczESMBAGA1UEAwwJ\ndW5pdF90ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA/m889tUZ\n9FQ4W6IU1zqi+W7mLHD5u94SbJn1dNovrFAqqiVc7T7Ektm8WcpmuF5i3js8D0ai\nQv5pqAhTrXCOGP6ufXoBO0FW8NVj+GPcvooZBl93s6L9H1S+R0BDGAaNDk/3BNzn\nz9+kAjKq8kmZ8jbV2DWVS6JByzkEoe8xK6jjTLifEL9WWkuZuTDOIeNe/lRfz58u\nhcmyktrzFbRKaFtIh8NbrPSqxLUPPD0XbIwnDC9e5u5JOhWXXnfiMV2hJGDSB9LH\nqCx93Pj51R1Q2JqdYpIjvruXph6vXeQ5uuauCgepdSjyOUancFmatPdi9tOeZpVE\nxl+H+owSSiZKQQIDAQABo4GBMH8wHQYDVR0OBBYEFHkzhaVv+2qM7xEkUYsAyMS8\n5yadMB8GA1UdIwQYMBaAFG+t/BHETxLNF6O617zZ7063GYjEMAwGA1UdEwEB/wQC\nMAAwCwYDVR0PBAQDAgTwMBAGBCoDBAAECDQuc2VjdXJlMBAGBCoDBAEECGRvbWFp\nbmVzMA0GCSqGSIb3DQEBCwUAA4IBAQCAc9ggkqZt1Nhj9z46uFWCge7e362zCIxv\ndT+ptRoqdw2DaYS1Ssca6ASkjjdqFNu3xSyf3kYD0SjUWnZ083o1GZL9n3c2L+Mw\ntoiHpiSbEhQG4FhLqPlZBHmQHAKf7dIODdyCqTm6aoUBbjyNM0+RRFw7siHjz8s1\nDa2Zbtj21V9/lPEqMQNOjS0wCzmW7bs7+tCY6LDaAfalGedOL+tqJCAR4k4yDbJ7\nBbkjRF1+MW2FvX0BKpJaOoNriRFr+U6VjpUqXbtIuuNAcu9mxEO9vnj28GqcA8jL\ntU03KSbdHtLsoejkhSs514mV1nvoVJ2ltMHVrPUsePhTIFgY3PMN\n-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\nMIIEszCCApugAwIBAgIUBB0GVlURk+vwX8BjIX6jAURrKRgwDQYJKoZIhvcNAQEL\nBQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y\nMTAyMjExNjQ1NDdaFw0yMTAzMjQxNjQ3NDdaMIGaMT8wPQYDVQQKDDZ6MlJBQ1dI\nQUZTcWdocThFYVRnNUhTR0tOUEJyM3VCZnBjcExtQlRKYTlTRUs5TW1iRDZjQTIx\nFjAUBgNVBAsMDUludGVybWVkaWFpcmUxPzA9BgNVBAMMNnoyUkFDV0hBRlNxZ2hx\nOEVhVGc1SFNHS05QQnIzdUJmcGNwTG1CVEphOVNFSzlNbWJENmNBMjCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxrIWXJhewPiVcRSyysq817N4/RxpFg\nrtLcdtDnJ/txbtJIdcV7X+y714HgVYHPvZO4mc1Rk53CVh9YS4uKL83Az1ksbYYG\n97G2lPJPjkLY/ycAxo0yZaweeVFCJPaQRrJ3qR3qS5nGiSHD/gLxRnSdoYnYw3Ps\n9VIG02WsB5bBDrhwXGe1ZVQ7Um03L6pa4xHQObKgDXVddrZ2kwkV38JpQv1a/1W5\nHAvnQwHvlD/w5j3I4arPJzCvJ7cqaPFl99FpnLT9O3S68MxOyiRvd0eQ8rQohnx1\n7+DkrGJ6nImyFwcZ+pFOr+Aipu5zDDaLqCcYhqE6Oipu4jqqxMgyD1ECAwEAAaNj\nMGEwHQYDVR0OBBYEFG+t/BHETxLNF6O617zZ7063GYjEMB8GA1UdIwQYMBaAFE44\nJLSB/bvYgljhsEwESKiQtYq3MBIGA1UdEwEB/wQIMAYBAf8CAQQwCwYDVR0PBAQD\nAgL8MA0GCSqGSIb3DQEBCwUAA4ICAQA5VE5pnaQz1YoffGc10i+FSw3aUWauy2y9\n4hKUZJFBrUpnvZUy0j98EdPbI2ti192/dAaeJ2QjPiliJ5hAKV6cAGthOQVFhw/i\n5bdixm0PbEdnf1KtHCQPgMlcolw2MVzBHoXU705brKAixiac+6sdFQEzE2KDLmvZ\nqEnrYGPQ692q7E+1IuVJNV75pftTq3ZhBqtpIFhv+Y5oyG487TrgX+v5uNzPwU2r\naalDhejjLeLGhT/QbwiW006B0ONi25P4fmd3aGA49RAVKEucF/p/piyVigpjhrzu\nALlcnK4TiLQ8ByT5WNumnddBu0Q4zdt/dj7IgPHjfJVT8TwydGl8QM5aigCdZwSK\nYtCKqfp4cW5K4q6ygDunr68qGqwlF/tLD+Pez9RP1LLfg/yHlkSvkVOACOue3Arp\nRWyK0X5ojyIIKpmsKY7zECWLKvSw/vV2cdAdAi4/ZSB7Fk+HYqwDP/fHsAjcoxe+\nM6iBTO2vxnSCtoYS7sNW4vIFgeBUtkQjcsjZh84EpUMEDFBaQunSiZxNvvWzeOnh\n2Q4/z3ZpZ4zl6tMHS0ThC2rvQ0kmgDf8kP7E+/3I6mQmTSUeaDsWGwrfcj0FZm0H\nPf8nbkPNVhpC9SX1sVxKCrKNVGWoMLLhoh1yxVoOZ6n9svna4YQSpY3Fxaunr7aY\nZWVJbvl0mQ==\n-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\nMIIFMjCCAxqgAwIBAgIUZt8j6LG+nsSb1wsrxjmWmSn5lzUwDQYJKoZIhvcNAQEN\nBQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y\nMTAxMTQxODU3NTZaFw0zMTAxMTcxODU5NTZaMCcxFDASBgNVBAoMC01pbGxlR3Jp\nbGxlMQ8wDQYDVQQDDAZSYWNpbmUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\nAoICAQDu4dTDbd9Wz3elIVisJdBedhmhtxdmgxefKEg5uu415TfICVI4c8ay7Qav\nn22S1C6LyVgB0aK1VD5NS+0fPp2sFmDQ7kP+s7QIjHkNCT6CL/n3SdLRN5gexyc1\ntDd52sDAmVuXqBReQ6xDaHWc94QTbMC3eqrAhtMUjG9XMcoyW0u9LT9d7w3AElYT\nzlkAcTSMmshqg893PQPzbOxjnSiLzsAUWuBrYYXx83jmMKaj6WPJ7tTFRZgZnfId\nuso7rl3UpnjoFBLN9AdhKWFPmt7jnVxxaN0JwG+7elxhR007lJD2RylLtHhcPSCx\nWiMZlFLTG+U+tFZgXRh5DeO1v5/vEj97JU6GX7tZG+0K0UdUa8MDvsToooFq33DV\nG5Al6odx+KLATGhBm/l1HIr9LVrj+5tVklXZpaB0P8SAlic8sEF+YpLjRQLueND3\nsi+TpKCg6S83fMJRdp0bTXNe3oeukB8DQxaH7OqksHzMvYZnLpqjSrTrg2kmtS3z\nwm6KOLXxHzE7r85m5o60SOO++C5gDxAAzwKFABZ0UhhzycMekEMTcqB+h23OQYJK\nFVtdhK95A0nMQGeQqthOyIeAAmEzmCZX2SrDhF3mK1N5PDaHdv6bGPJNHzm5wMQc\nnJcVTJCK9+jmFAVnEZfzphjOHcWtd95XqOYb6kkUAWxca6zGOwIDAQABo1YwVDAd\nBgNVHQ4EFgQUTjgktIH9u9iCWOGwTARIqJC1ircwEgYDVR0TAQH/BAgwBgEB/wIB\nBTAfBgNVHSMEGDAWgBROOCS0gf272IJY4bBMBEiokLWKtzANBgkqhkiG9w0BAQ0F\nAAOCAgEAd/8X18Yt8p6L+ox7Hm23BokcVY6AfZOJajDECuVPlVqUvqu6puP2u+uk\nyg1NPPmPTA981L9EQXGmW8fuwcvlJqiUueIszPqk1Zo2Zg6EvcSHJ93d3SPcDo+W\nzTxrfNFDhVxnlp6RdiaYuhJzAZKICA4EJFi7rogKMdcxrzDk7yNAguoU9pkRM3oP\nnKyCqe34madILHHYTir25wcaV3WsSrY+BmjSTgJkoAUWnuSWKa6fvbcocYmELSIu\nnNcpavckTMPEYwLBA7xxVUppSKdXN4vOCRJVAh6NOx+NW4XhN/rb+ltSFFO87oIG\n3+YihVbIith5Xj0GzUswyOX3gn2SJlXjk+B5UIiOh8cd3U4HarquArnn3cf4P5Ev\n3d6J8i6oq0RQzguu6ER6JcwWkWI9psDag0GTxYUG1oQ99hSsxYavdlonJAao/hS8\ni6vDK150gjFv4+mxanmuGxxgr3f5Kzu+NxwSsCVJGZ3ckyRK/SQlnGHe7K6YncTW\nuEeeBOTeRYnf25D+2lr/MpCtkz5i3DHc3eI9FfeAbmDUI6O5NxYz5pBytb4zQ8Sz\neIdNRGmLNchR/uWo9Wnenvz7DAmqteUWm9Lo+5EStaYesIyHeuirUsKDSJVyS+s6\nZE4ROy5y+dG0q3rgtYWkRh5Jseo1fwtVE2IQ/WhPpi9jdFX4DRw=\n-----END CERTIFICATE-----\n"
    ]
}

const MESSAGE_2 = {
  'texte': 'Du texte',
  'int': 1234,
  'float': 5678.12,
  'float zero': 1234,
  'date': 1613826000,
  'dict': { 'valeur': 'davantage de contenu' },
  'texte_accents': 'ÀÉËÊÈÇÏÎÔÛŨÙàéëèçïîôù',
  'texte_chars': '¤{}[]¬~`°|/\'"\n\\',
  'en-tete': {
    'domaine': 'Domaine.test',
    'idmg': 'QLA8z7SaLx4ZFTyRbUdPiejojm5hUfqxcPRcwsuiVR8T',
    'uuid_transaction': 'cbc7096d-b870-4df8-b54e-358469bddeff',
    'estampille': 1613933393,
    'fingerprint_certificat': 'zQmT8L1ctRhSV6QAVXWm7bGs9uR14K9whuUnAKanC4Pz84T',
    'hachage_contenu': 'mEiCTYQUmipCIDGauFwcwtEJW7hJUhrrpqGHUcNZHj3S+oA',
    'version': 1
  },
  '_certificat': [
    '-----BEGIN CERTIFICATE-----\nMIIEbDCCA1SgAwIBAgIUd8jlVh+5i4blQjkMSEbOAx42Xh4wDQYJKoZIhvcNAQEL\nBQAwfjEtMCsGA1UEAxMkYjBlN2UxNmItNTMyMC00OTc0LTgxZDAtYmZkMTIyMzVh\nN2E1MRYwFAYDVQQLEw1pbnRlcm1lZGlhaXJlMTUwMwYDVQQKEyxRTEE4ejdTYUx4\nNFpGVHlSYlVkUGllam9qbTVoVWZxeGNQUmN3c3VpVlI4VDAeFw0yMTAyMTUyMDAz\nNDNaFw0yMTAzMTcyMDA1NDNaMHgxNTAzBgNVBAoMLFFMQTh6N1NhTHg0WkZUeVJi\nVWRQaWVqb2ptNWhVZnF4Y1BSY3dzdWlWUjhUMRAwDgYDVQQLDAdtb25pdG9yMS0w\nKwYDVQQDDCRiMGU3ZTE2Yi01MzIwLTQ5NzQtODFkMC1iZmQxMjIzNWE3YTUwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDl/fpKc+Wu+LcatADxy3ViBX54\nn3EK1LEWZJWC6AQR8hGGkaxxtgiyoasMJiblrqnZommcjk399D60Ix2GeMNoCEfu\nTWpoxDz7VXFfTQFiUExDwPWqKAdQSeK0B9JUQMyh/0IKH9ARWqnUg9c6Q3DUpHCO\niIqEc3YN9yi+wFplTFnrzemBLYhsql+gNwq5YseqX/ZaV7iM+MoLkYdYERJPlGIA\naYiSD10BZ9K5XXzdXyz8UBwfzJC2haP5fCKjWalusz0d7FLAqVQtLSOf+EANJiQ5\nxlbo8HZyqKc9zOChukQDiO4mGNIm0O8aghl9ypAybyX3gJxKJj0UEJTkwEHtAgMB\nAAGjgecwgeQwHQYDVR0OBBYEFJfXeAZw7qYc+XASOU6CcUVbfsm6MB8GA1UdIwQY\nMBaAFB87VTm4RcNiLLIQTLZ7KIEEu6chMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQD\nAgTwMCIGBCoDBAAEGjQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlMA8GBCoDBAEE\nB21vbml0b3IwUgYDVR0RBEswSYIkYjBlN2UxNmItNTMyMC00OTc0LTgxZDAtYmZk\nMTIyMzVhN2E1gglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJ\nKoZIhvcNAQELBQADggEBAAlPk0Efd4kpagvwRTyX5X5W//xnMZ1w47ITc0sGeT4e\nuFJh5hBjzCoM56TCb1pQ7s7oM212HzEBvxS7HEcvejbihHFVxr7BFicEl640lFgC\n7Za9w+CcJ8a9XoiXxj0n1eIEtP2+M3C+3989bo7Pu7XU3cTRg2MKQ4siMbF8eC5p\nHGUcpspZKUewZYWd/jp2vQaUqe9PP/hLHLSQRySo8GVUIITyvbhDZMCaKcTSjbB3\nSJhmTaxLKFP0ZMwHnanxpYUVCTgnhL/rjnVcphCyauevJfnz/F9jkQfqSiAnekXR\nMp0ZzHARNeA6hsAjgnIliyUkhw8/A6mH/PDyl+RSl/w=\n-----END CERTIFICATE-----',
    '-----BEGIN CERTIFICATE-----\nMIIDfzCCAmegAwIBAgIKBDNxl1cTgCQkADANBgkqhkiG9w0BAQ0FADAnMQ8wDQYD\nVQQDEwZSYWNpbmUxFDASBgNVBAoTC01pbGxlR3JpbGxlMB4XDTIxMDIxNTIwMDUz\nMVoXDTI0MDIxODIwMDUzMVowfjEtMCsGA1UEAxMkYjBlN2UxNmItNTMyMC00OTc0\nLTgxZDAtYmZkMTIyMzVhN2E1MRYwFAYDVQQLEw1pbnRlcm1lZGlhaXJlMTUwMwYD\nVQQKEyxRTEE4ejdTYUx4NFpGVHlSYlVkUGllam9qbTVoVWZxeGNQUmN3c3VpVlI4\nVDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIFnRbD8jatuetbT0xZ\nG+FkzJWcTO/iiJmmy2An1rCxJYyII9UJwTT06iNmcBKN0j1RQQH9oys2S63EGWWn\nBgKQDmqVXt+PKzcD/HT5OUfzkiviSC6eH7GNpDcSMPOBmeHpOqPhuLqhDQkopDiO\nDzGBKr7o79M9+C6kCUptxKCs5EvJVOu0m3aCdVnlhFNnfVmwz1qE8df8HuFgIsK7\ndnSPTXx98EkxfwibNjlhmfx2uaEQBNxG/EPkdtkZqKOgluMvVV29z0+ursNmtkR2\nIWTkPdel8eLaFBmQxws35+RzBdv1IJAyuQLt8r84k5HODIY4gJEwtQSw/LmXWACg\nUs0CAwEAAaNWMFQwEgYDVR0TAQH/BAgwBgEB/wIBBDAdBgNVHQ4EFgQUHztVObhF\nw2IsshBMtnsogQS7pyEwHwYDVR0jBBgwFoAULmWyQdaWzDUSLJesMFG5FvsCF1cw\nDQYJKoZIhvcNAQENBQADggEBADGcUWDBJdgXiY4xImmP10PR1iVI5IhmORU8BrSg\n2xN8EST8aRQn3FaPRTxiCAhHyPGf+DAH5aFAcQZn7bB0hqKS1yuoYGK71EM2j63W\nl7+aGZ1W6+1Gm2vUk4D2M3pqubWMgnJgNAynC6oJO3o8o3b+TwMkFRb8x2HCBF+v\nSDMRXBfSxPxpgdibrTh/BW+d07aGjtQy1fggGAlRoHapqilaZ0f01r4r7fGaNEnD\nbguzR11dLma1TokMYnK3uki2yUdWrW1sKhzh35PN9VmWSJJC0qmy30+WPHUm36/Z\nU47D1s/j8pKzeq5C2pJiNcEwJP6WW16c0Ce/dWGlGh0KFjk=\n-----END CERTIFICATE-----',
    '-----BEGIN CERTIFICATE-----\nMIIDJzCCAg+gAwIBAgIJh4hTAQFkKTIAMA0GCSqGSIb3DQEBDQUAMCcxDzANBgNV\nBAMTBlJhY2luZTEUMBIGA1UEChMLTWlsbGVHcmlsbGUwHhcNMjAxMDE1MTczNjQx\nWhcNMjExMDE1MTczNjQxWjAnMQ8wDQYDVQQDEwZSYWNpbmUxFDASBgNVBAoTC01p\nbGxlR3JpbGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoEQE8xzF\n4BeTqnui0ri3F8wKGmF75xLKBUWklpc/FSnyIb6R/IfjoxT+tgI9Gr38lA9ITvdB\nykNAeS4HbKv4K7g+vIWJixGWXBspd0Fs7FKMwZgN/c1wpBZw4rPjujk8u385/Aiu\n6WkCK0+QIPl5bmKWLIzs/wpcWt+g7vlFYSM7qKdvlxJ6LToqcZKrKVemPfokIJ+X\nQNe6vWTSVKqTCETe9ltPxnftI2eELuHpSyigYwkEIjkQPRbShpm/GdO7MJJwfo0i\nXJqAZabEAgJnCt1o0FNySRa8o5VThpiUDlbaAS77v0E/cgM8Q8+vbwZN3mAjzbn9\nxBYdSC2KMT5MFQIDAQABo1YwVDASBgNVHRMBAf8ECDAGAQH/AgEFMB0GA1UdDgQW\nBBQuZbJB1pbMNRIsl6wwUbkW+wIXVzAfBgNVHSMEGDAWgBQuZbJB1pbMNRIsl6ww\nUbkW+wIXVzANBgkqhkiG9w0BAQ0FAAOCAQEAOML4p+SwPU+VeTikYrH4tPQsTXnC\nDt4VqI71MsTD4zOdKUN+voRaKQWO0RE3zcTfIcY784cDxvSrzpDWIkQ1OkAu9VvR\nMX1f9dlX3J7jEywnpHnEZ6uphew0PIApumXVsumGsztw+X8RAL8tX9a4V/xSzHwM\nGls59U8FYZbvfIeo+IYxjbiK2tY44qU76tETdhJkUqbYwZKLveRv8UIjmaFAoybA\nCbpFuvHsuGMpL1Eg+nqDyn7z4GjAsjxu5UrCTlzXkUXyvGUcZ87zWFJo7ftG4EyM\n1D5hhfH0whmeLRxOs/BkYThHe3q+uis8K9R6qbdvXXmuw/nVUQU7QmL0mA==\n-----END CERTIFICATE-----'
  ],
  '_signature': 'mAWgoDvq6LL2uqgDCAfRZYZrDjEFTyAFv37KAJBkvyiNNdly7yc+iPPy449Nfs3ujKfUSmer+UkCeNH+b+jTztenSEQXE49yaFdpG0UJeAfR9kt7jsAp1dUV/EfcVRTw9R8xAt/nu7GNBfGVYbOCkI18aMFxB3BDuK33XXDN4SU2cCv/ddJDHLQfZSsnjIaIMtmPURAZ/tt6fobyY821gVO+E+bfdeq4Af6pxqfqGeUeWQDwn5eK0ByVqwkitTY3z+t5i4Dp5aTjcpXZ5tRonJWYmFK/HHbP6q/9Ex3O1WtZYVdDkNyLzbxCh2uFSNe8vtNjGksXAOaJh53Gyrf15kZs'
}

describe('verificateurMessage', ()=>{

  test('verifier hachage message 1', async ()=>{
    await validateurMessage.verifierHachageMessage(MESSAGE_1)
  })

  test('verifier hachage message 2', async ()=>{
    await validateurMessage.verifierHachageMessage(MESSAGE_2)
  })

  test('verifier signature message 1', async ()=>{
    const pem = MESSAGE_1['_certificat'][0]
    const certificat = pki.certificateFromPem(pem)
    await validateurMessage.verifierSignatureMessage(MESSAGE_1, certificat)
  })

  test('verifier signature message 2', async ()=>{
    const pem = MESSAGE_2['_certificat'][0]
    const certificat = pki.certificateFromPem(pem)
    await validateurMessage.verifierSignatureMessage(MESSAGE_2, certificat)
  })

  test('verifier signature message 1 mismatch', async ()=>{
    const pem = MESSAGE_1['_certificat'][0]
    const certificat = pki.certificateFromPem(pem)
    const copieMessage1 = {...MESSAGE_1}
    copieMessage1['_signature'] = 'mAWgoDvq6LL2uqgDCAfRZYZrDjEFTyAFv37KAJBkvyiNNdly7yc+iPPy449Nfs3ujKfUSmer+UkCeNH+b+jTztenSEQXE49yaFdpG0UJeAfR9kt7jsAp1dUV/EfcVRTw9R8xAt/nu7GNBfGVYbOCkI18aMFxB3BDuK33XXDN4SU2cCv/ddJDHLQfZSsnjIaIMtmPURAZ/tt6fobyY821gVO+E+bfdeq4Af6pxqfqGeUeWQDwn5eK0ByVqwkitTY3z+t5i4Dp5aTjcpXZ5tRonJWYmFK/HHbP6q/9Ex3O1WtZYVdDkNyLzbxCh2uFSNe8vtNjGksXAOaJh53Gyrf15kZs'
    try {
      await validateurMessage.verifierSignatureMessage(copieMessage1, certificat)
      throw Error("Invalide")
    } catch(err) {
      // OK
    }
  })

  test('verification hachage et signature message 1', async()=>{
    const pem = MESSAGE_2['_certificat'][0]
    const certificat = pki.certificateFromPem(pem)
    await validateurMessage.verifierMessage(MESSAGE_2, certificat)
  })

})
