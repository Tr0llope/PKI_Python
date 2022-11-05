import datetime
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


#Choisr l'algorithme de signature
signature=input("Choisir l'algorithme de signature: 1 pour SHA1, 2 pour SHA256\n") #, 3 pour SHA512
if signature=="1":
    signature=hashes.SHA1()
elif signature=="2":
    signature=hashes.SHA256()
# elif signature=="3":
#     signature=hashes.SHA512()
else:
    print("Erreur de saisie")
    exit()

# Choisir l'algorithme de chiffrement et Génération de la clé privée
cipher=input("Choisir l'algorithme de chiffrement: 1 pour DSA, 2 pour RSA ou 3 pour ECDSA \n")
if cipher=="1":
    key = dsa.generate_private_key(key_size=2048, backend=default_backend())
elif cipher=="2":
    key = rsa.generate_private_key( public_exponent=65537, key_size=2048, backend=default_backend())
elif cipher=="3":
    key = ec.generate_private_key(ec.SECP384R1(), default_backend())
else:
    print("Erreur de saisie")
    exit()


#Créer son autorité d’enregistrement
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile de France"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"groupe ESIEA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"esiea.com"),
])).sign(key, signature, default_backend())
with open("csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))


#Créer son autorité racine
if not os.path.exists("autorite_racine"):
    os.makedirs("autorite_racine")

    with open("autorite_racine/key.pem", "wb") as f:
            f.write(key.private_bytes( encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=serialization.NoEncryption()))

    with open("autorite_racine/cert.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print("Création de l'autorité racine terminée")
else:
    print("L'autorité racine existe déjà")

#Signer les certificats générés par l’autorité d’enregistrement
with open("csr.pem", "rb") as f:
    csr = x509.load_pem_x509_csr(f.read(), default_backend())
with open("rsaKeys/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

certificate = x509.CertificateBuilder().subject_name(
    csr.subject
).issuer_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Ile de France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"groupe ESIEA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"esiea.com"),
    ])
).public_key(
    csr.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).sign(private_key, signature, default_backend())
with open("certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

#Parser le certificat
with open("certificate.pem", "rb") as f:
    certificate = x509.load_pem_x509_certificate(f.read(), default_backend())

print("Emeteur: {}".format(certificate.issuer)) 

print("Sujet: {}".format(certificate.subject))

print("Algorithme de signature: {}".format(certificate.signature_hash_algorithm))

print("Clé publique: {}".format(certificate.public_key()))

print("Numéro de série: {}".format(certificate.serial_number))

print("Début de validité: {}".format(certificate.not_valid_before))

print("Fin de validité: {}".format(certificate.not_valid_after))
