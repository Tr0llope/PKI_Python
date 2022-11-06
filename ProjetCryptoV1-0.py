#Cryptographie appliquée
#Projet n°2: PKI et Python
#Auteur: Guillaume Paris
#Date: 07-11-2022
#Description: Ce programme permet de créer une autorité de certification, de créer des certificats et de les signer.

import datetime
import os
#from tkinter.ttk import _Padding

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

#Choisr l'algorithme de signature
si=input("Choisir l'algorithme de signature: 1 pour SHA1, 2 pour SHA256\n")
if si=="1":
    signature=hashes.SHA1()
elif si=="2":
    signature=hashes.SHA256()
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

# Créer son autorité racine: certificat et clé privée
if not os.path.exists("autorite_racine"):
    os.makedirs("autorite_racine")

with open("autorite_racine/private_key.pem", "wb") as f:
        f.write(key.private_bytes( encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.NoEncryption()))
with open("autorite_racine/certificat_racine.pem", "wb") as f:
        subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ESIEA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Guillaume Paris"),
        ])
        certificat_racine = x509.CertificateBuilder().subject_name(subject
        ).issuer_name(issuer
        ).public_key(key.public_key()
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).sign(key, signature, default_backend())

        f.write(certificat_racine.public_bytes(serialization.Encoding.PEM))

# Créer son autorité d'enregistrement: demande de certificat
if not os.path.exists("autorite_enregistrement"):
    os.makedirs("autorite_enregistrement")

with open("autorite_enregistrement/demande_certificat.pem", "wb") as f:
        subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Etats-Unis"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Milwaukee"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Université de Milwaukee"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Bill Miller"),
        ])
        demande = x509.CertificateSigningRequestBuilder().subject_name(subject
        ).sign(key, signature, default_backend())
        f.write(demande.public_bytes(serialization.Encoding.PEM))

# Créer un certificat signé par l'autorité racine
certificat = x509.CertificateBuilder().subject_name(demande.subject
        ).issuer_name(certificat_racine.subject
        ).public_key(key.public_key()
        ).serial_number(x509.random_serial_number()
        ).not_valid_before(datetime.datetime.utcnow()
        ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).sign(key, signature, default_backend())
with open("certificat.pem", "wb") as f:
        f.write(certificat.public_bytes(serialization.Encoding.PEM))

# Parser le certificat
print("Emeteur: {}".format(certificat.issuer)) 
print("Sujet: {}".format(certificat.subject))
print("Algorithme de signature: {}".format(certificat.signature_hash_algorithm))
print("Clé publique: {}".format(certificat.public_key()))
print("Numéro de série: {}".format(certificat.serial_number))
print("Début de validité: {}".format(certificat.not_valid_before))
print("Fin de validité: {}".format(certificat.not_valid_after))