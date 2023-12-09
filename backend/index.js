import { Web5 } from '@web5/api';
import { DidKeyMethod, utils as didUtils } from '@web5/dids';
import { VerifiableCredential, PresentationExchange } from '@web5/credentials';
import { Ed25519, Jose } from "@web5/crypto";
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

//const { web5, did: mainDID } = await Web5.connect()

/* Create DIDs for landlord, tenant and apartment */
const landlord = await DidKeyMethod.create();
console.log("landlord DID:", landlord.did);

const tenant = await DidKeyMethod.create();
console.log("tenant DID:", tenant.did);

const apartment = await DidKeyMethod.create();
console.log("apartment DID:", apartment.did);

class Rent {
    constructor(apartmentDID, issuedDate, expirationDate) {
        this.apartmentDID = apartmentDID;
        this.issuedDate = issuedDate;
        this.expirationDate = expirationDate;
    }
}

/* Create VCs for the Rent */
const vc = VerifiableCredential.create({
    type: 'Rent',
    issuer: landlord.did,
    subject: tenant.did,
    data: new Rent(apartment.did, "2023-12-09", "2024-12-09"),
    //expirationDate: "2024-12-09",
});
console.log("VC:", vc);

const { privateKeyJwk } = landlord.keySet.verificationMethodKeys[0];

const signOptions = {
	issuerDid: landlord.did,
	subjectDid: tenant.did,
	kid: `${landlord.did}#${landlord.did.split(":")[2]}`,
	signer: async (data) => await Ed25519.sign({ data, key: privateKeyJwk }),
};

const signedVC = await vc.sign(signOptions);
console.log("signedVC:", signedVC);

/* Store in a DWN */
