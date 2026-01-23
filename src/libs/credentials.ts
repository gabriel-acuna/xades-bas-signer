import * as forge from "node-forge";
import { PKCS8Bags } from "./types";

import {
  bigintToBase64,
  getRandomValues,
  hexToBase64,
  sha1ToBase64,
} from "./security";
export function getP12(
  certificate: Uint8Array<ArrayBufferLike>,
  certKey: string
): forge.pkcs12.Pkcs12Pfx {
  const der = forge.util.decode64(
    forge.util.binary.base64.encode(new Uint8Array(certificate))
  );

  const ansi = forge.asn1.fromDer(der);
  return forge.pkcs12.pkcs12FromAsn1(ansi, certKey);
}

export function getIssuerName(cert: forge.pkcs12.Bag) {
  const issuerTributes = cert.cert?.issuer.attributes;
  let issuerName = issuerTributes
    ?.reverse()
    .map((attr) => {
      return `${attr.shortName}=${attr.value}`;
    })
    .join(", ");
  return issuerName;
}

export function getKeyContainer(pkcs8Bags: PKCS8Bags, friendlyName: string) {
  let pkcs8: forge.pkcs12.Bag;
  const oid = forge.pki.oids["pkcs8ShroudedKeyBag"];
  const bags = pkcs8Bags?.[oid];

  if (!bags || !Array.isArray(bags) || bags.length === 0) {
    throw new Error("No key bags found in the PKCS#12 certificate.");
  }

  if (friendlyName.includes("BANCO CENTRAL")) {
    const index = bags.findIndex((key) =>
      key?.attributes?.friendlyName?.[0]?.includes("Signing Key")
    );
    if (!index) {
      throw new Error("Unable to find the key bag for BANCO CENTRAL");
    }
    pkcs8 = bags[index];
  } else {
    pkcs8 = bags[0];
  }
  return pkcs8;
}
export function getKey(pckcs8: forge.pkcs12.Bag) {
  let key: forge.pki.rsa.PrivateKey;
  if (pckcs8["key"]) {
    key = pckcs8["key"] as forge.pki.rsa.PrivateKey;
  } else if (pckcs8["asn1"]) {
    key = forge.pki.privateKeyFromAsn1(
      pckcs8["asn1"]
    ) as forge.pki.rsa.PrivateKey;
  } else {
    throw new Error("No private key found in the PKCS#12 key bag.");
  }
  return key;
}

export function getCertificate(certBag: forge.pkcs12.Bag[]) {
  let crt = certBag.reduce(
    (prev: forge.pkcs12.Bag, current: forge.pkcs12.Bag) => {
      return (current.cert?.extensions?.length ?? 0) >
        (prev.cert?.extensions?.length ?? 0)
        ? current
        : prev;
    }
  );
  return crt;
}
export function isCerticateValid(certficate: forge.pki.Certificate) {
  const notBefore = certficate.validity.notBefore;
  const notAfter = certficate.validity.notAfter;
  const currentDate = new Date();
  return currentDate >= notBefore && currentDate <= notAfter;
}
export function certX509ToPem(certificate: forge.pki.Certificate) {
  return forge.pki.certificateToPem(certificate);
}
export function certX509ToASN1(certificate: forge.pki.Certificate) {
  return forge.pki.certificateToAsn1(certificate);
}
export function getPCK12CertInfo(
  certificate: Uint8Array<ArrayBufferLike>,
  certKey: string
) {
  const p12 = getP12(certificate, certKey);
  const pkcs8Bags: PKCS8Bags = p12.getBags({
    bagType: forge.pki.oids["pkcs8ShroudedKeyBag"],
  });
  const data = p12.getBags({ bagType: forge.pki.oids.certBag });
  if (!data || !data?.[forge.pki.oids.certBag]?.[0])
    throw new Error("Unable to parse certificate. Incorrect Password?");

  const certBags = data[forge.pki.oids.certBag] ?? [];
  const friendlyName = certBags[1].attributes.friendlyName[0];
  let certBag = getCertificate(certBags);
  if (!isCerticateValid(certBag.cert!)) {
    throw new Error("Invalid certificate, check the validity");
  }
  const cert = certBag.cert;

  let pckcs8: forge.pkcs12.Bag;
  let issuerName = getIssuerName(certBag);
  pckcs8 = getKeyContainer(pkcs8Bags, friendlyName);
  let key = getKey(pckcs8);
  const pem = certX509ToPem(cert!);
  let certificateX509 = pem.substring(
    pem.indexOf("\n") + 1,
    pem.indexOf("-----END CERTIFICATE-----")
  );
  certificateX509 = certificateX509.replace(/\r?\n|\r/g, "").replace(/([^\0]{76})/g, "$1\n");
  const ISODateTime = new Date().toISOString().slice(0, 19);
  const certificateANS1 = certX509ToASN1(cert!);
  const certificateDER = forge.asn1.toDer(certificateANS1).getBytes();
  const hashCErtificateX509DER = sha1ToBase64(certificateDER, "utf-8");
  const certificateX509SN = parseInt(cert?.serialNumber!, 16);
  const exponent = hexToBase64(key.e.data[0].toString(16));
  let modulus = bigintToBase64(BigInt(key.n.toString()));
  modulus = modulus!.replace(/\r?\n|\r/g, '').replace(/([^\0]{76})/g, '$1\n');

  const certificateNumber = getRandomValues(999990, 9999999);
  const signatureNumber = getRandomValues(99990, 999999);
  const signedPropertiesNumber = getRandomValues(99990, 999999);
  const signedInfoNumber = getRandomValues(99990, 999999);
  const signedPropertiesIdNumber = getRandomValues(99990, 999999);
  const referenceIdNumber = getRandomValues(99990, 999999);
  const signatureValueNumber = getRandomValues(99990, 999999);
  const objectNumber = getRandomValues(99990, 999999);

  return {
    radomValues: {
      certificateNumber,
      signatureNumber,
      signedPropertiesNumber,
      signedInfoNumber,
      signedPropertiesIdNumber,
      referenceIdNumber,
      signatureValueNumber,
      objectNumber,
    },
    certInfo: {
      digestValue: hashCErtificateX509DER,
      issuerName,
      issuerSerialNumber: certificateX509SN,
      signingTime: ISODateTime,
      certificateX509,
      modulus,
      exponent,
      key,
    },
  };
}
