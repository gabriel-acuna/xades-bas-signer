import * as forge from "node-forge";
import { PKCS88Bags } from "./types";
import { Certificate } from "crypto";
import {
  bigintToBase64,
  getRandomValues,
  hexToBase64,
  sha1ToBase64,
} from "./security";
export function getP12(
  certificate: Uint8Array<ArrayBuffer>,
  certKey: string
): forge.pkcs12.Pkcs12Pfx {
  const der = forge.util.decode64(
    forge.util.binary.base64.encode(new Uint8Array(certificate))
  );

  const ansi = forge.asn1.fromDer(der);
  return forge.pkcs12.pkcs12FromAsn1(ansi, certKey);
}

function getIssuerName(cert: forge.pkcs12.Bag) {
  const issuerTributes = cert.cert?.issuer.attributes;
  let issuerName = issuerTributes
    ?.reverse()
    .map((attr) => {
      return `${attr.shortName}=${attr.value}`;
    })
    .join(", ");
  return issuerName;
}

function getKeyContainer(pkcs8Bags: PKCS88Bags, friendlyName: string) {
  let pckcs8;
  forge.pki.oids;
  if (friendlyName.includes("BANCO CENTRAL")) {
    let index = pkcs8Bags[forge.pki.oids["pckcs8ShroudedkeyBag"]]?.findIndex(
      (key) => key.attributes.friendlyName[0].includes("Signing Key")
    );
    //@ts-ignore
    pckcs8 = pkcs8Bags[forge.pki.oids.pckcs8ShorudedkeyBag][index];
  }
  if (friendlyName.includes("SECURITY DATA")) {
    //@ts-ignore
    pckcs8 = pckcs8Bags[forge.pki.oids["pckcs8ShorudedkeyBag"]][0];
  }
  return pckcs8;
}

export function getCertificate(certBag: forge.pkcs12.Bag[]) {
  let crt = certBag.reduce(
    (prev: forge.pkcs12.Bag, current: forge.pkcs12.Bag) => {
      //@ts-ignore
      return current.cert?.extensions.length > prev.cert?.extensions.length
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
  certificate: Uint8Array<ArrayBuffer>,
  certKey: string
) {
  const p12 = getP12(certificate, certKey);
  const pkcs8Bags: PKCS88Bags = p12.getBags({
    bagType: forge.pki.oids["pkcs8ShroudedKeyBag"],
  });
  const data = p12.getBags({ bagType: forge.pki.oids.certBag });
  if (!data || !data?.[forge.pki.oids.certBag]?.[0])
    throw new Error("Unable to parse certificate. Incorrect Password?");

  const certBags = data[forge.pki.oids.certBag] ?? [];
  const friendlyName = certBags[1].attributes.friendlyName[0];
  let certBag = getCertificate(certBags);
  if (isCerticateValid(certBag.cert!)) {
    throw new Error("Invalid certificate, check the validity");
  }
  const cert = certBag.cert;

  let pckcs8;
  let issuerName = getIssuerName(certBag);
  pckcs8 = getKeyContainer(pkcs8Bags, friendlyName);
  const key: forge.pki.rsa.PrivateKey = pckcs8["key"] ?? pckcs8["asn1"];
  const pem = certX509ToPem(cert!);
  let certificateX509 = pem.substring(
    pem.indexOf("\n") + 1,
    pem.indexOf("-----END CERTIFICATE-----")
  );
  certificateX509.replace(/\r?\n|\r/g, "").replace(/([^\0]{76})/g, "$1\n");
  const ISODateTime = new Date().toISOString().slice(0, 19);
  const certificateANS1 = certX509ToASN1(cert!);
  const certificateDER = forge.asn1.toDer(certificateANS1).getBytes();
  const hashCErtificateX509DER = sha1ToBase64(certificateDER, "utf-8");
  const certificateX509SN = parseInt(hashCErtificateX509DER, 16);
  const exponent = hexToBase64(key.e.data[0].toString(16));
  const modulus = bigintToBase64(BigInt(key.n.toString()));

  const certificateNumber = getRandomValues();
  const signatureNumber = getRandomValues();
  const signedPropertiesNumber = getRandomValues();
  const signedInfoNumber = getRandomValues();
  const signedPropertiesIdNumber = getRandomValues();
  const referenceIdNumber = getRandomValues();
  const signatureValueNumber = getRandomValues();
  const objectNumber = getRandomValues();

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
      key
    },
  };
}
