import { FileManager } from "../../src/libs/files";
import {
  getP12,
  getCertificate,
  isCerticateValid,
  getIssuerName,
  getKeyContainer,
  getKey,
} from "../../src/libs/credentials";
import { describe, expect, test, beforeAll, afterEach } from "@jest/globals";
import * as dotenv from "dotenv";
import * as forge from "node-forge";
dotenv.config();

const CERT_PATH = process.env.CERT_PATH;
const CERT_KEY = process.env.CERT_KEY;

describe("Crdentials", () => {
  let fileManager: FileManager;
  let arrayuint8: Uint8Array<ArrayBuffer>;
  beforeAll(async () => {
    fileManager = new FileManager();
    await fileManager.openFile(CERT_PATH!);
    let p12Buffer = fileManager.getFile();
    arrayuint8 = new Uint8Array(p12Buffer!);
  });

  afterEach(async () => {
    fileManager = new FileManager();
    await fileManager.openFile(CERT_PATH!);
    let p12Buffer = fileManager.getFile();
    arrayuint8 = new Uint8Array(p12Buffer!);
  });
  describe("getP12 function", () => {
    test("should successfully return a forge.pkcs12.Pkcs12Pfx object", async () => {
      expect(CERT_PATH).toBeDefined();
      expect(CERT_KEY).toBeDefined();
      expect(arrayuint8).toBeDefined();
      let p12 = getP12(arrayuint8, CERT_KEY!);
      expect(p12).toBeInstanceOf(Object);
      console.log(p12);
    });
  });
  describe("isCerticateValid function", () => {
    test("should return true", async () => {
      expect(CERT_PATH).toBeDefined();
      expect(CERT_KEY).toBeDefined();
      expect(arrayuint8).toBeDefined();
      let p12 = getP12(arrayuint8, CERT_KEY!);
      const data = p12.getBags({ bagType: forge.pki.oids["certBag"] });
      const certBags = data[forge.pki.oids["certBag"]] ?? [];
      const certBag = getCertificate(certBags);
      const isValid = isCerticateValid(certBag.cert!);
      expect(isValid).toBeTruthy();
    });
  });
  describe("getIssuerName", () => {
    test("should return issuer name string", async () => {
      expect(CERT_PATH).toBeDefined();
      expect(CERT_KEY).toBeDefined();
      expect(arrayuint8).toBeDefined();
      let p12 = getP12(arrayuint8, CERT_KEY!);
      const data = p12.getBags({ bagType: forge.pki.oids["certBag"] });
      const certBags = data[forge.pki.oids["certBag"]] ?? [];
      const certBag = getCertificate(certBags);
      const cert = certBag.cert;
      let issuerName = getIssuerName(certBag);
      expect(typeof issuerName).toBe("string");
      expect(issuerName).toContain("CN=");
      expect(issuerName).toContain("OU=");
      expect(issuerName).toContain("O=");
      expect(issuerName).toContain("C=");
    });
  });
  describe("getKeyContainer", () => {
    test("should return pkcs8 bag", async () => {
      expect(CERT_PATH).toBeDefined();
      expect(CERT_KEY).toBeDefined();
      expect(arrayuint8).toBeDefined();
      let p12 = getP12(arrayuint8, CERT_KEY!);
      const pkcs8Bags = p12.getBags({
        bagType: forge.pki.oids["pkcs8ShroudedKeyBag"],
      });
      expect(pkcs8Bags).toBeDefined();
      const data = p12.getBags({ bagType: forge.pki.oids["certBag"] });
      const certBags = data[forge.pki.oids["certBag"]] ?? [];
      const friendlyName = certBags[1].attributes.friendlyName[0];
      let pkcs8 = getKeyContainer(pkcs8Bags, friendlyName);
      expect(pkcs8).toBeDefined();
    });
  });
  describe("getKey", () => {
    test("should return key", async () => {
      expect(CERT_PATH).toBeDefined();
      expect(CERT_KEY).toBeDefined();
      expect(arrayuint8).toBeDefined();
      let p12 = getP12(arrayuint8, CERT_KEY!);
      const pkcs8Bags = p12.getBags({
        bagType: forge.pki.oids["pkcs8ShroudedKeyBag"],
      });
      expect(pkcs8Bags).toBeDefined();
      const data = p12.getBags({ bagType: forge.pki.oids["certBag"] });
      const certBags = data[forge.pki.oids["certBag"]] ?? [];
      const friendlyName = certBags[1].attributes.friendlyName[0];
      let pkcs8 = getKeyContainer(pkcs8Bags, friendlyName);
      expect(pkcs8).toBeDefined();
      let key = getKey(pkcs8);
      expect(key).toBeDefined();
      const properties = Object.getOwnPropertyNames(key);
      expect(properties).toContain("n");
      expect(properties).toContain("e");
      expect(properties).toContain("d");
      expect(properties).toContain("sign");
    });
  });
});
