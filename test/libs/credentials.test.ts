import { FileManager } from "../../src/libs/files";
import {
  getP12,
  getCertificate,
  isCerticateValid,
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
});
