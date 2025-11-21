import { FileManager } from "../../src/libs/files";
import { describe, expect, test, beforeAll, afterEach } from "@jest/globals";
import * as dotenv from "dotenv";
import * as path from "path";

dotenv.config();

const CERT_PATH = process.env.CERT_PATH;

describe("FileManager", () => {
  let fileManager: FileManager;

  beforeAll(() => {
    fileManager = new FileManager();
  });

  afterEach(() => {
    fileManager = new FileManager();
  });

  describe("environment configuration", () => {
    test("CERT_PATH should be defined in environment", () => {
      expect(CERT_PATH).toBeDefined();
      expect(CERT_PATH).not.toBeNull();
      expect(typeof CERT_PATH).toBe("string");
    });

    test("CERT_PATH should have .p12 extension", () => {
      expect(CERT_PATH).toMatch(/\.p12$/i);
    });

    test("CERT_PATH should be a valid path format", () => {
      expect((CERT_PATH as string).length).toBeGreaterThan(0);
    });
  });

  describe("openFile method", () => {
    test("should successfully open a certificate file", async () => {
      expect(CERT_PATH).toBeDefined();
      const result = await fileManager.openFile(CERT_PATH!);
      expect(result).toBe(fileManager);
    });

    test("should throw error for non-existent file", async () => {
      const invalidPath = path.join(__dirname, "non-existent-cert.p12");
      await expect(fileManager.openFile(invalidPath)).rejects.toThrow();
    });

    test("should load file as Buffer internally", async () => {
      await fileManager.openFile(CERT_PATH!);
      const buffer = fileManager.getFile();
      expect(buffer).toBeInstanceOf(Buffer);
      expect(buffer).not.toBeUndefined();
    });
  });

  describe("getFile method", () => {
    test("should return undefined when no file is loaded", () => {
      const buffer = fileManager.getFile();
      expect(buffer).toBeUndefined();
    });

    test("should return Buffer after file is loaded", async () => {
      await fileManager.openFile(CERT_PATH!);
      const buffer = fileManager.getFile();
      expect(buffer).toBeInstanceOf(Buffer);
    });

    test("should return non-empty buffer for valid certificate", async () => {
      await fileManager.openFile(CERT_PATH!);
      const buffer = fileManager.getFile();
      expect(buffer?.length).toBeGreaterThan(0);
    });
  });

  describe("toString method", () => {
    test("should throw error when file is not loaded", async () => {
      const fm = new FileManager();
      await expect(fm.toString("utf8")).rejects.toThrow(
        "File data is not loaded. Please call openFile() first."
      );
    });

    test("should convert buffer to string with utf8 encoding", async () => {
      await fileManager.openFile(CERT_PATH!);
      // P12 files are binary, so this will have special characters
      const result = await fileManager.toString("utf8");
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });

    test("should convert buffer to base64 encoding", async () => {
      await fileManager.openFile(CERT_PATH!);
      const base64Result = await fileManager.toString("base64");
      expect(typeof base64Result).toBe("string");
      // Base64 should only contain valid base64 characters
      expect(base64Result).toMatch(/^[A-Za-z0-9+/=]+$/);
    });
  });

  describe("chaining and state management", () => {
    test("should allow method chaining with openFile", async () => {
      const result = await fileManager.openFile(CERT_PATH!);
      expect(result).toBe(fileManager);
      const buffer = fileManager.getFile();
      expect(buffer).toBeInstanceOf(Buffer);
    });

    test("should isolate state between instances", async () => {
      const fm1 = new FileManager();
      const fm2 = new FileManager();

      await fm1.openFile(CERT_PATH!);
      const buffer1 = fm1.getFile();
      const buffer2 = fm2.getFile();

      expect(buffer1).toBeInstanceOf(Buffer);
      expect(buffer2).toBeUndefined();
    });
  });
});
