import * as forge from 'node-forge'
declare interface PKCS8Bags {
    [key: string]: forge.pkcs12.Bag[] | undefined;
    localKeyId?: forge.pkcs12.Bag[] | undefined;
    friendlyName?: forge.pkcs12.Bag[] | undefined;
}
declare function sign(params: {
  p12Path: string;
  p12Password: string;
  rootElement: string;
  xmlPath?: string;
  xmlString?: string;
}):string