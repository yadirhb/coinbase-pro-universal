import {ClientAuthentication} from '../CoinbasePro';
import crypto from 'crypto-ts';

export interface RequestSetup {
  httpMethod: string;
  payload: string;
  requestPath: string;
}

export interface SignedRequest {
  key: string;
  passphrase: string;
  signature: string;
  timestamp: number;
}

export class RequestSigner {
  // https://docs.pro.coinbase.com/#creating-a-request
  static signRequest(auth: ClientAuthentication, setup: RequestSetup, clockSkew: number): SignedRequest {
    const timestamp = Date.now() / 1000 + clockSkew;
    const what = `${timestamp}${setup.httpMethod}${setup.requestPath}${setup.payload}`;

    const key = crypto.enc.Base64.parse(auth.apiSecret);
    const hash = crypto.HmacSHA256(what, key);
    const signature = crypto.enc.Base64.stringify(hash);

    return {
      key: auth.apiKey,
      passphrase: auth.passphrase,
      signature,
      timestamp,
    };
  }
}
