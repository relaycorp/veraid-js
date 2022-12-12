import { CertificateStore } from './CertificateStore.js';
import { PrivateKeyStore } from './PrivateKeyStore.js';
import { PublicKeyStore } from './PublicKeyStore.js';

export interface KeyStoreSet {
  readonly privateKeyStore: PrivateKeyStore;
  readonly publicKeyStore: PublicKeyStore;
  readonly certificateStore: CertificateStore;
}
