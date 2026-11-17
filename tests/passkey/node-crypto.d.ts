// The project intentionally ships without @types/node. Tests that compare
// against a real cryptographic implementation need only this slice of the
// built-in node:crypto module, so declare it locally instead of pulling the
// full Node typings into the Nuxt type-check graph.

declare module "node:crypto" {
  export interface Cipher {
    setAutoPadding(value: boolean): void;
    update(data: Uint8Array): Uint8Array;
    final(): Uint8Array;
  }

  export function createCipheriv(
    algorithm: string,
    key: Uint8Array,
    iv: null,
  ): Cipher;
}
