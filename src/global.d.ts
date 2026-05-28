// circomlibjs 和 snarkjs 都没有官方 type 声明,这里声明成 any.
// 运行时是 JS, type 缺失不影响功能.

declare module 'circomlibjs' {
  export function buildPoseidon(): Promise<any>;
  export const poseidonContract: any;
}

declare module 'snarkjs' {
  export const groth16: {
    fullProve(input: any, wasmPath: string, zkeyPath: string): Promise<{
      proof: any;
      publicSignals: any[];
    }>;
    verify(verificationKey: any, publicSignals: any[], proof: any): Promise<boolean>;
  };
  export const wtns: any;
  export const r1cs: any;
}
