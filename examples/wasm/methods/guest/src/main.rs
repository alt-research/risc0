// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]
#![allow(unused_imports)]

use codec::{Decode};
use wasmi::proof::{CodeProof, OspProof};
use risc0_zkvm::guest::env;
use wasmi::merkle::{DefaultMemoryConfig, MerkleKeccak256};

risc0_zkvm::guest::entry!(main);

pub type EthConfig = DefaultMemoryConfig<MerkleKeccak256>;

pub fn main() {
    let osp_proof_bytes: Vec<u8> = env::read();
    let code_proof_bytes: Vec<u8> = env::read();
    let post_proof_hash: Vec<u8> = env::read();

    let mut osp_proof: OspProof<EthConfig> = Decode::decode(&mut &*osp_proof_bytes).expect("osp proof");
    let code_proof: CodeProof<MerkleKeccak256> = Decode::decode(&mut &*code_proof_bytes).expect("code proof");

    osp_proof.run(&code_proof).expect("osp proof run");

    let proof_hash = osp_proof.hash().to_vec();

    // should be eq
    assert_eq!(proof_hash, post_proof_hash);

    // test ne
    // assert_ne!(proof_hash, post_proof_hash);
}

