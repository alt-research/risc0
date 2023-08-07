use std::time::SystemTime;

use codec::Encode;
use impl_serde::serialize as bytes;
use serde::Serialize;
use wasmi::{
    core::Value,
    merkle::{DefaultMemoryConfig, MerkleKeccak256},
    proof::{CodeProof, OspProof},
    AsContextMut,
    Engine,
    Error,
    Extern,
    Instance,
    Linker,
    Module,
    StepResult,
    Store,
};
use wat::parse_str;
// TODO: Update the name of the method loaded by the prover. E.g., if the method
// is `multiply`, replace `METHOD_NAME_ELF` with `MULTIPLY_ELF` and replace
// `METHOD_NAME_ID` with `MULTIPLY_ID`

use methods::{METHOD_NAME_ELF, METHOD_NAME_ID};
use risc0_zkvm::{
    default_prover,
    serde::to_vec,
    ExecutorEnv,
    ExitCode,
    ReceiptMetadata,
};

pub type EthConfig = DefaultMemoryConfig<MerkleKeccak256>;

fn setup_module<T>(store: &mut Store<T>, wat: impl AsRef<str>) -> Result<Module, Error> {
    let wasm = parse_str(wat).expect("Illegal wat");
    Module::new(store.engine(), &wasm[..])
}

fn instantiate<T>(store: &mut Store<T>, module: &Module) -> Result<Instance, Error> {
    let linker = <Linker<T>>::new();
    let pre = linker.instantiate(store.as_context_mut(), module)?;
    let instance = pre.ensure_no_start(store.as_context_mut())?;
    Ok(instance)
}

fn call_step<T>(
    store: &mut Store<T>,
    instance: Instance,
    name: &str,
    inputs: &[Value],
    outputs: &mut [Value],
    n: Option<&mut u64>,
) -> Result<StepResult<()>, Error> {
    let f = instance
        .get_export(store.as_context_mut(), name)
        .and_then(Extern::into_func)
        .expect("Could find export function");

    f.step_call(store.as_context_mut(), inputs, outputs, n)
}

fn main() {
    let start = SystemTime::now();

    let engine = Engine::default();
    let mut store = Store::new(&engine, ());
    let module = setup_module(&mut store, FIB).unwrap();
    let instance = instantiate(&mut store, &module).unwrap();

    let code_merkle = store
        .code_proof::<MerkleKeccak256>(instance)
        .make_code_merkle();

    let code_proof = code_merkle.code_proof();

    let inputs = vec![Value::I32(10)];
    let mut outputs = vec![Value::I32(0)];

    // change steps to test differnt inst.
    let mut steps = 10;
    let res = call_step(
        &mut store,
        instance,
        "fib",
        &inputs,
        &mut outputs,
        Some(&mut steps),
    )
        .unwrap();

    let pc = match res {
        StepResult::Results(()) => unreachable!(),
        StepResult::RunOutOfStep(pc) => pc,
    };

    let osp_proof = store
        .osp_proof::<DefaultMemoryConfig<MerkleKeccak256>>(&code_merkle, instance)
        .make_osp_proof_v0(pc)
        .unwrap();

    println!("osp inst: {:?}", osp_proof.inst_proof.inst);
    let env = create_env(osp_proof, code_proof);

    // // Next, we make an executor, loading the (renamed) ELF binary.
    // let mut exec = default_executor_from_elf(env, METHOD_NAME_ELF).unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    {
        let start = SystemTime::now();
        // Produce a receipt by proving the specified ELF binary.
        let receipt = prover.prove_elf(env, METHOD_NAME_ELF).unwrap();
        // println!("receipt segments size: {}", receipt.inner.len());
        // println!("seal size: {}", receipt.segments[0].get_seal_bytes().len());

        let end = SystemTime::now();
        println!("prove time: {:?}", end.duration_since(start).unwrap());

        let start = SystemTime::now();
        receipt.verify(METHOD_NAME_ID).unwrap();
        let end = SystemTime::now();
        println!("verify time: {:?}", end.duration_since(start).unwrap());

        // // output data for solidity side verify
        // let receipts = receipt
        //     .segments
        //     .iter()
        //     .map(|receipt| {
        //         let seal = receipt.get_seal_bytes().to_vec();
        //         let metadata = receipt.get_metadata().unwrap();
        //         Receipt {
        //             seal,
        //             metadata: metadata.into(),
        //         }
        //     })
        //     .collect::<Vec<_>>();
        //
        // let file = std::fs::File::create("osp.json").unwrap();
        // serde_json::to_writer(&file, &receipts).unwrap();
    }

    let end = SystemTime::now();

    println!("time: {:?}", end.duration_since(start).unwrap());
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Receipt {
    /// This is very large.
    #[serde(with = "bytes")]
    pub seal: Vec<u8>,
    pub metadata: Metadata,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Metadata {
    /// Digest of the SystemState of a segment just before execution has begun.
    #[serde(with = "bytes")]
    pub pre: Vec<u8>,
    /// Digest of the SystemState of a segment just after execution has completed.
    #[serde(with = "bytes")]
    pub post: Vec<u8>,
    /// The exit code for a segment
    pub exit_code: ExitCode,
    /// A digest of the input, from the viewpoint of the guest.
    #[serde(with = "bytes")]
    pub input: Vec<u8>,
    /// A digest of the journal, from the viewpoint of the guest.
    #[serde(with = "bytes")]
    pub output: Vec<u8>,
}

impl From<ReceiptMetadata> for Metadata {
    fn from(meta: ReceiptMetadata) -> Self {
        Self {
            pre: meta.pre.digest().as_bytes().to_vec(),
            post: meta.post.digest().as_bytes().to_vec(),
            exit_code: meta.exit_code,
            input: meta.input.as_bytes().to_vec(),
            output: meta.output.as_bytes().to_vec(),
        }
    }
}

fn create_env<'a>(
    mut osp_proof: OspProof<EthConfig>,
    code_proof: CodeProof<MerkleKeccak256>,
) -> ExecutorEnv<'a> {
    let osp_proof_bytes = osp_proof.encode();
    let code_proof_bytes = code_proof.encode();

    osp_proof.run(&code_proof).expect("osp proof run");
    let post_proof_hash = osp_proof.hash().to_vec();

    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&osp_proof_bytes).unwrap())
        .add_input(&to_vec(&code_proof_bytes).unwrap())
        .add_input(&to_vec(&post_proof_hash).unwrap())
        .build()
        .unwrap();

    env
}

const FIB: &str = r#"
    (module
        (export "fib" (func $fib))
        (func $fib (; 0 ;) (param $0 i32) (result i32)
        (local $1 i32)
        (local $2 i32)
        (local $3 i32)
        (local $4 i32)
        (set_local $4
         (i32.const 1)
        )
        (block $label$0
         (br_if $label$0
          (i32.lt_s
           (get_local $0)
           (i32.const 1)
          )
         )
         (set_local $3
          (i32.const 0)
         )
         (loop $label$1
          (set_local $1
           (i32.add
            (get_local $3)
            (get_local $4)
           )
          )
          (set_local $2
           (get_local $4)
          )
          (set_local $3
           (get_local $4)
          )
          (set_local $4
           (get_local $1)
          )
          (br_if $label$1
           (tee_local $0
            (i32.add
             (get_local $0)
             (i32.const -1)
            )
           )
          )
         )
         (return
          (get_local $2)
         )
        )
        (i32.const 0)
       )
    )
    "#;
