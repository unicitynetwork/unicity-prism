# Unicity Prism

A zkVM-Powered EVM layer.

Prism by Unicity is a zero-knowledge EVM implementation running inside RISC-0’s zkVM and generates
cryptographic proofs of validity to be verified by Unicity’s BFT guaranteeing fast finality with an
eventual inclusion on the Proof of Work chain.

## What Prism Does
* **zkVM Execution**: All logic runs in RISC Zero’s zkVM for verifiable computation.
* **EVM Execution**: Using REVM the Ethereum Virtual Machine for smart contracts is enabled for
* developers to run solidity contracts.
* **Verifiable Computation**: External systems can verify token operations without running the
logic themselves.
* **Alpha RPC Sync**: The ability to run an Unicity alpha RPC client which is able to parse the
chain from other peers and store the UTXO set as claimable base tokens to be stored in the Prism
state.
* **Familiar Interface**: Will support ETH’s RPC interface so that integration would be dead simple
for any applications upstream.
* **Aggregation**: Transactions executed are aggregated for submission to the BFT consensus.

## Why Our Own EVM to zkVM?
There are a lot of great implementations out there, RISC Zero’s Ethereum application comes to mind,
but they all have one critical issue that won’t work for Unicity: they require an EVM contract on a
host chain to work as the verifier. In our case, the verifier is embedded into the BFT consensus
protocol. Likewise, the migration functionality must be included which doesn’t need to be written
as an EVM solidity contract itself, it can exist as compiled code as either a precompile for
maximal compatibility, or as a custom function.
