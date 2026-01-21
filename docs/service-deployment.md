# service deployment on romio testnet

this guide explains how to deploy corevm guest services to the romio jam testnet.

## architecture

```
jam testnet (romio)
├── service #0: bootstrap (creates new services)
└── service #N: corevm instance
    └── guest code (your service logic)
```

**corevm** is a meta-vm that hosts guest programs. when you deploy a `.corevm` file:
- corevm module (~272kb) acts as the host executor
- guest code (your logic) runs inside corevm
- metadata provides initialization parameters

this abstraction simplifies service development by handling jam protocol details.

## prerequisites

1. **romio testnet running**
   ```bash
   julia --threads=2 --project=. -e 'include("src/testnet/testnet.jl"); Testnet.run(; num_nodes=2)'
   ```

2. **jamt cli tool**
   ```bash
   # auto-install (downloads from github releases)
   ./scripts/install-jamt.sh

   # or manual: https://github.com/parity-asia/jamt/releases
   ```

3. **guest code compiled**
   ```bash
   # example: build blc-vm guest
   cd corevm-guests/blc-vm
   cargo build --release --target riscv32ema-unknown-none-elf
   ```

## deploying a service

### quick deploy (blc-vm)

```bash
# start testnet in one terminal
julia --threads=2 --project=. -e 'include("src/testnet/testnet.jl"); Testnet.run(; num_nodes=2)'

# deploy in another terminal (wait ~14s for testnet to start)
./scripts/deploy-service.sh
```

### manual deploy

```bash
./bin/jamt --rpc ws://127.0.0.1:19800 vm new corevm-guests/blc-vm/blc-vm.corevm 100000000
```

parameters:
- `--rpc`: websocket endpoint of testnet node
- `vm new`: create new corevm service
- `<guest.corevm>`: path to guest code
- `<gas_limit>`: gas limit for service creation

### expected output

```
Using CoreVM module corevm v0.1.27 by Parity Technologies <admin@parity.io>
Found Bootstrap service at #0: jam-bootstrap-service v0.1.27
Solicited 3 items in package 0x647137391854101c...
Work package submitted at slot 5539617. Monitoring...
Service 00000002 created at slot 5539618
Service id: 2
Code file: 0:a39010c2115b54e88aa290bb6d6975c33c2edfe6b4979683e156c0fa6c1cb1b6
```

## deployment flow

1. **serviceRequest** (3x) - announce preimages to testnet
   - corevm module (~272kb)
   - guest code (~800 bytes for blc-vm)
   - metadata (~81 bytes)

2. **submitWorkPackage** - submit work package to bootstrap service

3. **subscribeServiceRequest** - subscribe to preimage acceptance notifications

4. **subscribeServiceValue** - watch for service creation result

5. **notification received** - service created, get service id

## querying deployed services

```bash
# get service info
./bin/jamt --rpc ws://127.0.0.1:19800 service info <service_id>

# get service data (raw)
curl -X POST http://127.0.0.1:19800 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"serviceData","params":[<service_id>],"id":1}'
```

## troubleshooting

### "connection refused"
testnet not running or wrong port. default rpc is `ws://127.0.0.1:19800`

### "bootstrap service not found"
testnet needs genesis_services configured. check testnet.jl has bootstrap service at index 0.

### jamt hangs after "monitoring..."
subscription notifications not being sent. check testnet logs for notification messages.

## files

- `scripts/install-jamt.sh` - downloads jamt cli tool
- `scripts/deploy-service.sh` - deployment helper script (auto-installs jamt if missing)
- `corevm-guests/blc-vm/` - blc light client guest code
- `src/testnet/testnet.jl` - testnet implementation with jamt rpc support
- `bin/jamt` - jamt binary (created by install script)
