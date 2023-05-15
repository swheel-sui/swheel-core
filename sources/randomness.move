module swheel::randomness {
  use std::vector;

  use sui::object::{Self, ID, UID};
  use sui::transfer;
  use sui::tx_context::{Self, TxContext};
  use sui::ed25519;
  use sui::address;
  use sui::event;

  const EVerifyFailed: u64 = 10;
  const ENoChanged: u64 = 11;
  const EServerVerifyFailed: u64 = 20;

  const INIT_PUBLIC_KEY: vector<u8> = x"a7ae1ee01eaa4315d933c1f761f6ab7ecdd614062149e9c77e342dc9f68ff680";

  struct Randomness has key, store {
    id: UID,
    client_seed: vector<u8>,
    server_seed_pk: vector<u8>,
    version: u64,
    nonce: u64,
  }

  struct RandomnessManage has key, store {
    id: UID,
    public_key: vector<u8>,
    nonce: u64,
  }

  struct Revealed has drop, copy {
    randomness_id: ID,
    version: u64,
    nonce: u64,
    server_seed_pk: vector<u8>,
  }

  struct ClientSeedChanged has drop, copy {
    randomness_id: ID,
    version: u64,
    nonce: u64,
    new_client_seed: vector<u8>,
  }

  fun init(ctx: &mut TxContext) {
    transfer::share_object(
      RandomnessManage {
        id: object::new(ctx),
        public_key: INIT_PUBLIC_KEY,
        nonce: 0,
      }
    );
  }

  public fun new(manage: &mut RandomnessManage, client_seed: vector<u8>, server_seed_pk: vector<u8>, signature: vector<u8>, ctx: &mut TxContext): Randomness {
    verify_manage_signature(manage, server_seed_pk, &signature, ctx);

    Randomness {
      id: object::new(ctx),
      client_seed,
      server_seed_pk,
      version: 0,
      nonce: 0,
    }
  }

  public fun reveal(
    manage: &mut RandomnessManage, randomness: &mut Randomness,
    server_seed_pk: vector<u8>, signature: vector<u8>, 
    ctx: &mut TxContext,
  ) {
    assert!(randomness.server_seed_pk != server_seed_pk, ENoChanged);
    verify_manage_signature(manage, server_seed_pk, &signature, ctx);

    event::emit(Revealed {
      randomness_id: object::uid_to_inner(&randomness.id),
      version: randomness.version,
      nonce: randomness.nonce,
      server_seed_pk: randomness.server_seed_pk,
    });

    randomness.server_seed_pk = server_seed_pk;
    randomness.version = randomness.version + 1;
    randomness.nonce = 0;
  }

  public fun set(randomness: &mut Randomness, client_seed: vector<u8>, _ctx: &mut TxContext) {
    assert!(randomness.client_seed != client_seed, ENoChanged);

    event::emit(ClientSeedChanged {
      randomness_id: object::uid_to_inner(&randomness.id),
      version: randomness.version,
      nonce: randomness.nonce,
      new_client_seed: client_seed,
    });
    
    randomness.client_seed = client_seed;
  }

  public fun verify_used(randomness: &mut Randomness, msg: &mut vector<u8>, signature: &vector<u8>) {
    vector::append(msg, u64_to_bytes(randomness.version));
    vector::append(msg, u64_to_bytes(randomness.nonce));

    assert!(ed25519::ed25519_verify(signature, &randomness.server_seed_pk, msg), EServerVerifyFailed);

    randomness.nonce = randomness.nonce + 1;
  }

  fun verify_manage_signature(manage: &mut RandomnessManage, server_seed_pk: vector<u8>, signature: &vector<u8>, ctx: &mut TxContext) {
    let msg_bytes = &mut address::to_bytes(tx_context::sender(ctx));
    vector::append(msg_bytes, server_seed_pk);
    vector::append(msg_bytes, u64_to_bytes(manage.nonce));

    assert!(ed25519::ed25519_verify(signature, &manage.public_key, msg_bytes), EVerifyFailed);
    manage.nonce = manage.nonce + 1;
  }

  public fun u64_to_bytes(i: u64): vector<u8> {
    let v = vector::empty<u8>();
    while (i >= 10) {
      vector::push_back(&mut v, (48 + i % 10 as u8));
      i = i / 10;
    };

    vector::push_back(&mut v, (48 + i as u8));
    vector::reverse(&mut v);
    v
  }

  #[test]
  fun test_signature() {
    use sui::test_scenario;

    let admin = @0xCAFE;
    let user = @0x28d655103ec24ff5226e500edbc3c624f5d651b1a520216bb05b5a56b4df8b2d;
    let scenario_val = test_scenario::begin(admin);
    let scenario = &mut scenario_val;
    {
      init(test_scenario::ctx(scenario));
    };

    test_scenario::next_tx(scenario, user);
    {
      let manage = test_scenario::take_shared<RandomnessManage>(scenario);
      assert!(manage.nonce == 0, 0);

      let server_seed_pk = x"93d9c7ff8e44c11d5a8b5f7584974b67a5b0d77a7d837f38573dfe0f4f42cb7d";
      let signature = x"b3150ff519f218817ba4243106c93e9aadd329cf9a485840c7cc5c0dc59c63d449adaf199a5144a850a42b627cbda13b0fc699fd80f01d98d8c70763686dab02";
      verify_manage_signature(&mut manage, server_seed_pk, &signature, test_scenario::ctx(scenario));
      test_scenario::return_shared(manage);
    };

    test_scenario::end(scenario_val);
  }
}