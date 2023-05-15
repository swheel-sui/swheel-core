module swheel::swheel {
  use std::option;

  use sui::tx_context::{Self, TxContext};
  use sui::coin::{Self, TreasuryCap};
  use sui::transfer;

  struct SWHEEL has drop {}

  fun init(witness: SWHEEL, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(
      witness,
      9,
      b"SWHEEL",
      b"Shell",
      b"",
      option::none(),
      ctx,
    );

    transfer::public_freeze_object(metadata);
    transfer::public_transfer(treasury, tx_context::sender(ctx));
  }

  public entry fun mint(
    treasury_cap: &mut TreasuryCap<SWHEEL>, amount: u64, recipient: address, ctx: &mut TxContext
  ) {
    coin::mint_and_transfer(treasury_cap, amount, recipient, ctx)
  }
}