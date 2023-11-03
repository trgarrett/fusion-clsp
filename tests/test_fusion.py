from blspy import G2Element
from copy import deepcopy
import json
import logging
import os
import pytest
import pytest_asyncio
import subprocess
from time import sleep
import traceback

from chia.types.announcement import Announcement
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.coin_record import CoinRecord
from chia.types.coin_spend import CoinSpend
from chia.types.spend_bundle import SpendBundle
from chia.util.bech32m import decode_puzzle_hash
from chia.util.config import load_config
from chia.util.ints import uint16
from chia.util.default_root import DEFAULT_ROOT_PATH
#from chia.wallet.nft_wallet.nft_puzzles import create_full_puzzle_with_nft_puzzle
from chia.wallet.nft_wallet.nft_info import NFTInfo
from chia.wallet.payment import Payment
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, SINGLETON_MOD, SINGLETON_MOD_HASH
from chia.wallet.trade_record import TradeRecord
from chia.wallet.trading.offer import Offer, OFFER_MOD, OFFER_MOD_HASH, NotarizedPayment
from chia.rpc.full_node_rpc_client import FullNodeRpcClient
from chia.rpc.wallet_rpc_client import WalletRpcClient
from chia.util.bech32m import decode_puzzle_hash, encode_puzzle_hash

from fusion.fusion import Fusion, wallet_keys, puzzle_for_coin

from typing import Any, Dict, List, Optional, Set, Tuple

ACS = Program.to(1)

config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
self_hostname = "localhost"
full_node_rpc_port = config["full_node"]["rpc_port"] # 8555
wallet_rpc_port = config["wallet"]["rpc_port"] # 9256
prefix = "txch"
logger = logging.getLogger()

##################################################################################################################
# NOTE: use one you have in your local simulator here!
FINGERPRINT = int(os.environ.get('FINGERPRINT'))
##################################################################################################################


class TestNftUpgrade:

    @pytest.mark.asyncio
    async def test_p2_singleton(self):
        p2_mod: Program = load_clvm("p2_fusion.clsp", package_or_requirement="clsp", recompile=True, include_standard_libraries=True)
        assert p2_mod is not None
        launcher_id = bytes32.from_hexstr("0x9bb9175628b08d6f37860bf7f4e320230ffd7cae76bf4c4a618b705c87402be4") # random test value
        nft_launcher_id = bytes32.from_hexstr("0x22e48b670ff415a5d49b720d34d44cebd34c2c65288ff5bd75d82351ffacd925")
        cafe_babe = bytes32.from_hexstr("0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe")
        next_puzzlehash = bytes32.from_hexstr("0x610f8034eba64c56ed6e7a66791e9be5da37be8c8058681094c848a053134832")

        singleton_inner_puzzlehash = ACS.get_tree_hash()
        singleton_coin_id = bytes32.from_hexstr("0x1153f45c9a956058b19be9625c45efca3904ca362a6d2221341e6546d5734d78")

        result: Program = p2_mod.run(Program.to([SINGLETON_MOD_HASH, launcher_id, SINGLETON_LAUNCHER_HASH, singleton_inner_puzzlehash,
                                                 singleton_coin_id, nft_launcher_id, cafe_babe, next_puzzlehash]))

        assert Program.fromhex("ffff48ffa06dc5f208f1c552a87a8c0519cebfa81866cfeaff8c15c719abf432558b56307b80ffff49ff0180ffff3fffa0bced5b08fc8737818f9742baf508c39536c7ddec4b668f238e15efad0951640880ffff33ffa0610f8034eba64c56ed6e7a66791e9be5da37be8c8058681094c848a053134832ff01ffffa0610f8034eba64c56ed6e7a66791e9be5da37be8c8058681094c848a0531348328080ffff3cffa0880e4b5aa3cd2f8499f64cd1de8aa2d2d8e46e72e833e8062809f3828f27e9db8080") == result


    @pytest.mark.asyncio
    async def test_roundtrip_simulator(self):
        fusion = Fusion()
        try:
            await fusion.init()
            fusion.load_keys(FINGERPRINT)

            wallet_client = fusion.wallet_client
            node_client = fusion.node_client

            did_one_id, _ = await fusion.create_did()
            did_two_id, _ = await fusion.create_did()
            did_three_id, _ = await fusion.create_did()

            # make simulated NFTs and send to primary address of wallet
            primary_puzzle = puzzle_for_pk(wallet_keys[0].get_g1())
            primary_puzzlehash = primary_puzzle.get_tree_hash()
            primary_address = encode_puzzle_hash(primary_puzzlehash, prefix)

            nft_a_launcher_id = await fusion.mint_nft(did_one_id, primary_puzzlehash, 'A')
            nft_a_coin_record = await fusion.wait_for_coin_record(nft_a_launcher_id)
            nft_b1_launcher_id = await fusion.mint_nft(did_two_id, primary_puzzlehash, 'B1')
            nft_b2_launcher_id = await fusion.mint_nft(did_three_id, primary_puzzlehash, 'B2')
            
            nft_a_coin_record: CoinRecord = await fusion.wait_for_coin_record(nft_a_launcher_id)
            nft_b1_coin_record: CoinRecord = await fusion.wait_for_coin_record(nft_b1_launcher_id)
            nft_b2_coin_record: CoinRecord = await fusion.wait_for_coin_record(nft_b2_launcher_id)

            singleton_launcher_id = await fusion.cli_deploy_singleton(encode_puzzle_hash(nft_a_launcher_id, "nft"),
                                                                      encode_puzzle_hash(nft_b1_launcher_id, "nft") + ","
                                                                      + encode_puzzle_hash(nft_b2_launcher_id, "nft"))
            assert singleton_launcher_id is not None

            p2_singleton = fusion.pay_to_singleton_puzzle(singleton_launcher_id)
            p2_puzzlehash = p2_singleton.get_tree_hash()

            # troubleshooting...
            logger.info(f"offer mod hash: {OFFER_MOD_HASH}")
            logger.info(f"primary address/puzzlehash: {primary_address} / {primary_puzzlehash.hex()}")
            logger.info(f"SINGLETON_MOD_HASH: {SINGLETON_MOD_HASH}")
            logger.info(f"SINGLETON_LAUNCHER_HASH: {SINGLETON_LAUNCHER_HASH}")

            # transfer A to P2
            nft_a_coin_id = (await fusion.find_unspent_descendant(nft_a_coin_record)).coin.name()
            logger.info(f"Locking A into p2 (coin id {nft_a_coin_id.hex()})")
            (a_spend_bundle, _) = await fusion.make_transfer_nft_spend_bundle(nft_a_launcher_id, p2_puzzlehash)
            status = await node_client.push_tx(a_spend_bundle)
            # make sure A is visible in p2 before we move further
            await self.wait_for_coin_spent(node_client, a_spend_bundle.coin_spends[0].coin.name())
            nft_a_coin_record = (await fusion.find_unspent_descendant(nft_a_coin_record))
            nft_a_coin_id = nft_a_coin_record.coin.name()
            logger.debug(f"After locking A into p2, (coin id {nft_a_coin_id.hex()})")

            offer: Offer = await self.make_offer_b_for_a(fusion, nft_a_launcher_id,
                                                         [(nft_b1_launcher_id, nft_b1_coin_record),
                                                          (nft_b2_launcher_id, nft_b2_coin_record)],
                                                          primary_puzzlehash)
            logger.info(f"Offer\n\t{offer.to_bech32()}")

            # test offer bundle - in general, this should do the same thing as the make_offer_b_for_a, but 
            # the test only supports it going back to its primary puzzlehash, so we're not adopting it for now
            offer_bundle_json: str = await fusion.make_offer_bundle_json(singleton_launcher_id, 'a', 1000)
            logger.info(f"JSON bundle: {offer_bundle_json}")
            assert offer_bundle_json is not None
            assert json.loads(offer_bundle_json) is not None

            await fusion.swap(singleton_launcher_id, offer.to_bech32())

            # make sure first swap is visible on chain
            logger.info("Waiting for swapped coins to show as moved on chain")
            logger.info("A...")
            await self.wait_for_coin_spent(fusion.node_client, nft_a_coin_record.coin.name())
            logger.info("B1...")
            await self.wait_for_coin_spent(fusion.node_client, nft_b1_coin_record.coin.name())
            logger.info("B2...")
            await self.wait_for_coin_spent(fusion.node_client, nft_b2_coin_record.coin.name())
            logger.info("Swapped on chain.")

            nft_a_coin_record = await fusion.find_unspent_descendant(await node_client.get_coin_record_by_name(nft_a_launcher_id))
            a_p2_puzzle = puzzle_for_pk(wallet_keys[0].get_g1())
            a_full_puzzle = await fusion.full_puzzle_for_p2_puzzle(nft_a_launcher_id, a_p2_puzzle)
            assert nft_a_coin_record.coin.puzzle_hash.hex() == a_full_puzzle.get_tree_hash().hex()

            nft_b1_coin_record = await fusion.find_unspent_descendant(await node_client.get_coin_record_by_name(nft_b1_launcher_id))
            b1_puzzle = await fusion.full_puzzle_for_p2_puzzle(nft_b1_launcher_id, p2_singleton)
            assert nft_b1_coin_record.coin.puzzle_hash.hex() == b1_puzzle.get_tree_hash().hex()

            nft_b2_coin_record = await fusion.find_unspent_descendant(await node_client.get_coin_record_by_name(nft_b2_launcher_id))
            b2_puzzle = await fusion.full_puzzle_for_p2_puzzle(nft_b2_launcher_id, p2_singleton)
            assert nft_b2_coin_record.coin.puzzle_hash.hex() == b2_puzzle.get_tree_hash().hex()

            # make sure last swap is completely visible on chain
            await farm_block(fusion.wallet_client)

            # complete the roundtrip by defusing and trading A back for B1 and B2
            logger.info("Beginning defusion flow...")

            offer: Offer = await self.make_offer_a_for_b(fusion, nft_a_launcher_id, nft_a_coin_record,
                                                         [(nft_b1_launcher_id, nft_b1_coin_record),
                                                          (nft_b2_launcher_id, nft_b2_coin_record)],
                                                          primary_puzzlehash)
            logger.info(f"Offer\n\t{offer.to_bech32()}")

            await fusion.swap(singleton_launcher_id, offer.to_bech32())

            logger.info("Waiting for swapped coins to show as moved on chain (defusion!)")
            logger.info(f"A...{nft_a_coin_record.coin.name().hex()}")
            await self.wait_for_coin_spent(fusion.node_client, nft_a_coin_record.coin.name())
            logger.info(f"B1...{nft_b1_coin_record.coin.name().hex()}")
            await self.wait_for_coin_spent(fusion.node_client, nft_b1_coin_record.coin.name())
            logger.info(f"B2...{nft_b2_coin_record.coin.name().hex()}")
            await self.wait_for_coin_spent(fusion.node_client, nft_b2_coin_record.coin.name())
            logger.info("Swapped on chain.")

            # assert everything ends up in the right spot
            # A locked into p2_singleton
            nft_a_coin_record = await fusion.find_unspent_descendant(await node_client.get_coin_record_by_name(nft_a_launcher_id))
            a_puzzle = await fusion.full_puzzle_for_p2_puzzle(nft_a_launcher_id, p2_singleton)
            assert nft_a_coin_record.coin.puzzle_hash.hex() == a_puzzle.get_tree_hash().hex()

            # B1 back to user wallet
            nft_b1_coin_record = await fusion.find_unspent_descendant(await node_client.get_coin_record_by_name(nft_b1_launcher_id))
            b1_puzzle = puzzle_for_pk(wallet_keys[0].get_g1())
            b1_full_puzzle = await fusion.full_puzzle_for_p2_puzzle(nft_b1_launcher_id, b1_puzzle)
            assert nft_b1_coin_record.coin.puzzle_hash.hex() == b1_full_puzzle.get_tree_hash().hex()

            # B2 back to user wallet
            nft_b2_coin_record = await fusion.find_unspent_descendant(await node_client.get_coin_record_by_name(nft_b2_launcher_id))
            b2_puzzle = puzzle_for_pk(wallet_keys[0].get_g1())
            b2_full_puzzle = await fusion.full_puzzle_for_p2_puzzle(nft_b2_launcher_id, b2_puzzle)
            assert nft_b2_coin_record.coin.puzzle_hash.hex() == b2_full_puzzle.get_tree_hash().hex()

        finally:
            # clean up connections
            await fusion.close()


    async def make_offer_b_for_a(self, fusion, nft_a_launcher_id: bytes32,
                                 b_coins: List[Tuple[bytes32, CoinRecord]],
                                 nft_next_puzzlehash: bytes32) -> Offer:
        driver_dict: Dict[bytes32, PuzzleInfo] = {}
        driver_dict[nft_a_launcher_id] = await self.get_puzzle_info(fusion, nft_a_launcher_id)

        nft_b1_launcher_id = b_coins[0][0]
        nft_b1_coin_record = b_coins[0][1]
        nft_b2_launcher_id = b_coins[1][0]
        nft_b2_coin_record = b_coins[1][1]
        driver_dict[nft_b1_launcher_id] = await self.get_puzzle_info(fusion, nft_b1_launcher_id)
        driver_dict[nft_b2_launcher_id] = await self.get_puzzle_info(fusion, nft_b2_launcher_id)

        requested_payments: Dict[Optional[bytes32], List[NotarizedPayment]] = {}
        requested_payments[nft_a_launcher_id] = [Payment(nft_next_puzzlehash, 1, [nft_next_puzzlehash])]

        notarized_payments = Offer.notarize_payments(requested_payments, [nft_b1_coin_record.coin, nft_b2_coin_record.coin])
        spend_bundle_b1, _ = await fusion.make_transfer_nft_spend_bundle(nft_b1_launcher_id, OFFER_MOD_HASH)
        spend_bundle_b2, _ = await fusion.make_transfer_nft_spend_bundle(nft_b2_launcher_id, OFFER_MOD_HASH)

        spend_bundle: SpendBundle = SpendBundle.aggregate([spend_bundle_b1, spend_bundle_b2])

        offer: Offer = Offer(notarized_payments, spend_bundle, driver_dict)
        return offer
    

    async def make_offer_a_for_b(self, fusion, nft_a_launcher_id: bytes32, nft_a_coin_record: CoinRecord,
                                 b_coins: List[Tuple[bytes32, CoinRecord]],
                                 nft_next_puzzlehash: bytes32) -> Offer:
        driver_dict: Dict[bytes32, PuzzleInfo] = {}
        driver_dict[nft_a_launcher_id] = await self.get_puzzle_info(fusion, nft_a_launcher_id)

        nft_b1_launcher_id = b_coins[0][0]
        nft_b2_launcher_id = b_coins[1][0]

        driver_dict[nft_b1_launcher_id] = await self.get_puzzle_info(fusion, nft_b1_launcher_id)
        driver_dict[nft_b2_launcher_id] = await self.get_puzzle_info(fusion, nft_b2_launcher_id)

        requested_payments: Dict[Optional[bytes32], List[NotarizedPayment]] = {}
        requested_payments[nft_b1_launcher_id] = [Payment(nft_next_puzzlehash, 1, [nft_next_puzzlehash])]
        requested_payments[nft_b2_launcher_id] = [Payment(nft_next_puzzlehash, 1, [nft_next_puzzlehash])]

        notarized_payments = Offer.notarize_payments(requested_payments, [nft_a_coin_record.coin])
        spend_bundle_a, _ = await fusion.make_transfer_nft_spend_bundle(nft_a_launcher_id, OFFER_MOD_HASH)

        offer: Offer = Offer(notarized_payments, spend_bundle_a, driver_dict)
        return offer


    async def get_puzzle_info(self, fusion, coin_id: bytes32) -> PuzzleInfo:
        driver_dict = await fusion.get_driver_dict(coin_id)
        id = coin_id.hex()
        return PuzzleInfo(driver_dict[id])


    # Wait for a coin record to be spent after creation - handles block farming delays
    async def wait_for_coin_spent(self, node_client: FullNodeRpcClient, coin_id: bytes32) -> bool:
        coin_record: CoinRecord = None
        for i in range(1, 20):
            coin_record = await node_client.get_coin_record_by_name(coin_id)
            if coin_record.spent:
                return True
            sleep(i * 0.25)
        if coin_record is None or coin_record.spent is False:
            raise Exception(f"Couldn't find spent coin {coin_id.hex()}")


async def farm_block(wallet_client, count=1):
    logger.info(f"Farming {count} block(s)...")
    subprocess.run(["chia", "dev", "sim", "farm", "-b", f"{count}"])
    await wallet_synced(wallet_client)


async def wallet_synced(wallet_client: WalletRpcClient):
    synced = await wallet_client.get_synced()
    while not synced:
        try:
            synced = await wallet_client.get_synced()
        except:
            logger.info("Waiting for synced wallet")
            sleep(1)
    logger.info("wallet synced")

