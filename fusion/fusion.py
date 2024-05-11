#########################
# fusion.py        #
#########################
import asyncio
import json
import logging
import os
import sys
import traceback

from blspy import G2Element, PrivateKey
from collections import deque
from copy import deepcopy
from time import sleep
from typing import Any, Dict, List, Optional, Set, Tuple
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.rpc.full_node_rpc_client import FullNodeRpcClient
from chia.rpc.wallet_rpc_client import WalletRpcClient
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.serialized_program import SerializedProgram
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.coin_record import CoinRecord
from chia.types.coin_spend import make_spend, CoinSpend
from chia.types.spend_bundle import SpendBundle
from chia.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from chia.util.config import load_config
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.ints import uint16, uint64
from chia.util.keychain import Keychain
from chia.wallet.conditions import CreateCoinAnnouncement, UnknownCondition
from chia.wallet.derive_keys import master_sk_to_wallet_sk, master_sk_to_wallet_sk_unhardened
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.nft_wallet.nft_info import NFTInfo
from chia.wallet.nft_wallet.nft_puzzles import (
    NFT_METADATA_UPDATER,
    NFT_OWNERSHIP_LAYER_HASH, 
    NFT_STATE_LAYER_MOD_HASH,
    create_full_puzzle_with_nft_puzzle, 
    create_nft_layer_puzzle_with_curry_params,
    create_ownership_layer_puzzle
)
from chia.wallet.nft_wallet.ownership_outer_puzzle import puzzle_for_ownership_layer
from chia.wallet.nft_wallet import nft_puzzles
from chia.wallet.nft_wallet.uncurry_nft import UncurriedNFT
from chia.wallet.payment import Payment
from chia.wallet.puzzle_drivers import PuzzleInfo
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk,
    puzzle_hash_for_synthetic_public_key,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.wallet.sign_coin_spends import sign_coin_spends
from chia.wallet.trading.offer import Offer, OFFER_MOD, OFFER_MOD_HASH, NotarizedPayment
from chia.wallet.util.compute_memos import compute_memos_for_spend
from chia.wallet.util.tx_config import CoinSelectionConfig, TXConfig
from chia.wallet.wallet import Wallet

NFT_METADATA_UPDATER_PUZZLE_HASH: bytes32 = NFT_METADATA_UPDATER.get_tree_hash()
NFT_METADATA_UPDATER_PUZZLE_HASH_HASH: Program = Program.to(NFT_METADATA_UPDATER_PUZZLE_HASH).get_tree_hash()

INFINITE_COST = 11000000000

P2_MOD: Program = load_clvm("p2_fusion.clsp", package_or_requirement="clsp", recompile=True)

PREFIX = os.environ.get("PREFIX", "xch")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger()

MAX_BLOCK_COST_CLVM = DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM

MAX_COIN_AMOUNT = DEFAULT_CONSTANTS.MAX_COIN_AMOUNT

SINGLETON_AMOUNT = uint64(1)
DERIVATIONS = int(os.environ.get('DERIVATIONS', 1000))

SINGLETON_INNER: Program = load_clvm("fusion_singleton.clsp", package_or_requirement="clsp", recompile=True)

CHIP21_HINT: bytes32 = bytes32.from_hexstr("0x0a8d35c54b18e9be24a1aebc49497ebc53d33c6b875d7e2c984cbe35185b5a7f")

config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
self_hostname = "localhost"
full_node_rpc_port = config["full_node"]["rpc_port"] # 8555
wallet_rpc_port = config["wallet"]["rpc_port"] # 9256

agg_sig_config = None

TESTNET = os.environ.get("TESTNET", "testnet10")

if PREFIX == 'txch':
    try:
        agg_sig_config = bytes32.from_hexstr(config["farmer"]["network_overrides"]["constants"][TESTNET]["AGG_SIG_ME_ADDITIONAL_DATA"])
        logger.info(f"Loaded AGG_SIG_ME_ADDITIONAL_DATA override: {agg_sig_config}")
    except Exception as e:
        logger.warning(f"Tried loading AGG_SIG_ME_ADDITIONAL_DATA from config. Exception {e}")

AGG_SIG_ME_ADDITIONAL_DATA = agg_sig_config or DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA

BACKOFF_RETRY_COUNT = int(os.environ.get("BACKOFF_RETRY_COUNT", 25))
BACKOFF_RETRY_WAIT_SECS = int(os.environ.get("BACKOFF_RETRY_WAIT_SECS", 5))

wallet_keys = []
puzzle_reveals = {}

# track coins spent recently to make sure they are not re-selected during pending block confirmations
recent_coins: deque = deque([], 1000)


class Fusion:

    async def init(self):
        self.node_client = await FullNodeRpcClient.create(self_hostname, uint16(full_node_rpc_port), DEFAULT_ROOT_PATH, config)
        self.wallet_client = await WalletRpcClient.create(self_hostname, uint16(wallet_rpc_port), DEFAULT_ROOT_PATH, config)


    async def close(self):
        self.node_client.close()
        self.wallet_client.close()
        await self.node_client.await_closed()
        await self.wallet_client.await_closed()


    # Let the NFT upgrade know about recently spent coins (pending confirmation or in a recent block) so it won't try to select them again for its purposes
    def record_spent_coin(self, coin: Coin):
        recent_coins.append(coin)


    def load_keys(self, fingerprint: int):

        if len(wallet_keys) > 0:
            logger.info(f"Found {len(wallet_keys)} pre-loaded wallet keys, skipping")
            return

        logger.info(f"Loading private key for spend bundle signing (fee support and private spends), fingerprint {fingerprint}")
        logger.info(f'Is keychain locked? {Keychain.is_keyring_locked()}')
        keychain = Keychain()
        
        sk = keychain.get_private_key_by_fingerprint(fingerprint)
        assert sk is not None
        
        logger.info(f'Deriving {DERIVATIONS} synthetic private keys')
        for i in range(DERIVATIONS):
            wk1 = master_sk_to_wallet_sk_unhardened(sk[0], i)
            wk2 = master_sk_to_wallet_sk(sk[0], i)
            wallet_keys.append(wk1)
            wallet_keys.append(wk2)

        logger.info(f'Caching {len(wallet_keys)} wallet keys')
        for wallet_key in wallet_keys:
            pk = wallet_key.get_g1()
            puzzle = puzzle_for_pk(pk)
            puzzle_reveals[puzzle.get_tree_hash()] = puzzle

        # TODO - could have a more elaborate default public key selection flow 
        # -- this assumes the first key found is always used for PUBKEY_A
        wallet_key = wallet_keys[0]


    async def create_singleton_launcher(self, fee_amount: int=1000) -> Coin:
        amount = uint64(SINGLETON_AMOUNT + fee_amount)
    
        logger.info('Creating singleton launcher...')
        coins: List[Coin] = await select_coins(self.wallet_client, amount)

        launcher_parent: Coin = coins.copy().pop()
        genesis_launcher_puz: Program = SINGLETON_LAUNCHER
        launcher_coin: Coin = Coin(launcher_parent.name(), genesis_launcher_puz.get_tree_hash(), SINGLETON_AMOUNT)
        recent_coins.append(launcher_parent)
        recent_coins.append(launcher_coin)

        return launcher_coin


    async def deploy_singleton(self, launcher_coin: Coin, inner_puzzle: Program, nft_a_launcher_ids: List[bytes32], nft_b_launcher_ids: List[bytes32], fee_amount: int) -> bytes32:
        try:
            logger.info("\r\n*******************************DEPLOYING NFT upgrade singleton ******************************************************")
            logger.info("NFT(s) A: ")
            for id in nft_a_launcher_ids:
                logger.info(encode_puzzle_hash(id, "nft"))
            logger.info("NFT(s) B: ")
            for id in nft_b_launcher_ids:
                logger.info(encode_puzzle_hash(id, "nft"))
            
            full_puzzle: Program = puzzle_for_singleton(launcher_coin.name(), inner_puzzle)
            puzzle_hash = full_puzzle.get_tree_hash()

            genesis_launcher_puz: Program = SINGLETON_LAUNCHER
            extra_data = [launcher_coin.name(), nft_a_launcher_ids, nft_b_launcher_ids]
            genesis_launcher_solution: Program = Program.to([puzzle_hash, SINGLETON_AMOUNT, [], extra_data])
            message_program: Program = Program.to([puzzle_hash, SINGLETON_AMOUNT, []])
            announcement = CreateCoinAnnouncement(message_program, launcher_coin.name())
            
            launcher_parent: Coin = (await self.node_client.get_coin_record_by_name(launcher_coin.parent_coin_info)).coin
            change_puzzlehash = launcher_parent.puzzle_hash
            change_amount = launcher_parent.amount - fee_amount - SINGLETON_AMOUNT
            assert change_amount >= 0

            primaries = []
            primaries.append(Payment(change_puzzlehash, change_amount, change_puzzlehash))
            primaries.append(Payment(SINGLETON_LAUNCHER.get_tree_hash(), SINGLETON_AMOUNT, [CHIP21_HINT]))

            logger.info(f'Making coin spend with fees: {fee_amount}')
            wallet = Wallet()
            solution = wallet.make_solution(
                primaries=primaries,
                fee=fee_amount,
                conditions = [announcement]
            )

            coin_a_puzzle = puzzle_for_coin(launcher_parent)
            coin_a_spend = make_spend(launcher_parent, coin_a_puzzle, solution)

            launcher_cs: CoinSpend = make_spend(
                launcher_coin,
                SerializedProgram.from_program(genesis_launcher_puz),
                SerializedProgram.from_program(genesis_launcher_solution),
            )

            logger.info('Will sign launcher spend...')

            full_spend = await sign_coin_spends([coin_a_spend, launcher_cs], wallet_keyf,
                                                self.get_synthetic_private_key_for_puzzle_hash,
                                                AGG_SIG_ME_ADDITIONAL_DATA, MAX_BLOCK_COST_CLVM, [puzzle_hash_for_synthetic_public_key])
            status = await self.node_client.push_tx(full_spend)
            print_json(status)

            p2_singleton = self.pay_to_singleton_puzzle(launcher_coin.name())
            p2_singleton_address = encode_puzzle_hash(p2_singleton.get_tree_hash(), PREFIX)

            if status["success"] == True:
                logger.info('*******************************DEPLOYED*******************************************************')
                logger.info(f' launcher ID: 0x{launcher_coin.name().hex()}')
                logger.info(f' p2_singleton address: {p2_singleton_address}')
                logger.info('**********************************************************************************************')
                return launcher_coin.name()

            raise RuntimeError("Unable to complete singleton deployment.")
        except Exception as e:
            logger.info(e)
            logger.info(f'Failed on: {traceback.format_exc(e)}')
            logger.info('\r\n...Continuing to next coin')


    async def get_synthetic_private_key_for_puzzle_hash(self, puzzle_hash: bytes32) -> Optional[PrivateKey]:
        # TODO new API from upstream...implement if needed
        return None

    def pay_to_singleton_puzzle(self, launcher_id: bytes32) -> Program:
        p2_curried: Program = P2_MOD.curry(SINGLETON_MOD_HASH, launcher_id, SINGLETON_LAUNCHER_HASH)
        return p2_curried
    

    async def nft_singleton_inner_puzzle_for_p2_puzzle(self, nft_launcher_id: bytes32, inner_puzzle: Program) -> Program:
        nft_coin_record: CoinRecord = await self.node_client.get_coin_record_by_name(nft_launcher_id)
        coin_record: CoinRecord = await self.find_unspent_descendant(nft_coin_record)
        parent_coin_record: CoinRecord = await self.node_client.get_coin_record_by_name(coin_record.coin.parent_coin_info)
        assert parent_coin_record is not None
        puzzle_and_solution: CoinSpend = await self.node_client.get_puzzle_and_solution(coin_id=coin_record.coin.parent_coin_info, height=parent_coin_record.spent_block_index)
        return await self.nft_singleton_inner_puzzle_for_p2_puzzle_and_spend(puzzle_and_solution, inner_puzzle)

    
    async def nft_singleton_inner_puzzle_for_p2_puzzle_and_spend(self, coin_spend: CoinSpend, inner_puzzle: Program) -> Program:
        parent_puzzle_reveal = coin_spend.puzzle_reveal
        nft_program = Program.from_bytes(bytes(parent_puzzle_reveal))
        unft = UncurriedNFT.uncurry(*nft_program.uncurry())

        nft_inner_puzzle: Program = await self.nft_inner_puzzle_from_spend(coin_spend, inner_puzzle)
        nft_singleton_inner_puzzle = create_nft_layer_puzzle_with_curry_params(unft.metadata, unft.metadata_updater_hash, nft_inner_puzzle)
        return nft_singleton_inner_puzzle
    

    async def full_puzzle_for_p2_puzzle(self, nft_launcher_id: bytes32, inner_puzzle: Program):
        full_puzzle = create_full_puzzle_with_nft_puzzle(nft_launcher_id, await(self.nft_singleton_inner_puzzle_for_p2_puzzle(nft_launcher_id, inner_puzzle)))
        return full_puzzle

    async def nft_inner_puzzle_from_spend(self, coin_spend: CoinSpend, p2_puzzle: Program) -> Program:
        nft_program = Program.from_bytes(bytes(coin_spend.puzzle_reveal))
        unft = UncurriedNFT.uncurry(*nft_program.uncurry())
        inner_puzzle: Program = None

        if unft is not None:
            if unft.supports_did:
                inner_puzzle = nft_puzzles.recurry_nft_puzzle(unft, coin_spend.solution.to_program(), p2_puzzle)
            else:
                inner_puzzle = p2_puzzle

        assert inner_puzzle is not None

        return inner_puzzle


    # transfer an NFT, held by the wallet for this app, to a new destination
    async def make_transfer_nft_spend_bundle(self, nft_launcher_id: bytes32, recipient_puzzlehash: bytes32, fee_amount:int=0) -> Tuple[SpendBundle, bytes32]:
        logger.info(f"Transferring NFT {encode_puzzle_hash(nft_launcher_id, 'nft')} to {encode_puzzle_hash(recipient_puzzlehash, PREFIX)}")

        nft_launcher_coin_record = await self.node_client.get_coin_record_by_name(nft_launcher_id)
        assert nft_launcher_coin_record is not None
        coin_record = await self.find_unspent_descendant(nft_launcher_coin_record)
        assert coin_record is not None
        parent_coin_record = await self.node_client.get_coin_record_by_name(coin_record.coin.parent_coin_info)
        assert parent_coin_record is not None
        puzzle_and_solution: CoinSpend = await self.node_client.get_puzzle_and_solution(coin_id=coin_record.coin.parent_coin_info, height=parent_coin_record.spent_block_index)
        parent_puzzle_reveal = puzzle_and_solution.puzzle_reveal

        nft_program = Program.from_bytes(bytes(parent_puzzle_reveal))
        unft = UncurriedNFT.uncurry(*nft_program.uncurry())
        parent_inner_puzzlehash = unft.nft_state_layer.get_tree_hash()

        _, phs = nft_puzzles.get_metadata_and_phs(unft, puzzle_and_solution.solution)
        p2_puzzle = puzzle_reveals.get(phs)

        if unft is not None:
            info = NFTInfo.from_json_dict((await self.wallet_client.get_nft_info(coin_record.name.hex()))["nft_info"])
            if unft.owner_did != info.owner_did:
                logger.warning(f"DID mismatch in make_transfer_nft_spend_bundle ({encode_puzzle_hash(nft_launcher_id, 'nft')}): unft: {unft.owner_did.hex() if unft.owner_did is not None else None}, info: {info.owner_did.hex() if info.owner_did is not None else None}")

            conditions=(UnknownCondition
                           (opcode=Program.to(-10),
                            args=[
                                Program.to(None), ###clear out DID when transferring
                                Program.to([]),
                                Program.to(None),
                            ]
                           )
                       , )

            primaries = []
            primaries.append(Payment(recipient_puzzlehash, 1, [recipient_puzzlehash]))
            innersol = Wallet().make_solution(
                primaries=primaries,
                fee=fee_amount,
                conditions=conditions
            )

            logger.debug(f"innersol: {str(innersol)}")

            lineage_proof = LineageProof(parent_coin_record.coin.parent_coin_info, parent_inner_puzzlehash, 1)
            if unft.supports_did:
                innersol = Program.to([innersol])

            nft_layer_solution: Program = Program.to([innersol])

            if unft.supports_did:
                inner_puzzle = nft_puzzles.recurry_nft_puzzle(unft, puzzle_and_solution.solution.to_program(), p2_puzzle)
            else:
                inner_puzzle = p2_puzzle

            assert unft.singleton_launcher_id == nft_launcher_id

            full_puzzle = nft_puzzles.create_full_puzzle(unft.singleton_launcher_id, unft.metadata, unft.metadata_updater_hash, inner_puzzle)
            assert full_puzzle.get_tree_hash().hex() == coin_record.coin.puzzle_hash.hex()

            assert isinstance(lineage_proof, LineageProof)
            singleton_solution = Program.to([lineage_proof.to_program(), 1, nft_layer_solution])
            coin_spend = make_spend(coin_record.coin, full_puzzle, singleton_solution)

            nft_spend_bundle = await sign_coin_spends([coin_spend], wallet_keyf, 
                                    self.get_synthetic_private_key_for_puzzle_hash, 
                                    AGG_SIG_ME_ADDITIONAL_DATA, MAX_BLOCK_COST_CLVM, [puzzle_hash_for_synthetic_public_key])

            if logger.isEnabledFor(logging.DEBUG):
                with open(f"./spend.json", "w") as f:
                    f.write(json.dumps(nft_spend_bundle.to_json_dict()))

            return nft_spend_bundle, inner_puzzle.get_tree_hash()
        else:
            raise RuntimeError("unexpected outcome of NFT transfer")


    # transfer an NFT, held by a p2 singleton, to a new destination
    async def make_transfer_nft_p2_spend_bundle(self, singleton_inner_puzzle, singleton_coin_id, nft_launcher_id: bytes32,
                                                 p2_puzzle: Program, recipient_puzzlehash: bytes32=OFFER_MOD_HASH) -> SpendBundle:
        logger.info(f"Transferring p2 singleton NFT {encode_puzzle_hash(nft_launcher_id, 'nft')} to {encode_puzzle_hash(recipient_puzzlehash, PREFIX)}")
        nft_launcher_coin_record = await self.node_client.get_coin_record_by_name(nft_launcher_id)
        assert nft_launcher_coin_record is not None
        coin_record = await self.find_unspent_descendant(nft_launcher_coin_record)
        logger.debug(f"Transferring p2 coin with ID {coin_record.coin.name().hex()}")
        assert coin_record is not None
        parent_coin_record = await self.node_client.get_coin_record_by_name(coin_record.coin.parent_coin_info)
        assert parent_coin_record is not None
        puzzle_and_solution: CoinSpend = await self.node_client.get_puzzle_and_solution(coin_id=coin_record.coin.parent_coin_info, height=parent_coin_record.spent_block_index)
        parent_puzzle_reveal = puzzle_and_solution.puzzle_reveal

        nft_program = Program.from_bytes(bytes(parent_puzzle_reveal))
        unft = UncurriedNFT.uncurry(*nft_program.uncurry())
        parent_inner_puzzlehash = unft.nft_state_layer.get_tree_hash()

        assert unft is not None, "Could not find uncurried NFT"

        innersol = None

        if unft is not None:
            info = NFTInfo.from_json_dict((await self.wallet_client.get_nft_info(coin_record.name.hex()))["nft_info"])
            if unft.owner_did != info.owner_did:
                logger.warning(f"DID mismatch in make_transfer_nft_p2_spend_bundle ({encode_puzzle_hash(nft_launcher_id, 'nft')}): unft: {unft.owner_did.hex() if unft.owner_did is not None else None}, info: {info.owner_did.hex() if info.owner_did is not None else None}")

            nft_ownership_puzzle: Program = create_ownership_layer_puzzle(nft_launcher_id, info.owner_did,
                                                                           p2_puzzle, unft.trade_price_percentage, unft.royalty_address)
            nft_singleton_inner_puzzle = create_nft_layer_puzzle_with_curry_params(unft.metadata, unft.metadata_updater_hash, nft_ownership_puzzle)
            full_puzzle = create_full_puzzle_with_nft_puzzle(nft_launcher_id, nft_singleton_inner_puzzle)
            logger.info(f"Preparing p2 spend for NFT at {full_puzzle.get_tree_hash()}")
            assert full_puzzle.get_tree_hash().hex() == coin_record.coin.puzzle_hash.hex()
    
            logger.debug(f"Singleton inner puzzle hash: {nft_singleton_inner_puzzle.get_tree_hash()}")

            p2_solution = Program.to([singleton_inner_puzzle.get_tree_hash(), singleton_coin_id, nft_launcher_id,
                                      nft_singleton_inner_puzzle.get_tree_hash(), coin_record.coin.amount, recipient_puzzlehash])
            innersol = p2_solution

            lineage_proof = LineageProof(parent_coin_record.coin.parent_coin_info, parent_inner_puzzlehash, 1)
            if unft.supports_did:
                innersol = Program.to([innersol])

            nft_layer_solution: Program = Program.to([innersol])

            assert unft.singleton_launcher_id == nft_launcher_id

            assert isinstance(lineage_proof, LineageProof)
            singleton_solution = Program.to([lineage_proof.to_program(), 1, nft_layer_solution])

            coin_spend = make_spend(coin_record.coin, full_puzzle, singleton_solution)

            nft_spend_bundle = await sign_coin_spends([coin_spend], wallet_keyf,
                        self.get_synthetic_private_key_for_puzzle_hash,
                        AGG_SIG_ME_ADDITIONAL_DATA, MAX_BLOCK_COST_CLVM, [puzzle_hash_for_synthetic_public_key])

            if logger.isEnabledFor(logging.DEBUG):
                with open("./spend.json", "w") as f:
                    f.write(json.dumps(nft_spend_bundle.to_json_dict()))

            return nft_spend_bundle


    # accept an offer by transferring ephemeral coin from OFFER_MOD_HASH
    # returns - Tuple of Spend Bundle and NFT singleton inner puzzlehash
    async def make_accept_offer_nft_spend_bundle(self, parent_coin_spend: CoinSpend, nonce: bytes32, nft_launcher_id: bytes32, puzzle: Program, recipient_puzzlehash: bytes32, owner_did=None, fee_amount:int=0) -> Tuple[SpendBundle, bytes32]:
        logger.info(f"Transferring offered NFT {encode_puzzle_hash(nft_launcher_id, 'nft')} to {encode_puzzle_hash(recipient_puzzlehash, PREFIX)}")
        nft_launcher_coin_record = await self.node_client.get_coin_record_by_name(nft_launcher_id)
        assert nft_launcher_coin_record is not None

        # in the case of the ephemeral spend, the blockchain doesn't see this as spent, but we know it is in the process of being spent so we interact with the pending CoinSpend
        nft_program = Program.from_bytes(bytes(parent_coin_spend.puzzle_reveal))
        unft = UncurriedNFT.uncurry(*nft_program.uncurry())

        nft_inner_puzzle: Program = await self.nft_inner_puzzle_from_spend(parent_coin_spend, puzzle)
        nft_singleton_inner_puzzle = create_nft_layer_puzzle_with_curry_params(unft.metadata, unft.metadata_updater_hash, nft_inner_puzzle)
        full_puzzle = create_full_puzzle_with_nft_puzzle(nft_launcher_id, nft_singleton_inner_puzzle)

        ephemeral_coin: Coin = Coin(parent_coin_spend.coin.name(), full_puzzle.get_tree_hash(), 1)

        assert ephemeral_coin.puzzle_hash.hex() == full_puzzle.get_tree_hash().hex()

        notarized_payment = (nonce, [[recipient_puzzlehash, 1, [recipient_puzzlehash]]])
        innersol = Program.to([notarized_payment])

        lineage_proof = lineage_proof_for_coinsol(parent_coin_spend)

        if unft.supports_did:
            innersol = Program.to([innersol])

        nft_layer_solution: Program = Program.to([innersol])

        assert unft.singleton_launcher_id == nft_launcher_id

        assert isinstance(lineage_proof, LineageProof)
        singleton_solution = Program.to([lineage_proof.to_program(), 1, nft_layer_solution])

        coin_spend = make_spend(ephemeral_coin, full_puzzle, singleton_solution)
        spends = [coin_spend]

        if fee_amount > 0:
            coins: List[Coin] = await select_coins(self.wallet_client, fee_amount)
            fee_coin: Coin = coins[0]
            change_puzzlehash = fee_coin.puzzle_hash
            
            primaries = []
            primaries.append(Payment(change_puzzlehash, coins[0].amount - fee_amount, change_puzzlehash))

            logger.info(f'Making coin spend with fees: {fee_amount}')
            wallet = Wallet()
            solution = wallet.make_solution(
                primaries=primaries,
                fee=fee_amount
                # FIXME - explicit puzzle announcements would be ideal here.
                # as nasty as they are in Chialisp, they're worse in Python
            )
            fee_coin_puzzle = puzzle_for_coin(fee_coin)
            fee_coin_spend = make_spend(fee_coin, fee_coin_puzzle, solution)
            spends.append(fee_coin_spend)

        spend_bundle = await sign_coin_spends(spends, wallet_keyf,
                                self.get_synthetic_private_key_for_puzzle_hash,
                                AGG_SIG_ME_ADDITIONAL_DATA, MAX_BLOCK_COST_CLVM, [puzzle_hash_for_synthetic_public_key])
        return spend_bundle, nft_singleton_inner_puzzle.get_tree_hash()


    async def create_offer_a_for_b_as_spend_bundle(self, nonce: bytes32, p2_singleton: Program,
                                                   a_launcher_ids: List[bytes32], b_launcher_ids: List[bytes32],
                                                   singleton_launcher_id, singleton_coin_id: bytes32, singleton_inner_puzzle: Program,
                                                   nft_next_puzzlehashes: List[bytes32]) -> SpendBundle:
        spend_bundles = []

        release_coin_ids: List[bytes32] = []
        for a_launcher_id in a_launcher_ids:
            a_coin_id = (await self.find_unspent_descendant(await self.node_client.get_coin_record_by_name(a_launcher_id))).coin.name()
            release_coin_ids.append(a_coin_id)
            
        lock_coin_ids: List[bytes32] = []
        for b_launcher_id in b_launcher_ids:
            b_coin_id = (await self.find_unspent_descendant(await self.node_client.get_coin_record_by_name(b_launcher_id))).coin.name()
            lock_coin_ids.append(b_coin_id)

        i = 0
        for a_launcher_id in a_launcher_ids:
            coin_record: CoinRecord = await self.node_client.get_coin_record_by_name(a_launcher_id)
            coin_record = await self.find_unspent_descendant(coin_record)
            a_spend_bundle = await self.make_transfer_nft_p2_spend_bundle(singleton_inner_puzzle, singleton_coin_id, a_launcher_id, p2_singleton, OFFER_MOD_HASH)
            spend_bundles.append(a_spend_bundle)
            offer_spend_bundle, _ = await self.make_accept_offer_nft_spend_bundle(a_spend_bundle.coin_spends[0], nonce, a_launcher_id, OFFER_MOD, nft_next_puzzlehashes[i])
            spend_bundles.append(offer_spend_bundle)
            i += 1

        spend_bundles.append(await self.make_swap_spend_bundle(singleton_launcher_id, singleton_inner_puzzle, lock_coin_ids, b_launcher_ids,
                                                               release_coin_ids, a_launcher_ids, nft_next_puzzlehashes, True, nonce))
        spend_bundle = SpendBundle.aggregate(spend_bundles)
        return spend_bundle



    async def create_offer_b_for_a_as_spend_bundle(self, nonce: bytes32, p2_singleton: Program,
                                                   a_launcher_ids: List[bytes32], b_launcher_ids: List[bytes32],
                                                   singleton_launcher_id, singleton_coin_id: bytes32, singleton_inner_puzzle: Program,
                                                   nft_next_puzzlehashes: List[bytes32]) -> SpendBundle:
        spend_bundles = []

        release_coin_ids: List[bytes32] = []
        for b_launcher_id in b_launcher_ids:
            b_coin_id = (await self.find_unspent_descendant(await self.node_client.get_coin_record_by_name(b_launcher_id))).coin.name()
            release_coin_ids.append(b_coin_id)
            
        lock_coin_ids: List[bytes32] = []
        for a_launcher_id in a_launcher_ids:
            a_coin_id = (await self.find_unspent_descendant(await self.node_client.get_coin_record_by_name(a_launcher_id))).coin.name()
            lock_coin_ids.append(a_coin_id)

        i = 0
        for b_launcher_id in b_launcher_ids:
            coin_record: CoinRecord = await self.node_client.get_coin_record_by_name(b_launcher_id)
            coin_record = await self.find_unspent_descendant(coin_record)
            b_spend_bundle = await self.make_transfer_nft_p2_spend_bundle(singleton_inner_puzzle, singleton_coin_id, b_launcher_id, p2_singleton, OFFER_MOD_HASH)
            spend_bundles.append(b_spend_bundle)
            offer_spend_bundle, _ = await self.make_accept_offer_nft_spend_bundle(b_spend_bundle.coin_spends[0], nonce, b_launcher_id, OFFER_MOD, nft_next_puzzlehashes[i])
            spend_bundles.append(offer_spend_bundle)
            i += 1

        spend_bundles.append(await self.make_swap_spend_bundle(singleton_launcher_id, singleton_inner_puzzle, lock_coin_ids, a_launcher_ids,
                                                               release_coin_ids, b_launcher_ids, nft_next_puzzlehashes, False, nonce))
        spend_bundle = SpendBundle.aggregate(spend_bundles)
        return spend_bundle
    

    # singleton spend
    async def make_swap_spend_bundle(self, singleton_launcher_id, singleton_inner_puzzle,
                                     nft_coin_ids_to_lock: List[bytes32], nft_launcher_ids_to_lock,
                                     nft_coin_ids_to_unlock: List[bytes32], nft_launcher_ids_to_unlock,
                                     nft_next_puzzlehashes: List[bytes32], unlock_a: bool, nonce: bytes32) -> SpendBundle:
        singleton_child: Coin = await get_unspent_singleton_coin(self.node_client, singleton_launcher_id)
        logger.info(f"make_swap_spend_bundle for singleton: {singleton_child.name().hex()}")
        singleton_parent_record: CoinRecord = await self.node_client.get_coin_record_by_name(singleton_child.parent_coin_info)
        singleton_coinsol: CoinSpend = await self.node_client.get_puzzle_and_solution(singleton_parent_record.coin.name(),
                                                                                singleton_parent_record.spent_block_index)

        full_puzzle: Program = puzzle_for_singleton(singleton_launcher_id, singleton_inner_puzzle)
        assert full_puzzle.get_tree_hash().hex() == singleton_child.puzzle_hash.hex()

        nfts_to_lock = []
        i = 0
        for coin_id in nft_coin_ids_to_lock:
            nfts_to_lock.append(await self.lookup_nft_coin_details(nft_launcher_ids_to_lock[i], coin_id))
            i += 1

        nfts_to_unlock = []
        i = 0
        for coin_id in nft_coin_ids_to_unlock:
            nfts_to_unlock.append(await self.lookup_nft_coin_details(nft_launcher_ids_to_unlock[i], coin_id, nft_next_puzzlehashes[i]))
            i += 1

        inner_solution: Program = Program.to([
            singleton_child.name(), singleton_inner_puzzle.get_tree_hash(), singleton_child.amount,
            nfts_to_lock, nfts_to_unlock,
            unlock_a, nonce])
        
        lineage_proof: LineageProof = lineage_proof_for_coinsol(singleton_coinsol)

        full_solution: Program = solution_for_singleton(
            lineage_proof,
            SINGLETON_AMOUNT,
            inner_solution,
        )

        singleton_claim_coinsol: CoinSpend = make_spend(
            singleton_child,
            SerializedProgram.from_program(full_puzzle),
            SerializedProgram.from_program(full_solution)
        )

        spend_bundle = await sign_coin_spends([singleton_claim_coinsol], wallet_keyf,
                                              self.get_synthetic_private_key_for_puzzle_hash,
                                AGG_SIG_ME_ADDITIONAL_DATA, MAX_BLOCK_COST_CLVM, [puzzle_hash_for_synthetic_public_key])
        return spend_bundle


    # lookup_nft_coin_details
    # (coin_id nft_metadata_hash nft_did nft_transfer_program_hash target_inner_puzzlehash)
    async def lookup_nft_coin_details(self, launcher_id, coin_id, target_inner_puzzlehash=None):
        nft_coin_record: CoinRecord = await self.node_client.get_coin_record_by_name(coin_id)

        logger.debug(f"Coin with ID: {nft_coin_record.coin.name().hex()} has full puzzlehash: {nft_coin_record.coin.puzzle_hash.hex()}")

        parent_coin_record: CoinRecord = await self.node_client.get_coin_record_by_name(nft_coin_record.coin.parent_coin_info)
        assert parent_coin_record is not None
        puzzle_and_solution: CoinSpend = await self.node_client.get_puzzle_and_solution(
            coin_id=nft_coin_record.coin.parent_coin_info, height=parent_coin_record.spent_block_index)

        nft_program = Program.from_bytes(bytes(puzzle_and_solution.puzzle_reveal))
        unft = UncurriedNFT.uncurry(*nft_program.uncurry())

        # Because fusion deals with provenance, going to just require this for now
        assert unft.supports_did

        info = NFTInfo.from_json_dict((await self.wallet_client.get_nft_info(coin_id.hex()))["nft_info"])
        # unft insists on giving us a None owner_did... Need info too for now??
        if unft.owner_did != info.owner_did:
            logger.warning(f"DID mismatch in lookup_nft_coin_details ({encode_puzzle_hash(launcher_id, 'nft')}): unft: {unft.owner_did.hex() if unft.owner_did is not None else None}, info: {info.owner_did.hex() if info.owner_did is not None else None}")

        details = [coin_id, unft.metadata.get_tree_hash(), None, ###info.owner_did, ###None
                   unft.transfer_program.get_tree_hash()]
        logger.debug(f"Details: [{coin_id.hex()}, {unft.metadata.get_tree_hash()}, {info.owner_did}, {unft.transfer_program.get_tree_hash()}]")

        if target_inner_puzzlehash is not None:
            details.append(target_inner_puzzlehash)
        
        logger.debug(f"puzzleshash at OFFER_MOD: {(await self.full_puzzle_for_p2_puzzle(launcher_id, OFFER_MOD)).get_tree_hash()}")

        return details

 
    async def find_unspent_descendant(self, coin_record: CoinRecord) -> CoinRecord:
        if not coin_record.spent:
            return coin_record

        child: CoinRecord = (await self.node_client.get_coin_records_by_parent_ids([coin_record.coin.name()]))[0]
        if not child.spent:
            return child
        return await self.find_unspent_descendant(child)
    

    async def cli_deploy_singleton(self, nft_a_ids: str, nft_b_ids: str, fee_amount:int=1000) -> bytes32:
        logger.info(f"CLI: deploy singleton for NFT(s) A: [{nft_a_ids}] ; B: [{nft_b_ids}]")

        a_as_str_arr: List[str] = nft_a_ids.split(',')
        b_as_str_arr: List[str] = nft_b_ids.split(',')
        
        nft_a_launcher_ids: List[bytes32] = []
        nft_b_launcher_ids: List[bytes32] = []

        for a in a_as_str_arr:
            nft_a_launcher_ids.append(decode_puzzle_hash(a))
        for b in b_as_str_arr:
            nft_b_launcher_ids.append(decode_puzzle_hash(b))

        launcher_coin: Coin = await self.create_singleton_launcher(fee_amount)
        launcher_id = launcher_coin.name()

        p2_singleton = self.pay_to_singleton_puzzle(launcher_id)
        p2_puzzlehash = p2_singleton.get_tree_hash()

        singleton_struct = (SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH))
        inner_puzzle: Program = SINGLETON_INNER.curry(singleton_struct, p2_puzzlehash,
                                                      OFFER_MOD_HASH, NFT_STATE_LAYER_MOD_HASH, NFT_OWNERSHIP_LAYER_HASH, NFT_METADATA_UPDATER_PUZZLE_HASH_HASH,
                                                      nft_a_launcher_ids, nft_b_launcher_ids)
        return await self.deploy_singleton(launcher_coin, inner_puzzle, nft_a_launcher_ids, nft_b_launcher_ids, fee_amount)


    # mint a fake NFT
    async def cli_mint(self, count=1):
        for i in range(count):
            did_id, _ = await self.create_did()
            await self.mint_nft(did_id, puzzle_for_pk(wallet_keys[0].get_g1()).get_tree_hash(), i)


    async def cli_check_singleton(self, launcher_id: str):
        launcher_id_bytes: bytes32 = bytes32.from_hexstr(launcher_id)
        launchers_a, launchers_b = await self.get_nft_launcher_ids_from_extra_data(launcher_id_bytes)
        logger.info("*********************************************************")
        logger.info("Check deployed singleton...")
        logger.info(f"    launcher_id: {launcher_id_bytes.hex()}")
        logger.info(f"    p2_singleton_address: {encode_puzzle_hash(self.pay_to_singleton_puzzle(launcher_id_bytes).get_tree_hash(), PREFIX)}")
        
        logger.info("NFT(s) A:")
        for a in launchers_a:
            logger.info("\t" + encode_puzzle_hash(a, "nft"))
        logger.info("NFT(s) B:")
        for b in launchers_b:
            logger.info("\t" + encode_puzzle_hash(b, "nft"))
        logger.info("*********************************************************")


    async def create_did(self) -> Tuple[str, bytes32]:
        logger.info("Creating DID wallet")
        res = await self.wallet_client.create_new_did_wallet(1)
        assert res["success"] is True
        did_id = res.get("my_did")
        did_coin_id = decode_puzzle_hash(did_id)
        did_launcher_coin_record = None
        did_launcher_coin_record = await self.wait_for_coin_record(did_coin_id)

        did_coin_record = await self.find_unspent_descendant(did_launcher_coin_record)
        assert did_coin_record is not None
        did_coin_parent = await self.node_client.get_coin_record_by_name(did_coin_record.coin.parent_coin_info)
        self.record_spent_coin(did_launcher_coin_record.coin)
        self.record_spent_coin(did_coin_record.coin)
        self.record_spent_coin(did_coin_parent.coin)

        logger.debug(f"DID_ID: {did_id}")

        return did_id, did_coin_id


    # Wait for a coin record to become visible after creation - handles block farming delays
    async def wait_for_coin_record(self, coin_id: bytes32) -> CoinRecord:
        coin_record: CoinRecord = None
        for i in range(1, BACKOFF_RETRY_COUNT):
            if i % 5 == 0: ## keep log noise down - for happy paths (immediate block farming), this might log nothing.
                logger.warning(f"Waiting for coin record...{coin_id.hex()}")
            coin_record = await self.node_client.get_coin_record_by_name(coin_id)
            sleep(i * BACKOFF_RETRY_WAIT_SECS)
            if coin_record is not None:
                break
        assert coin_record is not None
        return coin_record


    # acknowledgment and thank you to Chia's test_nft_wallet.py
    async def mint_nft(self, did_id: str, recipient_puzzlehash: bytes32, suffix:int=1) -> bytes32:
        logger.info("Minting a fake NFT")

        wallet_client: WalletRpcClient = self.wallet_client
        node_client = self.node_client

        res = await wallet_client.create_new_nft_wallet(did_id=did_id)
        assert res.get("success")
        wallet_id = res["wallet_id"]

        data_hash_param = "0xD4584AD463139FA8C0D9F68F4B59F185"
        meta_hash_param = "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        address = encode_puzzle_hash(recipient_puzzlehash, prefix=PREFIX)

        tx_config = TXConfig(min_coin_amount=1, max_coin_amount=MAX_COIN_AMOUNT, excluded_coin_amounts=[], excluded_coin_ids=[], reuse_puzhash=True)

        res = await wallet_client.mint_nft(
            wallet_id,
            address,
            address,
            data_hash_param,
            [f"https://example.com/img/{suffix}"],
            meta_hash=meta_hash_param,
            meta_uris=[f"https://example.com/meta/{suffix}"],
            tx_config=tx_config,
            did_id=did_id,
        )
        assert res.get("success")

        # tell the fusion.py we are pulling coins out from under it
        # this could include NFT minting, DID creation, change handling

        coin_spends = res.get("spend_bundle").get("coin_spends")
        for solution in coin_spends:
            coin = solution.get("coin")
            if coin:
                parent_info = bytes32.from_hexstr(coin.get("parent_coin_info"))
                coin_records = await node_client.get_coin_records_by_parent_ids([parent_info])
                for coin_record in coin_records:
                    self.record_spent_coin(coin_record.coin)

        nft_id = res.get("nft_id")
        launcher_id = decode_puzzle_hash(nft_id)
        logger.info(f" {nft_id} -> {launcher_id}")
        return launcher_id

    
    async def get_nft_launcher_ids_from_extra_data(self, launcher_id: bytes32):
        launcher_coin_record = await self.node_client.get_coin_record_by_name(launcher_id)
        launcher_coin_spend: CoinSpend = await self.node_client.get_puzzle_and_solution(launcher_coin_record.coin.name(), launcher_coin_record.spent_block_index)

        # we store critical information about the puzzle on-chain via the launcher's extra_data (solution parameters exceeding what it will read)
        extra_data = Program.from_bytes(bytes(launcher_coin_spend.solution)).rest().rest().rest().first()
        ##logger.info(f"Found extra_data: {extra_data}")

        nft_a_launcher_ids = extra_data.as_python()[1]
        nft_b_launcher_ids = extra_data.as_python()[2]
        assert nft_a_launcher_ids is not None and nft_b_launcher_ids is not None, "NFTs must be resolvable from extra_data"

        return nft_a_launcher_ids, nft_b_launcher_ids


    async def make_offer_bundle_json(self, launcher_id: bytes32, a_or_b: str, fee: int=0) -> str:
        payload: Dict = {}
        offer_dict, driver_dict = await self.make_offer_bundle(launcher_id, a_or_b)
        payload["offer"] = offer_dict
        payload["driver_dict"] = driver_dict

        if fee > 0:
            payload["fee"] = fee

        return json.dumps(payload)
    

    # a_or_b 'a'|'b' - which one is being requested
    # returns - tuple of offer_dict, driver_dict
    async def make_offer_bundle(self, launcher_id: bytes32, a_or_b: str) -> tuple[Dict, Dict]:
        nft_a_launcher_ids, nft_b_launcher_ids = await self.get_nft_launcher_ids_from_extra_data(launcher_id)
        offer_dict = {}
        driver_dict = {}

        a_factor = 1 if a_or_b == 'a' else -1
        b_factor = 1 if a_or_b == 'b' else -1

        for a in nft_a_launcher_ids:
            offer_dict[a.hex()] = a_factor
            a_driver = await self.get_driver_dict(a)
            driver_dict.update(a_driver)

        for b in nft_b_launcher_ids:
            offer_dict[b.hex()] = b_factor
            b_driver = await self.get_driver_dict(b)
            driver_dict.update(b_driver)

        return offer_dict, driver_dict
    

    async def get_driver_dict(self, coin_id: bytes32) -> Dict:
        driver_dict = {}
        info = NFTInfo.from_json_dict((await self.wallet_client.get_nft_info(coin_id.hex()))["nft_info"])
        id = info.launcher_id.hex()
        assert isinstance(id, str)
        driver_dict[id] = {
            "type": "singleton",
            "launcher_id": "0x" + id,
            "launcher_ph": "0x" + info.launcher_puzhash.hex(),
            "also": {
                "type": "metadata",
                "metadata": info.chain_info,
                "updater_hash": "0x" + info.updater_puzhash.hex(),
            },
        }
        if info.supports_did:
            assert info.royalty_puzzle_hash is not None
            assert info.royalty_percentage is not None
            driver_dict[id]["also"]["also"] = {
                "type": "ownership",
                "owner": "0x" + info.owner_did.hex() if info.owner_did is not None else "()",
                "transfer_program": {
                    "type": "royalty transfer program",
                    "launcher_id": "0x" + info.launcher_id.hex(),
                    "royalty_address": "0x" + info.royalty_puzzle_hash.hex(),
                    "royalty_percentage": str(info.royalty_percentage),
                },
            }
        return driver_dict


    async def swap(self, launcher_id: bytes32, offer: str, fee_amount:int=0):
        logger.info("******************************************************************************************************************")
        logger.info(f"Accepting offer at singleton: {launcher_id.hex()}")
        logger.info(f"offer: {offer}")

        a_ids, b_ids = await self.get_nft_launcher_ids_from_extra_data(launcher_id)
        assert len(a_ids) > 0
        assert len(b_ids) > 0

        logger.info("*********************************************************")

        logger.info("Swapping...")

        logger.info("NFT(s) A:")
        for a in a_ids:
            logger.info("\t" + encode_puzzle_hash(a, "nft"))
        logger.info("NFT(s) B:")
        for b in b_ids:
            logger.info("\t" + encode_puzzle_hash(b, "nft"))
        logger.info("*********************************************************")

        nft_next_puzzlehashes: List[bytes32] = []

        offer: Offer = Offer.from_bech32(offer)

        nonce: bytes32 = None
        logger.debug("Offer debug: ")
        for _, payments in offer.requested_payments.items():
            nonce = payments[0].nonce
            for p in payments:
                # assumption here is that offer requests NFTs in the same order as the singleton is curried.
                # If this doesn't hold, we'll need to modify the driver
                nft_next_puzzlehash = p.memos[0]
                nft_next_puzzlehashes.append(nft_next_puzzlehash)
                logger.info(f"Found nft_next_puzzlehash: {nft_next_puzzlehash.hex()}")

                msg: bytes32 = Program.to((p.nonce, [p.as_condition_args() for p in payments])).get_tree_hash()
                logger.info(f"Announcement msg (not combined with puzzle): {msg.hex()}")

                logger.debug(f"payment: {p}")
                logger.debug(f"Offer memos: {Program.to(p.memos)}")

        logger.debug(f"Offer nonce: {nonce.hex()}")
        
        logger.debug(f"Offer driver_dict: {offer.driver_dict}")

        logger.debug(f"Offer requested_payments: {offer.requested_payments}")

        announcements: List[Announcement] = Offer.calculate_announcements(offer.requested_payments, offer.driver_dict)

        with open("./offer.json", "w") as f:
             f.write(json.dumps(Offer.to_spend_bundle(offer).to_json_dict()))
        with open("./offer.txt", "w") as f:
             f.write(offer.to_bech32())

        logger.debug("User offer requests:")
        for asset_id, payment in offer.requested_payments.items():
            logger.debug(f"asset_id: {asset_id}, payment: {payment}") 

        user_offer_spend_bundle = self.to_spend_bundle(offer)

        offers_spend_bundle = SpendBundle([], G2Element())

        p2_singleton: Program = self.pay_to_singleton_puzzle(launcher_id)

        a_matches: bool = False
        b_matches: bool = False

        for spend in user_offer_spend_bundle.coin_spends:
            nft_program = Program.from_bytes(bytes(spend.puzzle_reveal))
            unft = UncurriedNFT.uncurry(*nft_program.uncurry())
            if unft is not None and unft.singleton_launcher_id in b_ids:
                b_launcher_id = unft.singleton_launcher_id
                accept_offer_spend_bundle, _ = await self.make_accept_offer_nft_spend_bundle(spend, nonce, b_launcher_id, OFFER_MOD, p2_singleton.get_tree_hash(), fee_amount)
                offers_spend_bundle = SpendBundle.aggregate([offers_spend_bundle, accept_offer_spend_bundle])
                logger.info("User offer presents B (fusion)")
                b_matches = True
            elif unft is not None and unft.singleton_launcher_id in a_ids:
                a_launcher_id = unft.singleton_launcher_id
                accept_offer_spend_bundle, _ = await self.make_accept_offer_nft_spend_bundle(spend, nonce, a_launcher_id, OFFER_MOD, p2_singleton.get_tree_hash(), fee_amount)
                offers_spend_bundle = SpendBundle.aggregate([offers_spend_bundle, accept_offer_spend_bundle])
                a_matches = True
                logger.info("User offer presents A (defusion)")
            else:
                logger.warning("Found offer spend but couldn't match to NFT!!!")

        if a_matches and b_matches:
            logger.warning("Strange offer encountered - trying to spend A and B. Aborting")
            raise RuntimeError("Strange offer. Aborting.")

        launcher_coin_record: CoinRecord = await self.node_client.get_coin_record_by_name(launcher_id)
        singleton_coin_record: CoinRecord = await self.find_unspent_descendant(launcher_coin_record)
        
        singleton_struct = (SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH))
        singleton_inner_puzzle: Program = SINGLETON_INNER.curry(singleton_struct, p2_singleton.get_tree_hash(),
                                                                OFFER_MOD_HASH, NFT_STATE_LAYER_MOD_HASH, NFT_OWNERSHIP_LAYER_HASH, NFT_METADATA_UPDATER_PUZZLE_HASH_HASH,
                                                                a_ids, b_ids)
        spend_bundle2 = None
        if b_matches: #fusion
            spend_bundle2 = await self.create_offer_a_for_b_as_spend_bundle(nonce, p2_singleton, a_ids, b_ids, launcher_id, singleton_coin_record.coin.name(),
                                                                            singleton_inner_puzzle, nft_next_puzzlehashes)
        elif a_matches: #defusion
            spend_bundle2 = await self.create_offer_b_for_a_as_spend_bundle(nonce, p2_singleton, a_ids, b_ids, launcher_id, singleton_coin_record.coin.name(),
                                                                            singleton_inner_puzzle, nft_next_puzzlehashes)

        spend_bundle = SpendBundle.aggregate([user_offer_spend_bundle, offers_spend_bundle, spend_bundle2])

        if logger.isEnabledFor(logging.DEBUG):
            with open("./spend.json", "w") as f:
                f.write(json.dumps(spend_bundle.to_json_dict()))

        status = await self.node_client.push_tx(spend_bundle)
        logger.info(f"* * * * {status}")

        logger.info("******************************************************************************************************************")


    def to_spend_bundle(self, offer: Offer) -> SpendBundle:
        offer_valid_spends = []
        spend_bundle = offer.to_spend_bundle()
        for spend in spend_bundle.coin_spends:
            if spend.coin.parent_coin_info == b"\x00" * 32: #hint for offer
                continue
            else:
                offer_valid_spends.append(spend)
        result = SpendBundle(offer_valid_spends, spend_bundle.aggregated_signature)
        return result


def print_json(a_dict):
    logger.info(json.dumps(a_dict, sort_keys=True, indent=4))


def wallet_keyf(pk):
    logger.info(f'Looking for wallet keys to sign spend, PK: {pk}')
    for wallet_key in wallet_keys:
        synth_key = calculate_synthetic_secret_key(wallet_key, DEFAULT_HIDDEN_PUZZLE_HASH)
        if synth_key.get_g1() == pk:
            logger.info('Found key!')
            return synth_key
    raise RuntimeError("Evaluated all keys without finding PK match!")


def puzzle_for_coin(coin: Coin) -> Program:
    puzzle_reveal = None
    puzzle_reveal = puzzle_reveals.get(coin.puzzle_hash, None)
    if puzzle_reveal is None:
        raise RuntimeError("Checked all known keys for valid puzzle reveal. Failed to find any.")
    return puzzle_reveal


async def select_coins(wallet_client: WalletRpcClient, amount: uint64):
    excluded_coin_ids = [c.name() for c in recent_coins]
    coin_selection_config = CoinSelectionConfig(min_coin_amount=1, max_coin_amount=MAX_COIN_AMOUNT, excluded_coin_amounts=[], excluded_coin_ids=excluded_coin_ids)
    coins: List[Coin] = await wallet_client.select_coins(amount=amount, wallet_id=1, coin_selection_config=coin_selection_config)
    logger.info(f'Selecting coins, will exclude {len(excluded_coin_ids)} coins recently spent')
    assert len(coins) >= 1
    logger.info(f'Selected {len(coins)} coins')
    for coin in coins:
        logger.info(f'coin: {coin.name().hex()}, amount: {coin.amount}')
        recent_coins.append(coin)
    return coins


async def get_unspent_singleton_coin(node_client: FullNodeRpcClient, launcher_id: bytes32) -> Coin:
    # TODO optimize to use hinting
    coin_record: CoinRecord = await node_client.get_coin_record_by_name(launcher_id)
    assert coin_record is not None and coin_record.spent_block_index != 0
    logger.info(f'Found spent launcher coin: {coin_record.coin.name().hex()}')

    while coin_record is None or coin_record.spent_block_index != 0:
        coin_record = (await node_client.get_coin_records_by_parent_ids([coin_record.coin.name()]))[0]

    logger.info(f'Found unspent singleton: {coin_record.coin.name().hex()} at puzzlehash: {coin_record.coin.puzzle_hash.hex()}')

    return coin_record.coin


def usage():
    logger.info("Usage: FINGERPRINT=<WALLET_FINGERPRINT> python fusion.py <mint>|<deploy NFT_A_ID(s) NFT_B_ID(s)>|<check LAUNCHER_ID>|<swap LAUNCHER_ID OFFER_FILE_TEXT>\n")
    sys.exit(1)


async def main():
    arg_count = len(sys.argv)
    if(arg_count < 2 or arg_count > 4):
        usage()
        sys.exit(1)

    fingerprint = int(os.environ.get("FINGERPRINT", None))
    fusion = Fusion()
    await fusion.init()
    fusion.load_keys(fingerprint)

    try:
        if sys.argv[1] == "deploy":
            if arg_count < 4:
                usage()
            nft_a_ids: str = sys.argv[2]
            nft_b_ids: str = sys.argv[3]
            if nft_a_ids is None or nft_b_ids is None or not nft_a_ids.startswith("nft") or not nft_b_ids.startswith("nft"):
                usage()
            await fusion.cli_deploy_singleton(nft_a_ids, nft_b_ids)
        elif sys.argv[1] == "swap":
            if arg_count < 4 or arg_count > 4:
                usage()
            launcher_id: bytes32 = bytes32.from_hexstr(sys.argv[2])
            offer: str = sys.argv[3]
            await fusion.swap(launcher_id, offer)
        elif sys.argv[1] == "check":
            if arg_count > 3:
                usage()
            launcher_id: str = sys.argv[2]
            await fusion.cli_check_singleton(launcher_id)
        elif sys.argv[1] == "mint":
            count = 1
            if arg_count > 3:
                usage()
            if arg_count == 3:
                count = int(sys.argv[2])
            await fusion.cli_mint(count)
    except Exception as e:
        logger.info(e)
        logger.info(f'Failed on: {traceback.format_exc(e)}')
    finally:
        await fusion.close()


if __name__ == "__main__":
    asyncio.run(main())
