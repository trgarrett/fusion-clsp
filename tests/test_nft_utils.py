import pytest
import pytest_asyncio

from chia.consensus.default_constants import DEFAULT_CONSTANTS
MAX_BLOCK_COST_CLVM = DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM

from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.util.ints import uint64
from chia.wallet.nft_wallet.nft_puzzles import (
    NFT_METADATA_UPDATER,
    NFT_STATE_LAYER_MOD_HASH
)
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH
)

LIST_OF_PAIRS_MOD: Program = load_clvm("test_list_of_pairs.clsp", package_or_requirement="clsp", recompile=True)

CALCULATE_NFT_FULL_PUZZLE_HASH_MOD: Program = load_clvm("test_calculate_nft_full_puzzle_hash.clsp", package_or_requirement="clsp", recompile=True)

NFT_METADATA_UPDATER_PUZZLE_HASH: bytes32 = NFT_METADATA_UPDATER.get_tree_hash()
NFT_METADATA_UPDATER_PUZZLE_HASH_HASH: Program = Program.to(NFT_METADATA_UPDATER_PUZZLE_HASH).get_tree_hash()

class TestNftUtils:
    @pytest.mark.asyncio
    async def test_calculate_nft_full_puzzle_hash(self):
        # sanity check constants
        assert bytes32.from_hexstr("0xfe8a4b4e27a2e29a4d3fc7ce9d527adbcaccbab6ada3903ccf3ba9a769d2d78b") == NFT_METADATA_UPDATER_PUZZLE_HASH
        assert bytes32.from_hexstr("0x0d4e16e0415e44257c623e20c571a7755f76d8f0088b1e6cc71de67418a14689").hex() == NFT_METADATA_UPDATER_PUZZLE_HASH_HASH.hex()
        assert bytes32.from_hexstr("0xa04d9f57764f54a43e4030befb4d80026e870519aaa66334aef8304f5d0393c2").hex() == NFT_STATE_LAYER_MOD_HASH.hex()

        # using NFT from mainnet
        result: Program = CALCULATE_NFT_FULL_PUZZLE_HASH_MOD.run([
            SINGLETON_MOD_HASH,
            SINGLETON_LAUNCHER_HASH,
            NFT_STATE_LAYER_MOD_HASH,
            NFT_METADATA_UPDATER_PUZZLE_HASH_HASH, #METADATA_UPDATER_PUZZLE_HASH_HASH,
            bytes32.from_hexstr("0xd9eb1eb2bd59d44e937e44dbfd9d70f8c593893eae1f86e363764401fa58d802"), #launcher ID
            bytes32.from_hexstr("0x20cb70ba71c2eb58e23b163331909b28f5b105418799bf1637ae7ea10ea448d3"), #metadata hash
            bytes32.from_hexstr("0x5bf47b4ac39c66c5fd2247a623acc22500254d2574d0b4496ec9ed36cd3c1847") # inner puzzlehash
        ])
        expected: Program = Program.to(bytes32.from_hexstr("0xff6290d44d3de87d1532e31aec99f9afbf3c3a6e25106357c876691f838ee4ea"))
        assert expected == result

    @pytest.mark.asyncio
    async def test_list_of_pairs_empty(self):
        l1 = []
        l2 = []
        result: Program = LIST_OF_PAIRS_MOD.run([l1, l2])
        expected: Program = Program.to([])
        assert expected == result

    @pytest.mark.asyncio
    async def test_list_of_pairs_unbalanced(self):
        l1 = []
        l2 = [1]
        with pytest.raises(ValueError):
            LIST_OF_PAIRS_MOD.run([l1, l2])

    @pytest.mark.asyncio
    async def test_list_of_pairs_one(self):
        l1 = [1]
        l2 = [2]
        result: Program = LIST_OF_PAIRS_MOD.run([l1, l2])
        expected: Program = Program.to([[1, 2]])
        assert expected == result

    @pytest.mark.asyncio
    async def test_list_of_pairs_four(self):
        l1 = [1, 2, 5, 9]
        l2 = [3, 4, 7, 11]
        result: Program = LIST_OF_PAIRS_MOD.run([l1, l2])
        expected: Program = Program.to([[1, 3], [2, 4], [5, 7], [9, 11]])
        assert expected == result


