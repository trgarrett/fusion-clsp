import pytest

from chia.consensus.default_constants import DEFAULT_CONSTANTS
MAX_BLOCK_COST_CLVM = DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM

from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.wallet.nft_wallet.nft_puzzles import (
    NFT_METADATA_UPDATER,
    NFT_STATE_LAYER_MOD_HASH, NFT_OWNERSHIP_LAYER_HASH
)
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH
)

PREPEND_ENTRIES_MOD: Program = load_clvm("test_prepend_entries_to_lists.clsp", package_or_requirement="clsp", recompile=True)

CALCULATE_NFT_FULL_PUZZLE_HASH_MOD: Program = load_clvm("test_calculate_nft_full_puzzle_hash.clsp", package_or_requirement="clsp", recompile=True)
CALCULATE_NFT_OWNERSHIP_LAYER_PUZZLE_HASH_MOD: Program = load_clvm("test_calculate_nft_ownership_layer_puzzle_hash.clsp", package_or_requirement="clsp", recompile=True)

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
    async def test_calculate_nft_ownership_layer_puzzle_hash(self):
        # using NFT from mainnet
        result: Program = CALCULATE_NFT_OWNERSHIP_LAYER_PUZZLE_HASH_MOD.run([
            NFT_OWNERSHIP_LAYER_HASH,
            Program.to([]),  # current owner
            bytes32.from_hexstr("0x3a4029c2fbca8c96c74512442d479ae7648d9d2bbba0123bb231c55598bb7ea5"), # transfer program hash
            bytes32.from_hexstr("0xb47861cfd1ec8e722283e6758fefdb9a23e3f36cb10d7a6778b47a17061a5dbb") # inner puzzlehash
        ])
        expected: Program = Program.to(bytes32.from_hexstr("0x5bf47b4ac39c66c5fd2247a623acc22500254d2574d0b4496ec9ed36cd3c1847"))
        assert expected == result

    @pytest.mark.asyncio
    async def test_calculate_nft_ownership_layer_puzzle_hash_2(self):
        # using NFT that was problematic for troubleshooting in simulator
        result: Program = CALCULATE_NFT_OWNERSHIP_LAYER_PUZZLE_HASH_MOD.run([
            NFT_OWNERSHIP_LAYER_HASH,
            Program.to(bytes32.from_hexstr("0xdd44ce3a68d5efe4bd1981979c2bcb906405a494952286710627d241f07c61b0")),  # current owner
            bytes32.from_hexstr("0xf47061827ce4ef4d5d7ae537695133a34b62a53353a865db0b09061288af29bd"), # transfer program hash
            bytes32.from_hexstr("0x556c22e6a209998508e330da1a25b0cf786a0b42055bf3eaf0d45ec900b45c02") # inner puzzlehash
        ])
        expected: Program = Program.to(bytes32.from_hexstr("3fee3a5f1c7c83207c98b35203fa4a2e8775ade3746d3022aa02fdd9a1fe8393"))
        assert expected == result

    @pytest.mark.asyncio
    async def test_prepend_entries_to_lists_empty(self):
        l1 = []
        l2 = []
        result: Program = PREPEND_ENTRIES_MOD.run([l1, l2])
        expected: Program = Program.to([])
        assert expected == result

    @pytest.mark.asyncio
    async def test_prepend_entries_to_lists_unbalanced(self):
        l1 = []
        l2 = [1]
        with pytest.raises(ValueError):
            PREPEND_ENTRIES_MOD.run([l1, l2])

    @pytest.mark.asyncio
    async def test_prepend_entries_to_lists_one(self):
        l1 = [1]
        l2 = [2]
        result: Program = PREPEND_ENTRIES_MOD.run([l1, l2])
        expected: Program = Program.to([(1, 2)])
        assert expected == result

    @pytest.mark.asyncio
    async def test_prepend_entries_to_lists_four(self):
        l1 = [1, 2, 5, 9]
        l2 = [3, 4, 7, 11]
        result: Program = PREPEND_ENTRIES_MOD.run([l1, l2])
        expected: Program = Program.to([(1, 3), (2, 4), (5, 7), (9, 11)])
        assert expected == result


