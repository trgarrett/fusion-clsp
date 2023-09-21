import pytest
import pytest_asyncio

from chia.consensus.default_constants import DEFAULT_CONSTANTS
MAX_BLOCK_COST_CLVM = DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM

from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.util.ints import uint64
from chia.wallet.puzzles.load_clvm import load_clvm

CALCULATE_COIN_ID_FROM_LINEAGE_PROOF_MOD: Program = load_clvm("test_calculate_coin_id_from_lineage_proof.clsp", package_or_requirement="clsp", recompile=True)

LIST_OF_PAIRS_MOD: Program = load_clvm("test_list_of_pairs.clsp", package_or_requirement="clsp", recompile=True)

class TestNftUtils:

    @pytest.mark.asyncio
    async def test_calculate_coin_id_from_lineage_proof_nil(self):
        with pytest.raises(ValueError):
            nft_lineage_proof = []
            CALCULATE_COIN_ID_FROM_LINEAGE_PROOF_MOD.run([nft_lineage_proof])
            assert False # should be unreachable

    @pytest.mark.asyncio
    async def test_calculate_coin_id_from_lineage_proof_one(self):
        nft_lineage_proof = [
            bytes32.from_hexstr("0x0d5b5e3c559b2256780630018887e089a174ef0e6a085dd1ff4e019901f22a38"),
        ]
        coin_id: Program = CALCULATE_COIN_ID_FROM_LINEAGE_PROOF_MOD.run([nft_lineage_proof])
        assert bytes32.from_hexstr("0x0d5b5e3c559b2256780630018887e089a174ef0e6a085dd1ff4e019901f22a38") == bytes32.from_bytes(coin_id.as_python())

    @pytest.mark.asyncio
    async def test_calculate_coin_id_from_lineage_proof_two(self):
        nft_lineage_proof = [
            bytes32.from_hexstr("0x0d5b5e3c559b2256780630018887e089a174ef0e6a085dd1ff4e019901f22a38"),
            bytes32.from_hexstr("0xeb788d47494e49eff9a83eb808dfbb0665004b59f0c27116e56c8ec824d2857d"),
        ]
        coin_id: Program = CALCULATE_COIN_ID_FROM_LINEAGE_PROOF_MOD.run([nft_lineage_proof])
        assert bytes32.from_hexstr("0x9bc5d0b9e5e7c8cea610d376a9860a98bcd42e4e785e22bb04941060b3574750") == bytes32.from_bytes(coin_id.as_python())

    @pytest.mark.asyncio
    async def test_calculate_coin_id_from_lineage_proof_three(self):
        nft_lineage_proof = [
            bytes32.from_hexstr("0x0d5b5e3c559b2256780630018887e089a174ef0e6a085dd1ff4e019901f22a38"),
            bytes32.from_hexstr("0xeb788d47494e49eff9a83eb808dfbb0665004b59f0c27116e56c8ec824d2857d"),
            bytes32.from_hexstr("0x9f20586c5c113cd50a5337ece5bd61c8e09a612cd3226de053742590706a181c")
        ]
        cost, coin_id = CALCULATE_COIN_ID_FROM_LINEAGE_PROOF_MOD.run_with_cost(MAX_BLOCK_COST_CLVM, [nft_lineage_proof])
        assert bytes32.from_hexstr("0x45fc955335b98b98976a4d37583c6f0ac49d14b590eec349c6a7a5ed031e8409") == bytes32.from_bytes(coin_id.as_python())
        assert 13193 == cost


    @pytest.mark.asyncio
    async def test_calculate_coin_id_from_lineage_proof_deep(self):
        nft_lineage_proof = [
            bytes32.from_hexstr("0x0d5b5e3c559b2256780630018887e089a174ef0e6a085dd1ff4e019901f22a38"),
            bytes32.from_hexstr("0xeb788d47494e49eff9a83eb808dfbb0665004b59f0c27116e56c8ec824d2857d"),
            bytes32.from_hexstr("0x9f20586c5c113cd50a5337ece5bd61c8e09a612cd3226de053742590706a181c"),
            bytes32.from_hexstr("0xf7225388c1d69d57e6251c9fda50cbbf9e05131e5adb81e5aa0422402f048162"),
            bytes32.from_hexstr("0xfcf8cbf5fe5706bb9a0c4c0d4e7699271e7ef2dc388c3cabdccee0e2d3408f28"),
            bytes32.from_hexstr("0xce2baaf1ffe7720c04dd87b172d8cc8f302eb03bf691fe9c5cef901b9d8efdc4"),
            bytes32.from_hexstr("0x46f8ba4f59e527ca1c0b5361e60e1e407e767a63549f8bfbd6ee02f59d527f09"),
            bytes32.from_hexstr("0x91db805fad4ae4548866b0e0d2c6334ab044b6998f3f4c9672c47ccac136c094"),
            bytes32.from_hexstr("0x3902c6db65948d3c2d65166a70353aab941531038e24bf8fbe6668b56655d8d7"),
            bytes32.from_hexstr("0x06c4df81c2718d452ff7ed090a147080fd0b31ce39be1407135d0234292235b5"),
            bytes32.from_hexstr("0xc3ad43f7cac9288db9db3a3efe24ecd35561b5e72323081af1ea48a197226c90"),
            bytes32.from_hexstr("0xc5d2074163a236b086a8cc5498b3f5422d5d461a4bb18dcc51de1f0edf872094"),
            bytes32.from_hexstr("0xce79b120c2488ce976dca3ae5423154b077779f797dd3c939e89c3a7567c5cc9"),
            bytes32.from_hexstr("0x85a0dc13cd20f9c1a84068ac33d84f65877daea371dbe17b91c4361e4cfa29ed"),
            bytes32.from_hexstr("0xded69c4d86cf37cfecf989f182dd4a43bf512173b545f2e4002f1eef183ef437"),
            bytes32.from_hexstr("0x6ce0345db761567eb37512f9f5e1dc276dda1f07a7a2781cb4a825a83ef47686"),
            bytes32.from_hexstr("0x88ec949304bdc7d8b4763fedaaa2e025b47fdbfe64095f7cd59da5b7bb08cf7b"),
            bytes32.from_hexstr("0xf1a6ba2960ddaea5f747dd88e6cd9d447b352f730caa3b356cb24e51c1bd5dc6"),
            bytes32.from_hexstr("0x21c9ff9c68f6c56a0847240a75cd153406c279623806f25057677e58de5c4a5e"),
            bytes32.from_hexstr("0x7f9a02a81abc54518208366cdc41d6f6a85876a3645f7c3cf4f65e18b206e2e6"),
            bytes32.from_hexstr("0x784dbe8702b13ddb67d8fb0249330490f3271a7824d1206cc700446458b118cf"),
            bytes32.from_hexstr("0xf11dc364145183d4d735ffdf0fb3bb5ca8d6bdbc7aa15a567d12e239f0cd1d04"),
            bytes32.from_hexstr("0x09a3922c7d10368c82e419d442af68d7bbb64f4fb009735d3d736091e73bb632")
        ]
        cost, coin_id = CALCULATE_COIN_ID_FROM_LINEAGE_PROOF_MOD.run_with_cost(MAX_BLOCK_COST_CLVM, [nft_lineage_proof])
        assert bytes32.from_hexstr("0xbf85db16192d7725c257c4bff11c91c27e00e5a9c70104e2421b098e438ca5e1") == bytes32.from_bytes(coin_id.as_python())
        assert 143453 == cost

    @pytest.mark.asyncio
    async def test_list_of_pairs_empty(self):
        l1 = []
        l2 = []
        result: Program = LIST_OF_PAIRS_MOD.run([l1, l2])
        expected: Program = Program.to([])
        assert expected == result

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


