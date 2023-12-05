import pytest
import pytest_asyncio

from chia.consensus.default_constants import DEFAULT_CONSTANTS
MAX_BLOCK_COST_CLVM = DEFAULT_CONSTANTS.MAX_BLOCK_COST_CLVM

from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.util.ints import uint64
from chia.wallet.puzzles.load_clvm import load_clvm

LIST_OF_PAIRS_MOD: Program = load_clvm("test_list_of_pairs.clsp", package_or_requirement="clsp", recompile=True)

class TestNftUtils:

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


