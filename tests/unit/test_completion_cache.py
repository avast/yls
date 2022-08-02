# type: ignore

import yls.completion as comp


def test_cc_get_symbol_pe(completion_cache):
    symbol = completion_cache.get_symbol("pe")
    assert symbol.name == "pe"


def test_cc_get_symbol_function(completion_cache):
    symbol = completion_cache.get_symbol("cuckoo.filesystem.file_access")
    assert isinstance(symbol, comp.Function)
    assert symbol.name == "file_access"


def test_cc_get_symbol_value_constant(completion_cache):
    symbol = completion_cache.get_symbol("pe.MACHINE_ARM")
    assert isinstance(symbol, comp.Value)
    assert symbol.name == "MACHINE_ARM"
    symbol = completion_cache.get_symbol("pe.MACHINE_ARMNT")
    assert isinstance(symbol, comp.Value)
    assert symbol.name == "MACHINE_ARMNT"


def test_cc_get_symbol_array(completion_cache):
    symbol = completion_cache.get_symbol("elf.sections")
    assert isinstance(symbol, comp.Array)
    assert symbol.name == "sections"


def test_cc_get_symbol_errors(completion_cache):
    assert completion_cache.get_symbol("") is None
    assert completion_cache.get_symbol("a") is None
    assert completion_cache.get_symbol("p") is None
    assert completion_cache.get_symbol("pe-MACHINE_ARM64") is None
    assert completion_cache.get_symbol(" ") is None
    assert completion_cache.get_symbol(".") is None
    assert completion_cache.get_symbol("..") is None
    assert completion_cache.get_symbol("pe.this.that.invalid") is None
    assert completion_cache.get_symbol("pe.MACHINE_ARM64.i.am.not.struct") is None
    assert completion_cache.get_symbol("pe.MACHINE_ARM64.") is None


def test_cc_get_symbols_matching_root(completion_cache):
    assert completion_cache.get_symbols_matching("")


def test_cc_get_symbols_matching_m(completion_cache):
    symbols = completion_cache.get_symbols_matching("m")
    assert symbols
    for module in ("magic", "math"):
        assert any(symbol.name == module for symbol in symbols)


def test_cc_get_symbols_matching_elf(completion_cache):
    symbols = completion_cache.get_symbols_matching("elf")
    assert len(symbols) == 1
    assert symbols[0].name == "elf"


def test_cc_get_symbols_matching_value(completion_cache):
    symbols = completion_cache.get_symbols_matching("pe.MACHINE_ARM64")
    assert len(symbols) == 1
    assert symbols[0].name == "MACHINE_ARM64"


def test_cc_get_symbols_matching_arm_machine(completion_cache):
    symbols = completion_cache.get_symbols_matching("pe.MACHINE_ARM")
    assert len(symbols) == 3
    for machine in ("MACHINE_ARM", "MACHINE_ARM64", "MACHINE_ARMNT"):
        assert any(symbol.name == machine for symbol in symbols)


def test_cc_get_symbols_matching_long_invalid_path(completion_cache):
    symbols = completion_cache.get_symbols_matching("pe.MACHINE_ARM.some.invalid.long.path")
    assert len(symbols) == 0


def test_cc_get_symbols_matching(completion_cache):
    # Not exact tests testing at least the number of returned results
    assert len(completion_cache.get_symbols_matching("")) >= 5
    assert len(completion_cache.get_symbols_matching("m")) >= 2
    assert len(completion_cache.get_symbols_matching("pe.MACHINE_ARM")) == 3
    assert len(completion_cache.get_symbols_matching("pe.MACHINE_ARM64")) == 1
    assert len(completion_cache.get_symbols_matching("pe.MACHINE_ARM64.")) == 0
