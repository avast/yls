# type: ignore

from yls.snippet_string import SnippetString


def test_simple():
    snip = SnippetString("test")
    assert str(snip) == "test"


def test_placeholder():
    snip = SnippetString()
    snip.append_placeholder("one")
    snip.append_placeholder("two")
    assert str(snip) == "${1:one}${2:two}"


def test_complex():
    snip = SnippetString()
    snip.append_text("text\n")
    snip.append_placeholder("one")
    snip.append_tabstop()
    snip.append_placeholder("two")
    snip.append_variable("CLIPBOARD", "")
    snip.append_variable("INVALID_VARIABLE", "default")
    snip.append_choice(("c", "ch", "choice"))
    assert str(snip) == "text\n${1:one}$2${3:two}${CLIPBOARD}${default}${4|c,ch,choice|}"
