# type: ignore

import pytest

from yls import snippets
from yls.snippet_string import SnippetString


@pytest.mark.parametrize(
    "config, expected",
    (
        (
            {},
            """rule ${1:my_rule} {
\tmeta:
\t\t${2:KEY} = ${3:"VALUE"}
\tstrings:
\t\t${4:\\$name} = ${5|"string",/regex/,{ HEX }|}
\tcondition:
\t\t${6:any of them}
}
""",
        ),
        (
            {"metaEntries": {"author": "test user", "hash": ""}},
            """rule ${1:my_rule} {
\tmeta:
\t\tauthor = "test user"
\t\thash = "$2"
\tstrings:
\t\t${3:\\$name} = ${4|"string",/regex/,{ HEX }|}
\tcondition:
\t\t${5:any of them}
}
""",
        ),
        (
            {"metaEntries": {"filename": "${TM_FILENAME}"}},
            """rule ${1:my_rule} {
\tmeta:
\t\tfilename = "${TM_FILENAME}"
\tstrings:
\t\t${2:\\$name} = ${3|"string",/regex/,{ HEX }|}
\tcondition:
\t\t${4:any of them}
}
""",
        ),
        (
            {
                "metaEntries": {
                    "author": "",
                    "date": "${CURRENT_YEAR}-${CURRENT_MONTH}-${CURRENT_DATE}",
                }
            },
            """rule ${1:my_rule} {
\tmeta:
\t\tauthor = "$2"
\t\tdate = "${CURRENT_YEAR}-${CURRENT_MONTH}-${CURRENT_DATE}"
\tstrings:
\t\t${3:\\$name} = ${4|"string",/regex/,{ HEX }|}
\tcondition:
\t\t${5:any of them}
}
""",
        ),
        (
            {
                "metaEntries": {
                    "date": "${CURRENT_YEAR}-${CURRENT_MONTH}-${CURRENT_DATE}",
                    "author": "",
                },
                "sortMeta": True,
            },
            """rule ${1:my_rule} {
\tmeta:
\t\tauthor = "$2"
\t\tdate = "${CURRENT_YEAR}-${CURRENT_MONTH}-${CURRENT_DATE}"
\tstrings:
\t\t${3:\\$name} = ${4|"string",/regex/,{ HEX }|}
\tcondition:
\t\t${5:any of them}
}
""",
        ),
    ),
)
def test_basic(config, expected):
    assert expected == str(snippets._generate_rule_snippet(SnippetString(), config))
