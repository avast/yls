# pytest-yls

![PyPI](https://img.shields.io/pypi/v/pytest-yls)

Pytest plugin adding primitives for E2E/integration tests.

Public fixtures:
- `yls_prepare`
- `yls_prepare_with_settings`

To interact with the tested YLS use `Context` obtained by calling the fixture.
For more information about the `Context` class checkout
[plugin.py](https://github.com/avast/yls/blob/master/pytest-yls/pytest_yls/plugin.py).

### Example test

```python

# Add yls_prepare fixture
def test_completion_basic(yls_prepare):
    # Prepare the tested file
    # <$> marks the cursor position
    contents = """rule test {
    condition:
        <$>
}"""
    
    # Initialize the testing context by calling the fixture
    context = yls_prepare(contents)

    # You can now simulate requests on the context
    # In this case we trigger the code completion
    response = context.send_request(
        methods.COMPLETION,
        types.CompletionParams(
            textDocument=types.TextDocumentIdentifier(uri=context.opened_file.as_uri()),
            position=context.get_cursor_position(),
        ),
    )

    # Assert the response how you want
    assert response
    for module in ["cuckoo", "elf", "pe", "time"]:
        assert any(
            module in item["label"] for item in response["items"]
        ), f"{module=} is not in response"
```

For more inspiration check out
[yls/tests](https://github.com/avast/yls/tree/master/tests).

## License

Copyright (c) 2022 Avast Software, licensed under the MIT license. See the
[`LICENSE`](https://github.com/avast/yls/blob/master/pytest-yls/LICENSE) file
for more details.
