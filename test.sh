#!/usr/bin/env bash

BIN="./target/release/xml-mcp"
PASS=0
FAIL=0

run() {
    local desc="$1"
    local input="$2"
    local expect="$3"

    result=$(echo "$input" | "$BIN" 2>/dev/null | tail -1)
    if echo "$result" | grep -q "$expect"; then
        echo "  PASS: $desc"
        ((PASS++))
    else
        echo "  FAIL: $desc"
        echo "    Expected to contain: $expect"
        echo "    Got: ${result:0:200}"
        ((FAIL++))
    fi
}

echo "=== xml-mcp test suite ==="
echo

# 1. Initialize
echo "--- Protocol ---"
run "initialize" \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    '"name":"xml-mcp"'

run "tools/list" \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    '"xpath_query"'

run "ping" \
    '{"jsonrpc":"2.0","id":3,"method":"ping","params":{}}' \
    '"result"'

# 2. xml_validate
echo
echo "--- xml_validate ---"
run "valid XML" \
    '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"xml_validate","arguments":{"xml_data":"<root><item>A</item></root>"}}}' \
    'Valid XML'

run "invalid XML" \
    '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"xml_validate","arguments":{"xml_data":"<root><item>"}}}' \
    'isError'

# 3. xpath_query
echo
echo "--- xpath_query ---"
run "query child text" \
    '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"xpath_query","arguments":{"xml_data":"<root><name>John</name></root>","expression":"/root/name/text()"}}}' \
    'John'

run "query attribute" \
    '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"xpath_query","arguments":{"xml_data":"<server port=\"8080\"/>","expression":"/server/@port"}}}' \
    '8080'

run "query recursive" \
    '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"xpath_query","arguments":{"xml_data":"<root><a><b>deep</b></a></root>","expression":"//b/text()"}}}' \
    'deep'

run "query with predicate" \
    '{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"xpath_query","arguments":{"xml_data":"<root><item id=\"1\">A</item><item id=\"2\">B</item></root>","expression":"/root/item[@id='"'"'2'"'"']/text()"}}}' \
    'B'

# 4. xpath_set
echo
echo "--- xpath_set ---"
run "set text content" \
    '{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"xpath_set","arguments":{"xml_data":"<root><name>old</name></root>","expression":"/root/name","value":"new"}}}' \
    'new'

run "set attribute" \
    '{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"xpath_set","arguments":{"xml_data":"<server port=\"8080\"/>","expression":"/server/@port","value":"9090"}}}' \
    '9090'

# 5. xml_to_json
echo
echo "--- xml_to_json ---"
run "simple element" \
    '{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"xml_to_json","arguments":{"xml_data":"<root><name>John</name><age>30</age></root>"}}}' \
    'John'

run "attributes" \
    '{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"xml_to_json","arguments":{"xml_data":"<item id=\"1\">text</item>"}}}' \
    '@id'

run "repeated elements become array" \
    '{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"xml_to_json","arguments":{"xml_data":"<root><item>A</item><item>B</item></root>"}}}' \
    'item'

# 6. json_to_xml
echo
echo "--- json_to_xml ---"
run "simple conversion" \
    '{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"json_to_xml","arguments":{"json_data":"{\"root\":{\"name\":\"John\"}}"}}}' \
    '<name>John</name>'

run "with attributes" \
    '{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"json_to_xml","arguments":{"json_data":"{\"item\":{\"@id\":\"1\",\"#text\":\"hello\"}}"}}}' \
    'id='

# 7. xml_format
echo
echo "--- xml_format ---"
run "pretty format" \
    '{"jsonrpc":"2.0","id":60,"method":"tools/call","params":{"name":"xml_format","arguments":{"xml_data":"<root><item>A</item></root>","mode":"pretty"}}}' \
    'root'

run "compact format" \
    '{"jsonrpc":"2.0","id":61,"method":"tools/call","params":{"name":"xml_format","arguments":{"xml_data":"<root>  <item> A </item>  </root>","mode":"compact"}}}' \
    'root'

# 8. schema_infer + schema operations
echo
echo "--- Schema operations ---"
run "schema_infer" \
    '{"jsonrpc":"2.0","id":70,"method":"tools/call","params":{"name":"schema_infer","arguments":{"xml_data":"<config><server port=\"8080\"><name>prod</name></server></config>","store_as":"test-config"}}}' \
    'test-config'

run "schema_list" \
    '{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"schema_list","arguments":{}}}' \
    'test-config'

run "schema_get" \
    '{"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"schema_get","arguments":{"name":"test-config"}}}' \
    'config'

# 9. xml_generate
echo
echo "--- xml_generate ---"
run "generate from schema" \
    '{"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"xml_generate","arguments":{"schema_name":"test-config"}}}' \
    'config'

# 10. xml_diff
echo
echo "--- xml_diff ---"
run "identical docs" \
    '{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"xml_diff","arguments":{"a_data":"<root><a>1</a></root>","b_data":"<root><a>1</a></root>"}}}' \
    'identical'

run "text change" \
    '{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"xml_diff","arguments":{"a_data":"<root><a>old</a></root>","b_data":"<root><a>new</a></root>"}}}' \
    'old'

run "attribute change" \
    '{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"xml_diff","arguments":{"a_data":"<item id=\"1\"/>","b_data":"<item id=\"2\"/>"}}}' \
    '@id'

run "added element" \
    '{"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"xml_diff","arguments":{"a_data":"<root><a>1</a></root>","b_data":"<root><a>1</a><b>2</b></root>"}}}' \
    '/root/b'

# 11. Cleanup
run "schema_delete" \
    '{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"schema_delete","arguments":{"name":"test-config"}}}' \
    'deleted'

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
