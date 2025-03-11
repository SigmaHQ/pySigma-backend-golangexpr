import pytest
from sigma.collection import SigmaCollection
from sigma.backends.golangexpr import GolangExprBackend
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.processing.resolver import ProcessingPipelineResolver

@pytest.fixture
def golangexpr_backend():
    return GolangExprBackend()

def test_golangexpr_and_expression1(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test 
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                   ServiceFileName|contains|all:
                        - '"set'
                        - '-f'
                condition: selection
        """)
    ) == [r'lower(ServiceFileName) contains lower("\"set") and lower(ServiceFileName) contains lower("-f")']

def test_golangexpr_and_expression2(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test 
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['lower(fieldA) == lower("valueA") and lower(fieldB) == lower("valueB")']

def test_golangexpr_or_expression(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['lower(fieldA) == lower("valueA") or lower(fieldB) == lower("valueB")']

def test_golangexpr_and_or_expression(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['(lower(fieldA) == lower("valueA1") or lower(fieldA) == lower("valueA2")) and (lower(fieldB) == lower("valueB1") or lower(fieldB) == lower("valueB2"))']

def test_golangexpr_or_and_expression(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['lower(fieldA) == lower("valueA1") and lower(fieldB) == lower("valueB1") or lower(fieldA) == lower("valueA2") and lower(fieldB) == lower("valueB2")']

def test_golangexpr_in_expression1(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['lower(fieldA) == lower("valueA") or lower(fieldA) == lower("valueB") or lower(fieldA) startsWith lower("valueC")']

def test_golangexpr_regex_query1(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['fieldA matches "foo.*bar" and lower(fieldB) == lower("foo")']

def test_golangexpr_cidr_query(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['lower(field) startsWith lower("192.168.")']

def test_golangexpr_win_path_backslash_1(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                condition: selection
                selection:
                    LocalName|contains:
                    - 'C:\Users\Public\'
        """)
    ) == [r'lower(LocalName) contains lower("C:\\Users\\Public\\")']

def test_golangexpr_win_path_backslash_2(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection_img:
                    - Image|endswith: '\certoc.exe'
                    - OriginalFileName: 'CertOC.exe'
                selection_cli:
                    CommandLine|contains|windash: ' -LoadDLL '
                condition: all of selection_*
        """)
    ) == [r'(lower(Image) endsWith lower("\\certoc.exe") or lower(OriginalFileName) == lower("CertOC.exe")) and (lower(CommandLine) contains lower(" -LoadDLL ") or lower(CommandLine) contains lower(" /LoadDLL ") or lower(CommandLine) contains lower(" –LoadDLL ") or lower(CommandLine) contains lower(" —LoadDLL ") or lower(CommandLine) contains lower(" ―LoadDLL "))']

def test_golangexpr_in_expression2(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - 'valueA'
                        - 'valueB'
                        - 'valueC*'
                        - 'val*ue'
                        - '*value'
                condition: sel
        """)
    ) == ['lower(fieldA) == lower("valueA") or lower(fieldA) == lower("valueB") or lower(fieldA) startsWith lower("valueC") or fieldA matches "val.*ue" or lower(fieldA) endsWith lower("value")']

def test_golangexpr_regex_query2(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['fieldA matches "foo.*bar" and lower(fieldB) == lower("foo")']

def test_golangexpr_regex_query3(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 'foo.*bar\w'
                condition: sel
        """)
    ) == [r'fieldA matches "foo.*bar\\w"']

def test_golangexpr_regex_query4(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 'foo.*bar\w"'
                condition: sel
        """)
    ) == [r'fieldA matches "foo.*bar\\w\""']

def test_golangexpr_regex_query5(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 'foo.*bar\[[az]'
                condition: sel
        """)
    ) == [r'fieldA matches "foo.*bar\\[[az]"']

def test_golangexpr_regex_query6(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: 'foo.*bar"'
                condition: sel
        """)
    ) == [r'fieldA matches "foo.*bar\""']

def test_golangexpr_regex_query_caseinsensitive(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: (?i)foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['fieldA matches "(?i)foo.*bar" and lower(fieldB) == lower("foo")']

def test_golangexpr_startendsWith_and_endswith_query(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: foo
                    fieldB|endswith: bar
                condition: sel
        """)
    ) == ['lower(fieldA) startsWith lower("foo") and lower(fieldB) endsWith lower("bar")']

def test_golangexpr_startendsWith_and_not_endswith_query(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA|startswith: foo
                sel2:
                    fieldB|endswith: bar
                condition: sel1 and not sel2
        """)
    ) == ['lower(fieldA) startsWith lower("foo") and not (lower(fieldB) endsWith lower("bar"))']

def test_golangexpr_contains_or_query(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:    
                selection:       
                   greeting|contains: 
                     - 'hello!'
                     - 'hi there!'
                     - 'hiya'
                condition: selection
        """)
    ) == ['lower(greeting) contains lower("hello!") or lower(greeting) contains lower("hi there!") or lower(greeting) contains lower("hiya")']

def test_golangexpr_complex_query(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                selection:
                    IntegrityLevel: System
                    User|contains:
                        - 'AUTHORI'
                        - 'AUTORI'
                selection_special:
                    - Image|endswith:
                        - '\calc.exe'
                        - '\wscript.exe'
                    - CommandLine|contains:
                        - ' -NoP '
                        - ' -W Hidden '
                condition: all of selection*
        """)
    ) == [r'lower(IntegrityLevel) == lower("System") and (lower(User) contains lower("AUTHORI") or lower(User) contains lower("AUTORI")) and (lower(Image) endsWith lower("\\calc.exe") or lower(Image) endsWith lower("\\wscript.exe") or lower(CommandLine) contains lower(" -NoP ") or lower(CommandLine) contains lower(" -W Hidden "))']

def test_golangexpr_special_values_query(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml(r"""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field: 'foo\nbar'
                condition: sel
        """)
    ) == [r'lower(field) == lower("foo\\nbar")']

def test_golangexpr_contains_all(golangexpr_backend : GolangExprBackend):
    assert golangexpr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    field|contains|all: 
                        - value1
                        - value2
                sel2:
                    field|contains: 
                        - value1
                        - value2
                condition: all of sel*
        """)
    ) == ['lower(field) contains lower("value1") and lower(field) contains lower("value2") and (lower(field) contains lower("value1") or lower(field) contains lower("value2"))']

def test_golangexpr_FieldChain():
    piperesolver = ProcessingPipelineResolver()
    piperesolver.add_pipeline_class(ecs_windows())  
    combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
    assert GolangExprBackend(combined_pipeline).convert(
        SigmaCollection.from_yaml(r"""
            title: Test 
            status: test
            logsource:
                product: windows
                service: security
            detection:
                selection:
                   CommandLine|contains|all:
                        - '"set'
                        - '-f'
                condition: selection
        """)
    ) == [r'lower(winlog?.channel) == lower("Security") and lower(process?.command_line) contains lower("\"set") and lower(process?.command_line) contains lower("-f")']

# NOT POSSIBLE IN Expr
# def test_golangexpr_field_name_with_whitespace(golangexpr_backend : GolangExprBackend):
#     assert golangexpr_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field name: value
#                 condition: sel
#         """)
#     ) == ['<insert expected result here>']