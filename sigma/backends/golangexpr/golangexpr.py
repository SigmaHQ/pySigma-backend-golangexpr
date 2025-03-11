from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag
import re
from sigma.types import SigmaString, SpecialChars
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conditions import (
    ConditionItem,
    ConditionOR,
    ConditionAND,
    ConditionNOT,
    ConditionFieldEqualsValueExpression,
)
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional, Union

class GolangExprBackend(TextQueryBackend):
    """Golang Expr backend."""
    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "Golang Expr backend"
    formats : Dict[str, str] = {
        "default": "Plain Golang Expr queries",
        
    }
    requires_pipeline : bool = False            # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = " == "  # Token inserted between field and value (without separator)
    eq_expression: ClassVar[str] = (
        "lower({field}){backend.eq_token}lower({value})"  # Expression for field = value
    )

    # String output
    ## Fields
    ### Quoting
    field_quote : None #ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    # CAUTION: the following could be considered as a slightly hacky solution
    # but since expr does not allow any "special" chars in its field names 
    # absuing the escaping to add `?` to any `.` (https://expr-lang.org/docs/language-definition#optional-chaining) seems reasonable
    field_escape : ClassVar[str] = "?"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile(r"\.")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = ".*"    # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "."     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\"\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "lower({field}) startsWith lower({value})"
    endswith_expression   : ClassVar[str] = "lower({field}) endsWith lower({value})"
    contains_expression   : ClassVar[str] = "lower({field}) contains lower({value})"
    wildcard_match_expression : ClassVar[str] = "{field} matches \"{regex}\""      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "{field} matches \"{regex}\""
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ("\"")               # List of strings that are escaped
    re_escape_escape_char : bool = True                 # If True, the escape character is also escaped
    re_flag_prefix : bool = True                        # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags : Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE : "m",
        SigmaRegularExpressionFlag.DOTALL    : "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression : ClassVar[str] = "{field} == {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression : ClassVar[str] = "{field}) casematch_startswith lower({value}"
    case_sensitive_endswith_expression   : ClassVar[str] = "{field}) casematch_endswith lower({value}"
    case_sensitive_contains_expression   : ClassVar[str] = "{field}) casematch_contains lower({value}"

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression : ClassVar[Optional[str]] = None  # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only).

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression : ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting : Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} == nil"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    field_exists_expression : ClassVar[str] = "{field} in $env"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "not ({field} in $env)"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = False                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = False       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} [{list}]"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = '"{value}"'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[str] = '_=~{value}'   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    # replace because of "not (....)"
    def convert_condition_not(
        self, cond: ConditionNOT, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:  # group if AND or OR condition is negated
                return (
                    self.not_token + self.token_separator + self.convert_condition_group(arg, state)
                )
            else:
                expr = self.convert_condition(arg, state)
                if isinstance(
                    expr, DeferredQueryExpression
                ):  # negate deferred expression and pass it to parent
                    return expr.negate()
                else:  # convert negated expression to string
                    return self.not_token + self.token_separator + "(" + expr + ")"
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")
    
    # took this from https://github.com/IBM/pySigma-backend-QRadar-AQL
    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """
        Convert a SigmaString into a plain string which can be used in query.
        Escape only chars in self.add_escaped
        """
        converted = ""
        escaped_chars = self.add_escaped

        for c in s:
            if isinstance(c, str):  # c is plain character
                if c in self.filter_chars:  # Skip filtered characters
                    continue
                if c in escaped_chars:
                    converted += self.escape_char
                converted += c
            else:  # special handling for special characters
                if c == SpecialChars.WILDCARD_MULTI:
                    if self.wildcard_multi is not None:
                        converted += self.wildcard_multi
                    else:
                        raise SigmaValueError(
                            "Multi-character wildcard not specified for conversion")
                elif c == SpecialChars.WILDCARD_SINGLE:
                    if self.wildcard_single is not None:
                        converted += self.wildcard_single
                    else:
                        raise SigmaValueError(
                            "Single-character wildcard not specified for conversion")

        if self.decide_string_quoting(s):
            return self.quote_string(converted)
        else:
            return converted