import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from spl.spl_utils import (  # noqa: E402
    assess_spl_safety,
    ensure_spl_time_bounds,
    extract_json_payload,
    extract_spl_entities,
    normalize_query_tool_args,
    scope_spl_to_index,
    split_spl_pipeline,
    validate_spl_against_environment,
)


# Shapes produced by the old "prepend index=X |" anchoring bug.
CORRUPTED_PREFIX_RE = re.compile(r"^\s*(?:search\s+)?index=\S+(?:\s+earliest=\S+)?\s*\|")

FAILED_LOGON = "index=wineventlog EventCode=4625 | stats count by user"
TSTATS = "| tstats count where index=* by sourcetype"
SOURCETYPE_ONLY = "sourcetype=WinEventLog:Security EventCode=4624 | stats count by user"
MAIN_BACKUP = "index=main_backup | stats count"


class SplitPipelineTests(unittest.TestCase):
    def test_splits_on_top_level_pipes(self):
        self.assertEqual(
            split_spl_pipeline("index=x error | stats count by host | sort -count"),
            ["index=x error", "stats count by host", "sort -count"],
        )

    def test_leading_pipe_yields_empty_first_segment(self):
        self.assertEqual(split_spl_pipeline(TSTATS), ["", "tstats count where index=* by sourcetype"])

    def test_ignores_pipes_in_double_quotes(self):
        self.assertEqual(split_spl_pipeline('search "a|b" | stats count'), ['search "a|b"', "stats count"])

    def test_ignores_pipes_in_single_quotes(self):
        self.assertEqual(
            split_spl_pipeline("index=x | eval y='a|b' | table y"),
            ["index=x", "eval y='a|b'", "table y"],
        )

    def test_apostrophe_in_raw_term_is_not_a_quote(self):
        self.assertEqual(split_spl_pipeline("index=x don't | stats count"), ["index=x don't", "stats count"])

    def test_ignores_pipes_in_subsearches(self):
        query = "index=x [search index=y | fields host] | stats count"
        self.assertEqual(split_spl_pipeline(query), ["index=x [search index=y | fields host]", "stats count"])

    def test_ignores_nested_subsearch_pipes(self):
        query = "index=x [search index=y [search index=z | fields user] | fields host] | stats count"
        self.assertEqual(len(split_spl_pipeline(query)), 2)

    def test_ignores_escaped_pipes(self):
        self.assertEqual(split_spl_pipeline(r"index=x a\|b | stats count"), [r"index=x a\|b", "stats count"])

    def test_escaped_quote_inside_string(self):
        self.assertEqual(split_spl_pipeline(r'search "say \"hi | there\"" | head 1'), [r'search "say \"hi | there\""', "head 1"])

    def test_empty_query(self):
        self.assertEqual(split_spl_pipeline(""), [])
        self.assertEqual(split_spl_pipeline("   "), [])

    def test_trailing_pipe_yields_empty_last_segment(self):
        self.assertEqual(split_spl_pipeline("index=x |"), ["index=x", ""])


class SafetyTests(unittest.TestCase):
    def assertBlocked(self, query, command):
        result = assess_spl_safety(query)
        self.assertFalse(result["allowed"], query)
        self.assertIn(command, result["blocked_commands"])
        self.assertTrue(result["reason"])

    def assertAllowed(self, query):
        result = assess_spl_safety(query)
        self.assertTrue(result["allowed"], (query, result))
        self.assertEqual(result["blocked_commands"], [])
        self.assertEqual(result["reason"], "")
        return result

    def test_blocks_write_commands(self):
        for command in (
            "delete",
            "outputlookup foo.csv",
            "outputcsv foo",
            "outputtext",
            "collect index=summary",
            "tscollect namespace=x",
            "mcollect index=m",
            "meventcollect index=m",
            "summaryindex index=s",
            "sendemail to=a@b.c",
            "sendalert myalert",
            "sendresults",
            "script python foo",
            "run foo",
            "runshellscript foo.sh",
            "dump basefilename=x",
            "crawl",
            "dbxoutput output=x",
            "outputtelemetry",
        ):
            with self.subTest(command=command):
                self.assertBlocked(f"index=main | {command}", command.split()[0])

    def test_blocks_any_send_prefixed_command(self):
        self.assertBlocked("index=main | sendtowebhook url=x", "sendtowebhook")

    def test_blocking_is_case_insensitive(self):
        self.assertBlocked("index=main | DELETE", "delete")
        self.assertBlocked("index=main | OutputLookup x.csv", "outputlookup")

    def test_blocks_leading_pipe_command(self):
        self.assertBlocked("| makeresults | outputlookup x.csv", "outputlookup")
        self.assertBlocked("|delete", "delete")

    def test_blocks_inside_subsearch(self):
        self.assertBlocked("index=x [ | outputlookup y ]", "outputlookup")
        self.assertBlocked("index=x | append [ search index=y | collect index=z ]", "collect")
        self.assertBlocked("index=x [search index=y [search index=z | delete] | fields host]", "delete")

    def test_blocks_implicit_first_command_inside_subsearch(self):
        self.assertBlocked("index=x [ outputlookup y ]", "outputlookup")

    def test_blocks_unclosed_subsearch_content(self):
        self.assertBlocked("index=x [ search index=y | delete", "delete")

    def test_blocks_map_search_string(self):
        self.assertBlocked('| makeresults | map search="search index=x | delete"', "delete")

    def test_blocks_pipe_hidden_behind_single_quote(self):
        self.assertBlocked("index=x 'foo | delete", "delete")
        # Single quotes are not string delimiters everywhere in SPL, so a pipe
        # inside them is treated as a real pipe by the safety check.
        self.assertBlocked("index=x | eval cmd='| outputlookup' | table cmd", "outputlookup")
        self.assertBlocked(r"index=x a\| delete", "delete")

    def test_blocks_rest_with_write_method(self):
        self.assertBlocked("| rest /services/saved/searches method=post", "rest")
        self.assertBlocked('| rest /services/x method="DELETE"', "rest")

    def test_allows_plain_rest(self):
        self.assertAllowed("| rest /services/data/indexes | table title")

    def test_allows_quoted_and_field_value_words(self):
        for query in (
            'search "delete user"',
            'index=x | eval action="collect" | stats count by action',
            'index=x "| delete"',
            "index=x action=delete | stats count",
            "index=x | where command=\"sendemail\"",
            "index=x | rename delete AS removed",
        ):
            with self.subTest(query=query):
                self.assertAllowed(query)

    def test_allows_si_and_read_commands(self):
        self.assertAllowed("index=x | sistats count by host")
        self.assertAllowed("| inputlookup assets.csv | stats count")
        self.assertAllowed(TSTATS)

    def test_implicit_first_term_is_not_a_command(self):
        result = self.assertAllowed("delete foo")
        self.assertTrue(any("delete" in warning for warning in result["warnings"]))

    def test_empty_query_not_allowed(self):
        for query in ("", "   ", None):
            result = assess_spl_safety(query)
            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason"], "Query is empty.")

    def test_warnings_for_expensive_patterns(self):
        self.assertTrue(any("map" in w for w in assess_spl_safety('index=x | map search="search index=y"')["warnings"]))
        self.assertTrue(any("transaction" in w for w in assess_spl_safety("index=x | transaction host")["warnings"]))
        self.assertFalse(
            any("transaction" in w for w in assess_spl_safety("index=x | transaction host maxspan=5m")["warnings"])
        )
        self.assertTrue(any("join" in w for w in assess_spl_safety("index=x | join host [search index=y]")["warnings"]))
        self.assertTrue(any("index=*" in w for w in assess_spl_safety("index=* | stats count")["warnings"]))

    def test_no_index_star_warning_when_bounded_or_tstats(self):
        self.assertFalse(any("index=*" in w for w in assess_spl_safety("index=* earliest=-1h | stats count")["warnings"]))
        self.assertFalse(any("index=*" in w for w in assess_spl_safety(TSTATS)["warnings"]))

    def test_result_shape(self):
        result = assess_spl_safety("index=x | stats count")
        self.assertEqual(set(result), {"allowed", "blocked_commands", "warnings", "reason"})


class NormalizeQueryToolArgsTests(unittest.TestCase):
    def test_applies_defaults(self):
        self.assertEqual(
            normalize_query_tool_args({"query": "  index=x | stats count  "}),
            {"query": "index=x | stats count", "earliest_time": "-24h", "latest_time": "now", "row_limit": 200},
        )

    def test_preserves_provided_times_and_other_keys(self):
        args = {"query": "index=x", "earliest_time": "-7d", "latest_time": "-1d", "row_limit": 50, "extra": True}
        result = normalize_query_tool_args(args)
        self.assertEqual(result["earliest_time"], "-7d")
        self.assertEqual(result["latest_time"], "-1d")
        self.assertEqual(result["row_limit"], 50)
        self.assertTrue(result["extra"])

    def test_blank_times_get_defaults(self):
        result = normalize_query_tool_args({"query": "index=x", "earliest_time": " ", "latest_time": None})
        self.assertEqual(result["earliest_time"], "-24h")
        self.assertEqual(result["latest_time"], "now")

    def test_custom_defaults(self):
        result = normalize_query_tool_args({"query": "index=x"}, default_earliest="-1h", default_latest="-5m")
        self.assertEqual((result["earliest_time"], result["latest_time"]), ("-1h", "-5m"))

    def test_spl_time_terms_suppress_defaults(self):
        result = normalize_query_tool_args({"query": "index=x earliest=-7d | stats count", "earliest_time": ""})
        self.assertNotIn("earliest_time", result)
        self.assertNotIn("latest_time", result)

    def test_tstats_where_time_terms_suppress_defaults(self):
        result = normalize_query_tool_args({"query": "| tstats count where index=x latest=now by host"})
        self.assertNotIn("earliest_time", result)
        self.assertNotIn("latest_time", result)

    def test_spl_time_terms_keep_provided_values(self):
        result = normalize_query_tool_args({"query": "index=x earliest=-7d", "earliest_time": "-30d"})
        self.assertEqual(result["earliest_time"], "-30d")
        self.assertNotIn("latest_time", result)

    def test_time_terms_in_eval_or_subsearch_do_not_count(self):
        result = normalize_query_tool_args({"query": "index=x [search index=y earliest=-1h | fields host] | eval earliest=1"})
        self.assertEqual(result["earliest_time"], "-24h")

    def test_row_limit_clamping(self):
        cases = [("50", 50), (5000, 1000), ("5000", 1000), (0, 1), (-5, 1), ("abc", 200), (None, 200), (True, 200), ("25.0", 25)]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(normalize_query_tool_args({"query": "index=x", "row_limit": value})["row_limit"], expected)
        self.assertEqual(normalize_query_tool_args({"query": "index=x"})["row_limit"], 200)
        self.assertEqual(normalize_query_tool_args({"query": "x", "row_limit": 900}, max_row_limit=500)["row_limit"], 500)
        self.assertEqual(normalize_query_tool_args({"query": "x"}, default_row_limit=20)["row_limit"], 20)

    def test_does_not_mutate_input(self):
        args = {"query": " index=x ", "row_limit": "9999"}
        result = normalize_query_tool_args(args)
        self.assertEqual(args, {"query": " index=x ", "row_limit": "9999"})
        self.assertIsNot(result, args)

    def test_handles_missing_args(self):
        self.assertEqual(normalize_query_tool_args(None)["query"], "")


class ExtractEntitiesTests(unittest.TestCase):
    def test_basic_and_quoted_values(self):
        entities = extract_spl_entities("index=main sourcetype=\"access_combined\" host='web 01' source=/var/log/messages")
        self.assertEqual(entities["indexes"], ["main"])
        self.assertEqual(entities["sourcetypes"], ["access_combined"])
        self.assertEqual(entities["hosts"], ["web 01"])
        self.assertEqual(entities["sources"], ["/var/log/messages"])

    def test_quoted_index_with_space(self):
        self.assertEqual(extract_spl_entities('index="foo bar" | stats count')["indexes"], ["foo bar"])

    def test_in_lists(self):
        self.assertEqual(extract_spl_entities('index IN (a, b, "c") | stats count')["indexes"], ["a", "b", "c"])
        self.assertEqual(extract_spl_entities("sourcetype in (x y)")["sourcetypes"], ["x", "y"])

    def test_wildcards_and_colons(self):
        entities = extract_spl_entities("index=net* sourcetype=WinEventLog:Security")
        self.assertEqual(entities["indexes"], ["net*"])
        self.assertEqual(entities["sourcetypes"], ["WinEventLog:Security"])

    def test_case_insensitive_keys(self):
        entities = extract_spl_entities("INDEX=Main SourceType=foo HOST=h1")
        self.assertEqual(entities["indexes"], ["Main"])
        self.assertEqual(entities["sourcetypes"], ["foo"])
        self.assertEqual(entities["hosts"], ["h1"])

    def test_tstats_where_clause(self):
        self.assertEqual(extract_spl_entities("| tstats count where index=fw sourcetype=pan:traffic by host")["indexes"], ["fw"])

    def test_metadata_and_index_double_colon(self):
        self.assertEqual(extract_spl_entities("| metadata type=sourcetypes index=os")["indexes"], ["os"])
        self.assertEqual(extract_spl_entities("index::main error")["indexes"], ["main"])

    def test_from_datamodel_ignored(self):
        self.assertEqual(extract_spl_entities("| from datamodel:Authentication | stats count"), {
            "indexes": [], "sourcetypes": [], "hosts": [], "sources": []})

    def test_negations_excluded(self):
        entities = extract_spl_entities("index=main NOT index=foo index!=bar sourcetype!=x NOT (host=a OR host=b) host=c")
        self.assertEqual(entities["indexes"], ["main"])
        self.assertEqual(entities["sourcetypes"], [])
        self.assertEqual(entities["hosts"], ["c"])

    def test_not_applies_to_single_term(self):
        self.assertEqual(extract_spl_entities("NOT host=a index=main")["indexes"], ["main"])

    def test_not_in_list_excluded(self):
        self.assertEqual(extract_spl_entities("index=main NOT sourcetype IN (a, b)")["sourcetypes"], [])

    def test_lookalike_field_names_ignored(self):
        entities = extract_spl_entities("index=main my_index=foo orig_host=x src_sourcetype=y source_ip=1.2.3.4")
        self.assertEqual(entities["indexes"], ["main"])
        self.assertEqual(entities["hosts"], [])
        self.assertEqual(entities["sourcetypes"], [])
        self.assertEqual(entities["sources"], [])

    def test_eval_and_quoted_text_ignored(self):
        entities = extract_spl_entities('index=main "index=foo" | eval index="bar" | stats count')
        self.assertEqual(entities["indexes"], ["main"])

    def test_where_only_counts_string_literals(self):
        entities = extract_spl_entities('index=main | where host="h1" OR host=other_field')
        self.assertEqual(entities["hosts"], ["h1"])

    def test_dedup_preserves_order(self):
        self.assertEqual(extract_spl_entities("index=b index=a index=B index=a")["indexes"], ["b", "a"])

    def test_subsearch_references_included(self):
        entities = extract_spl_entities("index=a [search index=b sourcetype=s | fields host]")
        self.assertEqual(entities["indexes"], ["a", "b"])
        self.assertEqual(entities["sourcetypes"], ["s"])

    def test_empty(self):
        self.assertEqual(extract_spl_entities(""), {"indexes": [], "sourcetypes": [], "hosts": [], "sources": []})


class ValidateTests(unittest.TestCase):
    KNOWN = {
        "indexes": ["main", "wineventlog", "netops", "_internal"],
        "sourcetypes": ["WinEventLog:Security", "pan:traffic"],
    }

    def validate(self, query, known=None):
        return validate_spl_against_environment(query, self.KNOWN if known is None else known)

    def test_validated(self):
        result = self.validate(FAILED_LOGON)
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["referenced"]["indexes"], ["wineventlog"])
        self.assertEqual(result["issues"], [])
        self.assertTrue(result["safety"]["allowed"])

    def test_main_backup_does_not_match_main(self):
        result = self.validate(MAIN_BACKUP)
        self.assertEqual(result["status"], "unknown_entities")
        self.assertEqual(result["unknown_entities"]["indexes"], ["main_backup"])

    def test_unknown_sourcetype(self):
        result = self.validate("index=main sourcetype=bogus")
        self.assertEqual(result["status"], "unknown_entities")
        self.assertEqual(result["unknown_entities"]["sourcetypes"], ["bogus"])

    def test_case_insensitive_matching(self):
        self.assertEqual(self.validate("index=MAIN sourcetype=wineventlog:security")["status"], "validated")

    def test_wildcard_query_matches_known(self):
        self.assertEqual(self.validate("index=net* | stats count")["status"], "validated")
        result = self.validate("index=zzz* | stats count")
        self.assertEqual(result["status"], "unknown_entities")
        self.assertEqual(result["unknown_entities"]["indexes"], ["zzz*"])

    def test_known_wildcard_matches_query(self):
        result = validate_spl_against_environment("index=app_web", {"indexes": ["app_*"]})
        self.assertEqual(result["status"], "validated")

    def test_internal_indexes_not_special_cased(self):
        self.assertEqual(self.validate("index=_internal | stats count")["status"], "validated")
        result = self.validate("index=_audit | stats count")
        self.assertEqual(result["status"], "unknown_entities")
        self.assertEqual(result["unknown_entities"]["indexes"], ["_audit"])

    def test_only_supplied_categories_checked(self):
        result = validate_spl_against_environment("index=main sourcetype=anything host=h", {"indexes": ["main"]})
        self.assertEqual(result["status"], "validated")
        result = validate_spl_against_environment("index=main host=h", {"indexes": ["main"], "hosts": ["other"]})
        self.assertEqual(result["status"], "unknown_entities")
        self.assertEqual(result["unknown_entities"]["hosts"], ["h"])

    def test_unscoped(self):
        result = self.validate(SOURCETYPE_ONLY)
        self.assertEqual(result["status"], "unscoped")
        self.assertTrue(result["issues"])
        self.assertEqual(self.validate("NOT index=main error")["status"], "unscoped")
        self.assertEqual(self.validate("| search error")["status"], "unscoped")

    def test_subsearch_index_does_not_scope_outer_search(self):
        self.assertEqual(self.validate("error [search index=main | fields host]")["status"], "unscoped")

    def test_tstats_without_index_is_not_unscoped(self):
        self.assertEqual(self.validate("| tstats count by sourcetype")["status"], "validated")
        self.assertEqual(self.validate(TSTATS)["status"], "validated")
        self.assertEqual(self.validate("| inputlookup assets.csv")["status"], "validated")

    def test_blocked(self):
        result = self.validate("index=main | delete")
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["safety"]["allowed"])
        self.assertEqual(self.validate("index=main [ | outputlookup y ]")["status"], "blocked")

    def test_invalid_empty(self):
        for query in ("", "   "):
            result = self.validate(query)
            self.assertEqual(result["status"], "invalid")
            self.assertEqual(result["issues"], ["Query is empty."])

    def test_invalid_generating_command_after_search(self):
        for query in (
            "index=main | tstats count",
            "index=main | inputlookup x.csv",
            "index=main | rest /services/data/indexes",
            "index=main | makeresults",
            "index=main | metadata type=hosts",
            "index=main | from datamodel:X",
            "index=main | mstats avg(cpu) WHERE index=m",
            "index=main | dbinspect index=main",
        ):
            with self.subTest(query=query):
                self.assertEqual(self.validate(query)["status"], "invalid")

    def test_append_true_generating_command_is_valid(self):
        self.assertEqual(self.validate("| inputlookup a.csv | inputlookup append=t b.csv")["status"], "validated")
        self.assertEqual(self.validate("| tstats count where index=main | tstats append=true count where index=netops")["status"], "validated")

    def test_invalid_structure(self):
        for query in (
            'index=main "unterminated',
            "index=main [search index=main",
            "index=main ] | stats count",
            "index=main (a OR b | stats count",
            "index=main | | stats count",
            "index=main |",
            "index=main []",
            "tstats count where index=main",
            "| stats count",
        ):
            with self.subTest(query=query):
                self.assertEqual(self.validate(query)["status"], "invalid")

    def test_corrupted_anchoring_outputs_are_invalid(self):
        for query in (
            "index=_audit earliest=-24h | index=wineventlog EventCode=4625 | stats count",
            "index=_audit earliest=-24h | tstats count where index=* by sourcetype",
            "index=_audit earliest=-24h | sourcetype=WinEventLog:Security EventCode=4624 | stats count",
        ):
            with self.subTest(query=query):
                self.assertEqual(self.validate(query, {"indexes": ["_audit", "wineventlog"]})["status"], "invalid")

    def test_result_shape(self):
        result = self.validate(FAILED_LOGON)
        self.assertEqual(set(result), {"status", "referenced", "unknown_entities", "issues", "safety"})
        self.assertEqual(set(result["unknown_entities"]), {"indexes", "sourcetypes", "hosts", "sources"})

    def test_none_known(self):
        self.assertEqual(validate_spl_against_environment(FAILED_LOGON, None)["status"], "validated")


class ScopeToIndexTests(unittest.TestCase):
    def test_existing_index_unchanged(self):
        self.assertEqual(scope_spl_to_index(FAILED_LOGON, "_audit"), FAILED_LOGON)
        self.assertEqual(scope_spl_to_index(MAIN_BACKUP, "main"), MAIN_BACKUP)

    def test_generating_commands_unchanged(self):
        self.assertEqual(scope_spl_to_index(TSTATS, "_audit"), TSTATS)
        self.assertEqual(scope_spl_to_index("| inputlookup x.csv", "_audit"), "| inputlookup x.csv")
        self.assertEqual(scope_spl_to_index("tstats count by host", "_audit"), "tstats count by host")

    def test_sourcetype_only_query_scoped_in_first_segment(self):
        scoped = scope_spl_to_index(SOURCETYPE_ONLY, "_audit")
        self.assertEqual(scoped, "index=_audit " + SOURCETYPE_ONLY)
        self.assertIsNone(CORRUPTED_PREFIX_RE.match(scoped))
        self.assertEqual(split_spl_pipeline(scoped)[1:], split_spl_pipeline(SOURCETYPE_ONLY)[1:])

    def test_after_search_keyword(self):
        self.assertEqual(scope_spl_to_index("search error | stats count", "main"), "search index=main error | stats count")
        self.assertEqual(scope_spl_to_index("  SEARCH error", "main"), "  SEARCH index=main error")

    def test_quotes_special_index_names(self):
        self.assertEqual(scope_spl_to_index("error", "my index"), 'index="my index" error')

    def test_negated_index_still_scoped(self):
        self.assertEqual(scope_spl_to_index("NOT index=foo error", "main"), "index=main NOT index=foo error")

    def test_subsearch_index_does_not_count(self):
        self.assertEqual(
            scope_spl_to_index("error [search index=x | fields host]", "main"),
            "index=main error [search index=x | fields host]",
        )

    def test_empty_inputs_unchanged(self):
        self.assertEqual(scope_spl_to_index("", "main"), "")
        self.assertEqual(scope_spl_to_index("error", ""), "error")

    def test_never_produces_index_pipe_prefix(self):
        for query in (FAILED_LOGON, TSTATS, SOURCETYPE_ONLY, MAIN_BACKUP, "search error | stats count", "error"):
            with self.subTest(query=query):
                scoped = scope_spl_to_index(query, "_audit")
                if not query.lstrip().startswith("index="):
                    self.assertIsNone(CORRUPTED_PREFIX_RE.match(scoped), scoped)
                self.assertEqual(len(split_spl_pipeline(scoped)), len(split_spl_pipeline(query)))


class TimeBoundsTests(unittest.TestCase):
    def test_inserts_into_first_segment(self):
        self.assertEqual(ensure_spl_time_bounds(FAILED_LOGON), "earliest=-24h " + FAILED_LOGON)

    def test_with_latest(self):
        self.assertEqual(ensure_spl_time_bounds("index=x", "-7d", "now"), "earliest=-7d latest=now index=x")

    def test_after_search_keyword(self):
        self.assertEqual(ensure_spl_time_bounds("search index=x | stats count"), "search earliest=-24h index=x | stats count")

    def test_existing_time_terms_unchanged(self):
        for query in ("index=x earliest=-1h | stats count", "index=x latest=now", "index=x EARLIEST=-2d"):
            with self.subTest(query=query):
                self.assertEqual(ensure_spl_time_bounds(query), query)

    def test_generating_queries_unchanged(self):
        self.assertEqual(ensure_spl_time_bounds(TSTATS), TSTATS)
        self.assertEqual(ensure_spl_time_bounds("| inputlookup x.csv"), "| inputlookup x.csv")

    def test_later_segment_time_terms_do_not_block_base_insert(self):
        query = "index=x | search earliest=-1h"
        result = ensure_spl_time_bounds(query)
        self.assertEqual(result, "earliest=-24h " + query)
        self.assertEqual(split_spl_pipeline(result)[1:], split_spl_pipeline(query)[1:])

    def test_subsearch_time_terms_ignored(self):
        query = "index=x [search index=y earliest=-1h | fields host]"
        self.assertEqual(ensure_spl_time_bounds(query), "earliest=-24h " + query)

    def test_no_terms_when_bounds_blank(self):
        self.assertEqual(ensure_spl_time_bounds("index=x", "", None), "index=x")
        self.assertEqual(ensure_spl_time_bounds("", "-24h"), "")

    def test_corruption_vectors(self):
        self.assertEqual(ensure_spl_time_bounds(TSTATS), TSTATS)
        for query in (FAILED_LOGON, SOURCETYPE_ONLY, MAIN_BACKUP):
            with self.subTest(query=query):
                result = ensure_spl_time_bounds(scope_spl_to_index(query, "_audit"))
                self.assertIsNone(re.match(r"^\s*index=_audit\s+earliest=\S+\s*\|", result), result)
                self.assertEqual(len(split_spl_pipeline(result)), len(split_spl_pipeline(query)))
                self.assertTrue(split_spl_pipeline(result)[0].startswith("earliest=-24h "))


class ExtractJsonPayloadTests(unittest.TestCase):
    def test_plain_list_and_dict(self):
        self.assertEqual(extract_json_payload('[{"a": 1}]'), [{"a": 1}])
        self.assertEqual(extract_json_payload('{"a": 1}', expect="dict"), {"a": 1})

    def test_fenced_json_preferred(self):
        text = 'Example: {"x": 0, "y": [1, 2, 3, 4, 5, 6, 7, 8]}\n```json\n[{"q": 1}]\n```\n'
        self.assertEqual(extract_json_payload(text, expect="list"), [{"q": 1}])

    def test_unlabelled_fence(self):
        self.assertEqual(extract_json_payload("```\n{\"a\": 1}\n```", expect="dict"), {"a": 1})

    def test_think_tags_stripped(self):
        text = '<think>Maybe {"draft": true} or [1, 2]</think>\nFinal: {"queries": [{"spl": "index=x"}]}'
        self.assertEqual(extract_json_payload(text, expect="list"), [{"spl": "index=x"}])
        text = '<thinking>\n[{"wrong": 1}]\n</thinking>[{"right": 1}]'
        self.assertEqual(extract_json_payload(text, expect="list"), [{"right": 1}])

    def test_orphan_closing_think_tag(self):
        self.assertEqual(extract_json_payload('reasoning {"no": 1} </think> {"yes": 1}', expect="dict"), {"yes": 1})

    def test_unclosed_think_tag(self):
        self.assertEqual(extract_json_payload('{"ok": 1}<think>still thinking {"no": 2', expect="dict"), {"ok": 1})

    def test_truncated_array_salvage(self):
        self.assertEqual(extract_json_payload('[{"a":1},{"b":2},{"c":', expect="list"), [{"a": 1}, {"b": 2}])
        self.assertEqual(extract_json_payload('Here you go:\n```json\n[{"a":1},{"b":2},{"c":'), [{"a": 1}, {"b": 2}])

    def test_truncated_array_in_dict_salvage(self):
        text = '{"queries": [{"q": 1}, {"q": 2}, {"q": "unfinished'
        self.assertEqual(extract_json_payload(text, expect="list"), [{"q": 1}, {"q": 2}])

    def test_truncated_scalar_not_salvaged_as_complete(self):
        self.assertEqual(extract_json_payload("[1, 2, 3", expect="list"), [1, 2])

    def test_dict_with_list_key(self):
        self.assertEqual(extract_json_payload('{"tasks": [{"t": 1}], "note": "x"}', expect="list"), [{"t": 1}])
        self.assertEqual(extract_json_payload('{"Findings": [1]}', expect="list"), [1])
        self.assertEqual(extract_json_payload('{"other": [1]}', expect="list", list_keys=("other",)), [1])
        self.assertIsNone(extract_json_payload('{"a": 1}', expect="list"))

    def test_expect_dict_skips_lists(self):
        self.assertEqual(extract_json_payload('[1, 2] then {"a": 1}', expect="dict"), {"a": 1})
        self.assertIsNone(extract_json_payload("[1, 2]", expect="dict"))

    def test_embedded_in_prose_prefers_largest(self):
        text = 'See [1] and the plan: {"steps": [1, 2, 3], "name": "full"} thanks'
        self.assertEqual(extract_json_payload(text), {"steps": [1, 2, 3], "name": "full"})

    def test_trailing_commas_and_comments(self):
        text = '{\n  "a": [1, 2,], // comment\n  "b": "http://x",\n}'
        self.assertEqual(extract_json_payload(text, expect="dict"), {"a": [1, 2], "b": "http://x"})

    def test_nothing_usable(self):
        self.assertIsNone(extract_json_payload("no json here"))
        self.assertIsNone(extract_json_payload(""))
        self.assertIsNone(extract_json_payload(None))
        self.assertIsNone(extract_json_payload("{broken"))

    def test_passthrough_objects(self):
        self.assertEqual(extract_json_payload({"items": [1]}, expect="list"), [1])

    def test_invalid_expect(self):
        with self.assertRaises(ValueError):
            extract_json_payload("[]", expect="tuple")


if __name__ == "__main__":
    unittest.main()
