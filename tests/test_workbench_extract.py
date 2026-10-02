"""Structured Workbench extraction: nested entities, typed indicators, aliases and field states."""

import unittest

from soc_bridge.workbench_extract import MAX_VALUE, parse_alert

from trend_fixtures import ALERT, GUID, HOST, IP4, IP6


class EntityTests(unittest.TestCase):
    def test_nested_host_entity_with_ip_list_and_ipv6(self):
        parsed = parse_alert(ALERT)
        self.assertEqual(parsed["endpoints"], [{"name": HOST, "guid": GUID, "ips": [IP4, IP6],
                                                "sources": ["impactScope.entities[0].entityValue"]}])
        ips = {o["value"]: o for o in parsed["observables"]["ip"]}
        self.assertEqual(set(ips), {IP4, IP6})
        self.assertEqual(ips[IP4]["sources"], ["impactScope.entities[0].entityValue.ips"])
        self.assertEqual(parsed["entities"][0]["value_kind"], "object")
        self.assertEqual(parsed["entities"][1]["value_kind"], "scalar")
        self.assertEqual(parsed["observables"]["user"][0]["role"], "account")
        self.assertEqual(parsed["impact_scope_counts"], {"desktopCount": 1, "accountCount": 1})

    def test_typed_indicators_keep_ids_relations_and_roles(self):
        parsed = parse_alert(ALERT)
        first = parsed["indicators"][0]
        self.assertEqual((first["id"], first["category"], first["role"]), (1, "command", "object"))
        self.assertEqual(first["related_entities"], [GUID])
        self.assertEqual(first["filter_ids"], ["f1"])
        hashes = parsed["observables"]["hash"]
        self.assertEqual((hashes[0]["role"], hashes[0]["algorithm"], hashes[0]["indicator_id"]), ("object", "sha256", 2))
        self.assertEqual(parsed["matched_event_uuids"], ["ev-launch-1"])
        self.assertEqual(parsed["matched_rules"][0]["matched_filters"][0]["mitre_technique_ids"], ["T1003.001"])

    def test_multiple_endpoints_and_scalar_entity_values(self):
        detail = {"impactScope": {"entities": [
            {"entityType": "host", "entityId": "PC-ONE", "entityValue": "PC-ONE"},
            {"entityType": "host", "entityId": ["198.51.100.7", "198.51.100.8"],
             "entityValue": {"name": "PC-TWO", "ips": ["198.51.100.7", "198.51.100.8"]}},
            {"entityType": "emailAddress", "entityValue": "user@example.test", "relatedIndicatorIds": [9]}]}}
        parsed = parse_alert(detail)
        self.assertEqual([e["name"] for e in parsed["endpoints"]], ["PC-ONE", "PC-TWO"])
        self.assertEqual(parsed["endpoints"][1]["ips"], ["198.51.100.7", "198.51.100.8"])
        self.assertEqual(parsed["observables"]["email"][0]["value"], "user@example.test")

    def test_aliases_keep_process_object_parent_roles_apart(self):
        detail = {"processFilePath": "C:\\a\\actor.exe", "objectFilePath": "C:\\b\\target.dll",
                  "parentFilePath": "C:\\c\\parent.exe", "processFileHashSha1": "a" * 40, "objectFileHashSha1": "b" * 40,
                  "endpointIp": ["192.0.2.1", "2001:db8::1", "not-ip"], "endpointName": "PC-ALIAS"}
        parsed = parse_alert(detail)
        roles = {o["value"]: o["role"] for o in parsed["observables"]["path"]}
        self.assertEqual(roles, {"C:\\a\\actor.exe": "process", "C:\\b\\target.dll": "object", "C:\\c\\parent.exe": "parent"})
        self.assertEqual({o["value"]: o["role"] for o in parsed["observables"]["hash"]},
                         {"a" * 40: "process", "b" * 40: "object"})
        self.assertEqual(sorted(o["value"] for o in parsed["observables"]["ip"]), ["192.0.2.1", "2001:db8::1"])
        self.assertEqual(parsed["endpoints"][0]["name"], "PC-ALIAS")


class FieldStateTests(unittest.TestCase):
    def test_absent_empty_and_unrecognized_are_different(self):
        absent = parse_alert({"id": "x"})
        self.assertEqual(absent["field_states"]["impactScope"], "absent")
        self.assertEqual(absent["field_states"]["indicators"], "absent")
        self.assertIn("absent, empty and unrecognized", absent["extraction_note"])
        empty = parse_alert({"impactScope": {"entities": []}, "indicators": []})
        self.assertEqual(empty["field_states"]["impactScope.entities"], "empty")
        self.assertEqual(empty["field_states"]["indicators"], "empty")
        odd = parse_alert({"impactScope": "unexpected", "indicators": {"not": "a list"},
                           "matchedRules": [{"matchedFilters": "x"}]})
        self.assertEqual(odd["field_states"]["impactScope"], "unrecognized")
        self.assertEqual(odd["field_states"]["indicators"], "unrecognized")
        unknown_entity = parse_alert({"impactScope": {"entities": [{"entityType": "container", "entityValue": {"k": 1}}]}})
        self.assertEqual(unknown_entity["entities"][0]["state"], "unrecognized entity shape")
        self.assertEqual(unknown_entity["entities"][0]["shape"], {"k": "int"})

    def test_shape_never_contains_values_and_text_is_not_scraped(self):
        parsed = parse_alert(ALERT)
        self.assertNotIn(HOST, str(parsed["shape"]))
        self.assertNotIn("203.0.113.99", str(parsed["observables"]))
        self.assertNotIn("evil.example.test", str(parsed["observables"]))

    def test_long_values_are_kept_and_cuts_are_explicit(self):
        long_cmd = "powershell.exe -c " + "A" * 3000
        parsed = parse_alert({"indicators": [{"id": 5, "type": "command_line", "field": "processCmd", "value": long_cmd}]})
        self.assertEqual(parsed["observables"]["command"][0]["value"], long_cmd)  # not cut to 240
        huge = parse_alert({"indicators": [{"id": 6, "type": "command_line", "value": "B" * (MAX_VALUE + 10)}]})
        item = huge["observables"]["command"][0]
        self.assertTrue(item["cut_by_bridge"])
        self.assertEqual(len(item["value"]), MAX_VALUE)
        self.assertIn("indicators[0].value", huge["field_states"]["cut_by_bridge"])


if __name__ == "__main__":
    unittest.main()
