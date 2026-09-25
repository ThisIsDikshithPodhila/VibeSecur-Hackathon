import base64
import json
import unittest

from vibesecur.issue_connectors import IssueConnectorError, connection_status, create_issue


LINEAR_ENV = {"LINEAR_API_KEY": "linear-secret", "LINEAR_TEAM_ID": "team-123"}
JIRA_ENV = {
    "JIRA_BASE_URL": "https://example.atlassian.net",
    "JIRA_EMAIL": "synthetic@example.invalid",
    "JIRA_API_TOKEN": "jira-secret",
    "JIRA_PROJECT_KEY": "DEMO",
    "JIRA_ISSUE_TYPE": "Task",
}


class IssueConnectorTests(unittest.TestCase):
    def test_connection_status_is_configuration_only_and_lists_missing_names(self):
        self.assertEqual(
            connection_status("linear", environ={"LINEAR_API_KEY": "x"}),
            {"provider": "linear", "configured": False, "connected": False, "missing": ["LINEAR_TEAM_ID"]},
        )
        self.assertEqual(connection_status("linear", environ=LINEAR_ENV)["connected"], True)

    def test_disconnected_create_never_calls_transport(self):
        called = []
        with self.assertRaises(IssueConnectorError) as caught:
            create_issue("linear", {"title": "Demo", "description": "Synthetic"}, environ={}, transport=lambda *args: called.append(args))
        self.assertEqual(caught.exception.code, "not_connected")
        self.assertEqual(called, [])

    def test_linear_uses_graphql_issue_create_and_requires_confirmed_result(self):
        observed = {}

        def transport(url, headers, body, timeout):
            observed.update(url=url, headers=headers, request=json.loads(body), timeout=timeout)
            result = {"data": {"issueCreate": {"success": True, "issue": {
                "id": "uuid-1", "identifier": "DEM-4", "title": "Broken demo", "url": "https://linear.app/demo/issue/DEM-4"
            }}}}
            return 200, json.dumps(result).encode()

        created = create_issue("linear", {
            "title": "Broken demo", "description": "synthetic details",
            "nativeFields": {"priority": 2, "labelIds": ["label-1"]},
        }, environ=LINEAR_ENV, transport=transport)
        self.assertEqual(observed["url"], "https://api.linear.app/graphql")
        self.assertEqual(observed["headers"]["Authorization"], "linear-secret")
        self.assertEqual(observed["request"]["variables"]["input"], {
            "teamId": "team-123", "title": "Broken demo", "description": "synthetic details",
            "priority": 2, "labelIds": ["label-1"],
        })
        self.assertEqual(created["key"], "DEM-4")
        self.assertEqual(observed["timeout"], 10)

    def test_linear_partial_graphql_error_never_reports_success(self):
        with self.assertRaises(IssueConnectorError) as caught:
            create_issue("linear", {"title": "Demo", "description": "text"}, environ=LINEAR_ENV,
                         transport=lambda *args: (200, b'{"errors":[{"message":"secret response"}]}'))
        self.assertEqual(caught.exception.code, "creation_unconfirmed")
        self.assertNotIn("secret response", str(caught.exception))

    def test_jira_sends_plain_text_as_adf_with_native_fields(self):
        observed = {}

        def transport(url, headers, body, timeout):
            observed.update(url=url, headers=headers, request=json.loads(body))
            # Jira REST v3 create commonly returns id/key/self, without fields.
            return 201, json.dumps({"id": "10001", "key": "DEMO-8", "self": "https://example.atlassian.net/rest/api/3/issue/10001"}).encode()

        result = create_issue("jira", {
            "title": "Synthetic issue", "description": "line one\nline two",
            "nativeFields": {"labels": ["vibesecur-demo"], "priority": {"name": "High"}},
        }, environ=JIRA_ENV, transport=transport)
        self.assertEqual(observed["url"], "https://example.atlassian.net/rest/api/3/issue")
        self.assertEqual(observed["headers"]["Authorization"], "Basic " + base64.b64encode(b"synthetic@example.invalid:jira-secret").decode())
        fields = observed["request"]["fields"]
        self.assertEqual(fields["project"], {"key": "DEMO"})
        self.assertEqual(fields["issuetype"], {"name": "Task"})
        self.assertEqual(fields["description"], {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": "line one\nline two"}]}
        ]})
        self.assertEqual(fields["labels"], ["vibesecur-demo"])
        self.assertEqual(result, {
            "provider": "jira", "id": "10001", "key": "DEMO-8", "title": "Synthetic issue",
            "url": "https://example.atlassian.net/browse/DEMO-8",
        })

    def test_jira_rejects_insecure_or_credential_bearing_base_url(self):
        for base_url in ("http://example.atlassian.net", "https://user:pass@example.atlassian.net", "https://example.atlassian.net?x=1"):
            with self.subTest(base_url=base_url), self.assertRaises(IssueConnectorError) as caught:
                create_issue("jira", {"title": "Demo", "description": "text"},
                             environ={**JIRA_ENV, "JIRA_BASE_URL": base_url}, transport=lambda *args: self.fail("network must not run"))
            self.assertEqual(caught.exception.code, "invalid_configuration")

    def test_provider_rejection_and_malformed_success_are_not_reported_as_created(self):
        for status, body, expected_code in (
            (403, b"private error response", "provider_error"),
                (201, b'{"id":"1","key":"bad key"}', "creation_unconfirmed"),
        ):
            with self.subTest(status=status), self.assertRaises(IssueConnectorError) as caught:
                create_issue("jira", {"title": "Demo", "description": "text"}, environ=JIRA_ENV,
                             transport=lambda *args: (status, body))
            self.assertEqual(caught.exception.code, expected_code)
            self.assertNotIn("private error response", str(caught.exception))

    def test_required_input_and_provider_fields_are_validated_before_transport(self):
        transport = lambda *args: self.fail("network must not run")
        for issue in ({"title": " ", "description": "x"}, {"title": "ok"},
                      {"title": "ok", "description": "x", "nativeFields": {"project": {"key": "OTHER"}}}):
            with self.subTest(issue=issue), self.assertRaises(IssueConnectorError):
                create_issue("jira", issue, environ=JIRA_ENV, transport=transport)
        with self.assertRaises(IssueConnectorError) as caught:
            create_issue("linear", {"title": "ok", "description": "x", "nativeFields": {"teamId": "other"}},
                         environ=LINEAR_ENV, transport=transport)
        self.assertEqual(caught.exception.code, "invalid_native_fields")


if __name__ == "__main__":
    unittest.main()
