from catexe.modules.sources.results import result_from_probe, source_error


def test_probe_statuses_are_distinct():
    assert result_from_probe(source="Demo", url="https://demo.test/alice", http_status=200, value=1).status == "found"
    assert result_from_probe(source="Demo", url="https://demo.test/alice", http_status=200, value=0).status == "not_found"
    assert result_from_probe(source="Demo", url="https://demo.test/alice", http_status=403, value=0).status == "blocked"
    assert result_from_probe(source="Demo", url="https://demo.test/alice", http_status=429, value=None).status == "rate_limited"


def test_result_keeps_legacy_unpacking():
    result = result_from_probe(source="Demo", url="https://demo.test", http_status=200, value=1)
    legacy_status, code = result
    assert (legacy_status, code) == ("trouvé", 200)


def test_error_is_not_reported_as_absence():
    result = source_error(source="Demo", url="https://demo.test", reason="timeout")
    assert result.status == "error"
    assert result.confidence == "none"
    assert result.to_dict()["reason"] == "timeout"
