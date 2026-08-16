"""Tests for DRRA-076 raw OTRF event ingestion and IoB feature extraction."""

import os

from vigil.ingest import classify_event, extract_windows

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "otrf_sample.jsonl")


def test_event_classification():
    assert classify_event({"EventID": 11, "Channel": "Sysmon"}) == "file"
    assert classify_event({"EventID": 4624, "Channel": "Security", "LogonType": "3"}) == "lateral"
    assert classify_event({"EventID": 4624, "Channel": "Security", "LogonType": "2"}) is None
    assert classify_event({"EventID": 4672, "Channel": "Security"}) == "privesc"
    assert classify_event({"EventID": 10, "Channel": "Sysmon",
                           "TargetImage": "C:\\Windows\\System32\\lsass.exe"}) == "privesc"
    assert classify_event({"EventID": 10, "Channel": "Sysmon",
                           "TargetImage": "C:\\notepad.exe"}) is None
    assert classify_event({"EventID": 4688, "Channel": "Security",
                           "CommandLine": "vssadmin delete shadows /all"}) == "shadow"
    assert classify_event({"EventID": 4634, "Channel": "Security"}) is None


def test_extract_windows_from_fixture():
    feats, stats = extract_windows(FIXTURE, window_seconds=10.0)
    assert stats.total_events == 11
    assert stats.hosts == {"WORKSTATION5"}
    # every IoB family present in the fixture is counted
    assert stats.signal_events["file"] == 3
    assert stats.signal_events["lateral"] == 3
    assert stats.signal_events["privesc"] == 2
    assert stats.signal_events["shadow"] == 2
    # one 10-second window covering the whole sample
    assert len(feats) == 1
    w = feats[0]
    assert w.host == "WORKSTATION5"
    assert w.file_rename_rate == 0.3          # 3 file events / 10 s
    assert w.shadow_copy_deletion_rate == 0.2  # 2 shadow-delete events / 10 s


def test_iob_vector_roundtrip():
    feats, _ = extract_windows(FIXTURE, window_seconds=10.0)
    vec = feats[0].as_iob()
    assert vec.as_list() == [0.3, 0.3, 0.2, 0.2]


def test_empty_or_missing_is_safe(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    feats, stats = extract_windows(str(empty))
    assert feats == [] and stats.total_events == 0


# --- DRRA-076 finding 7: integration test on a PINNED REAL OTRF sample -------

import os as _os

_FIXTURES = _os.path.join(_os.path.dirname(__file__), "fixtures")
_REAL = _os.path.join(_FIXTURES, "otrf_real_lsass_sample.jsonl")


def test_real_otrf_sample_parses_and_scores():
    """Parse a verbatim subset of a real, pinned OTRF LSASS-dump capture
    (psh_lsass_memory_dump_comsvcs @ commit d9d40ef1) and assert measured signals."""
    from vigil.ingest import extract_windows
    feats, stats = extract_windows(_REAL, window_seconds=10.0)
    assert stats.total_events == 23            # exact — pinned real fixture
    assert stats.malformed_lines == 0          # real capture parses cleanly
    assert stats.hosts == {"WORKSTATION5"}
    assert stats.signal_events["privesc"] >= 5  # real LSASS ProcessAccess signals
    assert stats.total_signals >= 6
    assert len(feats) >= 1                      # at least one populated window
    # the ingested real window is scoreable by the model
    from vigil.ml_model import load_or_train_ensemble
    model = load_or_train_ensemble()
    for w in feats:
        d = model.score(w.as_iob())
        assert d.backend  # scores without error


def test_malformed_json_lines_are_counted_not_silent():
    import tempfile
    from vigil.ingest import extract_windows
    good = ('{"EventID":10,"Channel":"Microsoft-Windows-Sysmon/Operational",'
            '"Hostname":"H1","TimeCreated":"2020-10-18 19:50:09.123","TargetImage":"C:\\\\lsass.exe"}')
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write(good + "\n")
        fh.write("{ this is not valid json \n")   # malformed
        fh.write("also not json}\n")               # malformed
        path = fh.name
    _feats, stats = extract_windows(path, window_seconds=10.0)
    _os.unlink(path)
    assert stats.malformed_lines == 2             # counted, not silently dropped
    assert stats.total_events == 1
