import gzip
import io
import zipfile

import pytest

import rebin as RB

CTX = RB.CTX


def make_zip(sizes):
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for index, size in enumerate(sizes):
            archive.writestr(f"item_{index}.bin", b"A" * size)
    return buffer.getvalue()


@pytest.mark.parametrize("size", [1024, 1025])
def test_gzip_expanded_limit(monkeypatch, size):
    monkeypatch.setattr(CTX, "MAX_EXPANDED_BYTES", 1024)
    data = gzip.compress(b"A" * size)

    if size > 1024:
        with pytest.raises(ValueError, match="expanded data limit"):
            CTX.run_ctx("gz", data)
    else:
        assert CTX.run_ctx("gz", data)


@pytest.mark.parametrize(
    "sizes", [[512, 512], [513, 512], [1025]],
)
def test_zip_expanded_limit(monkeypatch, sizes):
    monkeypatch.setattr(CTX, "MAX_EXPANDED_BYTES", 1024)
    data = make_zip(sizes)

    def forbidden_read(*args, **kwargs):
        raise AssertionError("Use streamed ZipFile.open, not ZipFile.read")

    monkeypatch.setattr(zipfile.ZipFile, "read", forbidden_read)

    if sum(sizes) > 1024:
        with pytest.raises(ValueError, match="expanded data limit"):
            CTX.run_ctx("docx", data)
    else:
        assert CTX.run_ctx("docx", data)


def test_zip_member_count_limit(monkeypatch):
    monkeypatch.setattr(CTX, "MAX_ZIP_MEMBERS", 2)
    data = make_zip([1, 1, 1])

    with pytest.raises(ValueError, match="member count limit"):
        CTX.run_ctx("docx", data)


def test_stream_limit_checks_actual_bytes(monkeypatch):
    monkeypatch.setattr(CTX, "ARCHIVE_READ_CHUNK", 128)
    stream = io.BytesIO(b"A" * 1025)

    with pytest.raises(ValueError, match="expanded data limit"):
        CTX._drain_limited(stream, 1024)

    assert stream.tell() == 1025


def test_concatenated_gzip_uses_one_total_limit(monkeypatch):
    monkeypatch.setattr(CTX, "MAX_EXPANDED_BYTES", 1024)
    data = gzip.compress(b"A" * 600) + gzip.compress(b"B" * 600)

    with pytest.raises(ValueError, match="expanded data limit"):
        CTX.run_ctx("gz", data)


@pytest.mark.parametrize(
    "events, expected",
    [
        (
            [(10, 4, "site"), (14, 6, "site")],
            [(10, 10, "site")],
        ),
        (
            [(10, 4, "first"), (14, 6, "second")],
            [(10, 4, "first"), (14, 6, "second")],
        ),
        (
            [(10, 4, "site"), (20, 6, "site")],
            [(10, 4, "site"), (20, 6, "site")],
        ),
    ],
)
def test_payload_read_normalization(events, expected):
    original = list(events)
    assert CTX._merge_payload_reads(events) == expected
    assert events == original


def test_zip_preserves_raw_read_events(monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_STORED,
    ) as archive:
        archive.writestr("payload.bin", b"A" * 70_000)

    captured = []
    original_class = CTX.CtxIO

    def capture_stream(data):
        stream = original_class(data)
        captured.append(stream)
        return stream

    monkeypatch.setattr(CTX, "CtxIO", capture_stream)
    log = CTX.run_ctx("docx", buffer.getvalue())
    stream = captured[0]

    assert log is stream.log
    assert len(stream.raw_log) > len(log)
    assert sum(size for _, size, _ in stream.raw_log) == sum(
        size for _, size, _ in log
    )
