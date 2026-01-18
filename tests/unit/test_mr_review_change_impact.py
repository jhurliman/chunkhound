from chunkhound.services.mr_review.change_impact import _extract_endpoint_changes


def test_deleted_file_resets_current_file() -> None:
    diff_text = "\n".join(
        [
            "diff --git a/api/new_routes.py b/api/new_routes.py",
            "index 1111111..2222222 100644",
            "--- a/api/new_routes.py",
            "+++ b/api/new_routes.py",
            "@@ -1,2 +1,3 @@",
            "+@app.get(\"/api/new\")",
            "+def handler():",
            "+    return \"ok\"",
            "diff --git a/api/removed_routes.py b/api/removed_routes.py",
            "deleted file mode 100644",
            "index 3333333..0000000",
            "--- a/api/removed_routes.py",
            "+++ /dev/null",
            "@@ -1,2 +0,0 @@",
            "-@app.post(\"/api/removed\")",
            "-def removed():",
            "-    return \"gone\"",
        ]
    )

    changes = _extract_endpoint_changes(diff_text)

    assert len(changes) == 2
    assert changes[0].file_path == "api/new_routes.py"
    assert changes[0].path == "/api/new"
    assert changes[1].file_path == "api/removed_routes.py"
    assert changes[1].path == "/api/removed"
