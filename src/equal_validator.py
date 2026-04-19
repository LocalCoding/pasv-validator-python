"""Port of equal-validator.js for Python.

Python version drops JS-specific checks (var/let/const, trailing semicolons).
Only strict equality and whitespace-difference warnings remain.
"""


def validate_equal(solution: str | None, completed_solution: str | None) -> list[dict]:
    s = (solution or "").strip()
    o = (completed_solution or "").strip()

    if s == o:
        return [{"type": "passed"}]

    warnings: list[dict] = []

    warnings.append({
        "type": "notEqual",
        "message": "Your code does not match the sample",
    })

    s_no_space = "".join(s.split())
    o_no_space = "".join(o.split())
    s_space_count = sum(1 for c in s if c.isspace())
    o_space_count = sum(1 for c in o if c.isspace())

    if s_no_space == o_no_space and s_space_count != o_space_count:
        warnings.append({
            "type": "checkSpaces",
            "message": "Your solution is correct, but spaces do not match",
        })

    return warnings
