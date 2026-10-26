"""A small JSON Schema (2020-12) check, for the keywords OpenVEX's schema uses: $ref to $defs, type, properties,
required, additionalProperties, enum, const, items, minItems, uniqueItems, minimum, allOf, anyOf, oneOf and
if/then/else. `format` is an annotation, as 2020-12 has it. CI has no jsonschema; where it's installed, the test
asks it too."""


def errors(instance, schema: dict, root: dict | None = None, at: str = "$") -> list[str]:
    root = root or schema
    out: list[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return [f"{at}: can't follow {ref}"]
        target = root
        for part in ref[2:].split("/"):
            target = target[part]
        out += errors(instance, target, root, at)
    kind = schema.get("type")
    if kind and not is_type(instance, kind):
        return out + [f"{at}: not {kind}"]
    if "const" in schema and instance != schema["const"]:
        out.append(f"{at}: not {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        out.append(f"{at}: {instance!r} not one of {schema['enum']}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool) and "minimum" in schema \
            and instance < schema["minimum"]:
        out.append(f"{at}: below {schema['minimum']}")
    if isinstance(instance, dict):
        props = schema.get("properties") or {}
        for name in schema.get("required") or []:
            if name not in instance:
                out.append(f"{at}: needs {name}")
        for name, value in instance.items():
            if name in props:
                out += errors(value, props[name], root, f"{at}.{name}")
            elif schema.get("additionalProperties") is False:
                out.append(f"{at}: {name} isn't allowed")
            elif isinstance(schema.get("additionalProperties"), dict):
                out += errors(value, schema["additionalProperties"], root, f"{at}.{name}")
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            out.append(f"{at}: fewer than {schema['minItems']} items")
        if schema.get("uniqueItems") and len({repr(sorted_json(x)) for x in instance}) != len(instance):
            out.append(f"{at}: items repeat")
        if isinstance(schema.get("items"), dict):
            for n, item in enumerate(instance):
                out += errors(item, schema["items"], root, f"{at}[{n}]")
    for sub in schema.get("allOf") or []:
        out += errors(instance, sub, root, at)
    if "anyOf" in schema and not any(not errors(instance, sub, root, at) for sub in schema["anyOf"]):
        out.append(f"{at}: matches none of anyOf")
    if "oneOf" in schema and sum(1 for sub in schema["oneOf"] if not errors(instance, sub, root, at)) != 1:
        out.append(f"{at}: doesn't match exactly one of oneOf")
    if "if" in schema:
        branch = schema.get("then") if not errors(instance, schema["if"], root, at) else schema.get("else")
        if branch:
            out += errors(instance, branch, root, at)
    return out


def is_type(value, kind) -> bool:
    if isinstance(kind, list):
        return any(is_type(value, k) for k in kind)
    return {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool), "null": value is None}.get(kind, True)


def sorted_json(x):
    if isinstance(x, dict):
        return sorted((k, sorted_json(v)) for k, v in x.items())
    if isinstance(x, list):
        return [sorted_json(v) for v in x]
    return x
