//! Exact-path, selection-free reflected property reads.
//!
//! UE3's GETALL command already exports values through the owning UProperty,
//! preserving native formatting for object references, structs and arrays. The
//! extra step here is resolving and verifying the requested object first, then
//! filtering GETALL's name-based output back to that exact path.

use std::ffi::c_void;

use super::{
    actor_identity, find_object_by_path, json_escape, object_path_from_full_name,
    run_static_exec, validate_identifier,
};

#[derive(Debug, PartialEq, Eq)]
struct ExportedProperty {
    actual_name: String,
    value: Option<String>,
    elements: Vec<(usize, String)>,
}

pub(super) fn read_property(object_path: &str, property: &str) -> Result<String, String> {
    validate_identifier(property, false)?;
    let object = find_object_by_path(object_path)?;
    read_resolved_property(object, object_path, property)
}

fn read_resolved_property(
    object: *mut c_void,
    requested_path: &str,
    property: &str,
) -> Result<String, String> {
    let (name, full_name, class_name) = actor_identity(object)?;
    validate_identifier(&name, false)?;
    validate_identifier(&class_name, false)?;
    let resolved_path = object_path_from_full_name(&full_name);

    let (handled, output) = run_static_exec(&format!(
        "GETALL {class_name} {property} NAME={name} SHOWDEFAULTS"
    ))?;
    if !handled {
        return Err("UE3 did not handle the reflected property query".to_string());
    }
    if output
        .lines()
        .any(|line| line.trim_start().starts_with("Unrecognized property"))
    {
        return Err(format!(
            "property '{property}' does not exist on class '{class_name}'"
        ));
    }

    let exported = parse_getall_exact(&output, &class_name, resolved_path, property).ok_or_else(|| {
        format!(
            "UE3 exported no value for property '{property}' on exact object '{requested_path}'"
        )
    })?;

    let value = exported
        .value
        .as_ref()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_string());
    let elements = exported
        .elements
        .iter()
        .map(|(index, value)| {
            format!(
                "{{\"index\":{index},\"value\":\"{}\"}}",
                json_escape(value)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"objectPath\":\"{}\",\"fullName\":\"{}\",\"class\":\"{}\",\"property\":\"{}\",\"actualProperty\":\"{}\",\"collection\":{},\"value\":{value},\"elementCount\":{},\"elements\":[{elements}],\"handled\":true}}",
        json_escape(resolved_path),
        json_escape(&full_name),
        json_escape(&class_name),
        json_escape(property),
        json_escape(&exported.actual_name),
        exported.value.is_none(),
        exported.elements.len(),
    ))
}

fn parse_getall_exact(
    output: &str,
    class_name: &str,
    object_path: &str,
    property: &str,
) -> Option<ExportedProperty> {
    let mut lines = output.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let Some((_, body)) = trimmed.split_once(") ") else {
            continue;
        };
        let Some((left, right)) = body.split_once(" =") else {
            continue;
        };
        let Some((identity, actual_property)) = left.rsplit_once('.') else {
            continue;
        };
        let expected_identity = format!("{class_name} {object_path}");
        if !identity.eq_ignore_ascii_case(&expected_identity)
            || !actual_property.eq_ignore_ascii_case(property)
        {
            continue;
        }

        let scalar = right.strip_prefix(' ').unwrap_or(right);
        if !scalar.is_empty() {
            return Some(ExportedProperty {
                actual_name: actual_property.to_string(),
                value: Some(scalar.to_string()),
                elements: Vec::new(),
            });
        }

        let mut elements = Vec::new();
        while let Some(next) = lines.peek().copied() {
            let element = next.trim();
            let Some((index, value)) = element.split_once(':') else {
                break;
            };
            let Ok(index) = index.trim().parse::<usize>() else {
                break;
            };
            lines.next();
            elements.push((index, value.trim_start().to_string()));
        }
        return Some(ExportedProperty {
            actual_name: actual_property.to_string(),
            value: None,
            elements,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{parse_getall_exact, ExportedProperty};

    #[test]
    fn selects_only_the_exact_path_among_duplicate_names() {
        let output = concat!(
            "0) StaticMeshActor Other.TheWorld:PersistentLevel.Crate_0.DrawScale = 1.0\n",
            "1) StaticMeshActor Test.TheWorld:PersistentLevel.Crate_0.DrawScale = 2.5\n"
        );
        assert_eq!(
            parse_getall_exact(
                output,
                "StaticMeshActor",
                "Test.TheWorld:PersistentLevel.Crate_0",
                "drawscale"
            ),
            Some(ExportedProperty {
                actual_name: "DrawScale".to_string(),
                value: Some("2.5".to_string()),
                elements: Vec::new(),
            })
        );
    }

    #[test]
    fn parses_dynamic_and_fixed_array_elements() {
        let output = concat!(
            "0) WorldInfo Test.TheWorld:PersistentLevel.WorldInfo_0.StreamingLevels =\n",
            "\t0: LevelStreaming'Pkg.Level'\n",
            "\t1: None\n",
            "Log tail that is not part of the array\n"
        );
        assert_eq!(
            parse_getall_exact(
                output,
                "WorldInfo",
                "Test.TheWorld:PersistentLevel.WorldInfo_0",
                "StreamingLevels"
            ),
            Some(ExportedProperty {
                actual_name: "StreamingLevels".to_string(),
                value: None,
                elements: vec![
                    (0, "LevelStreaming'Pkg.Level'".to_string()),
                    (1, "None".to_string())
                ],
            })
        );
    }
}
