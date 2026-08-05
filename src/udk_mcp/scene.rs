//! Bounded, selection-free queries over actors loaded by the editor.
//!
//! UE3's native `OBJ LIST` path already walks the object table with the
//! engine's own class checks. Using it here avoids baking another global object
//! array address and layout into the bridge. The human-oriented output is
//! parsed immediately and only compact, stable object paths cross the MCP
//! boundary.

use super::{json_escape, run_static_exec, validate_identifier};

pub(super) const DEFAULT_LIMIT: usize = 50;
pub(super) const MAX_LIMIT: usize = 200;
pub(super) const MAX_OFFSET: usize = 50_000;
const MAX_FILTER_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListedActor {
    class_name: String,
    path: String,
    name: String,
    level: String,
    map: String,
    num_bytes: u64,
    max_bytes: u64,
    resource_kib: u64,
    true_resource_kib: u64,
}

fn valid_local_filter(value: &str) -> bool {
    value.len() <= MAX_FILTER_LENGTH
        && !value
            .chars()
            .any(|character| character == '\0' || character.is_control())
}

pub(super) fn validate_find(
    class_name: &str,
    query: &str,
    level: &str,
    offset: usize,
    limit: usize,
) -> Result<(), String> {
    validate_identifier(class_name, false)?;
    if !valid_local_filter(query) {
        return Err(format!(
            "query must be at most {MAX_FILTER_LENGTH} characters and contain no control characters"
        ));
    }
    if !valid_local_filter(level) {
        return Err(format!(
            "level must be at most {MAX_FILTER_LENGTH} characters and contain no control characters"
        ));
    }
    if offset > MAX_OFFSET {
        return Err(format!("offset must be at most {MAX_OFFSET}"));
    }
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
    }
    Ok(())
}

fn parse_obj_list_line(line: &str) -> Option<ListedActor> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // A detailed OBJ LIST row is:
    //   <Class> <Object.Path> <NumBytes> <MaxBytes> <ResKBytes> <TrueResKBytes>
    // Summary rows end their sizes in K and therefore fail the integer parse.
    if fields.len() != 6 {
        return None;
    }
    let num_bytes = fields[2].parse().ok()?;
    let max_bytes = fields[3].parse().ok()?;
    let resource_kib = fields[4].parse().ok()?;
    let true_resource_kib = fields[5].parse().ok()?;
    let path = fields[1].to_string();
    let name = path
        .rsplit_once('.')
        .map_or(path.as_str(), |(_, name)| name)
        .to_string();
    let level = path
        .rsplit_once('.')
        .map_or("", |(level, _)| level)
        .to_string();
    let map = path
        .split(['.', ':'])
        .next()
        .unwrap_or_default()
        .to_string();
    Some(ListedActor {
        class_name: fields[0].to_string(),
        path,
        name,
        level,
        map,
        num_bytes,
        max_bytes,
        resource_kib,
        true_resource_kib,
    })
}

fn matches_filters(actor: &ListedActor, query: &str, level: &str) -> bool {
    let query = query.to_ascii_lowercase();
    let level = level.to_ascii_lowercase();
    let query_match = query.is_empty()
        || actor.name.to_ascii_lowercase().contains(&query)
        || actor.path.to_ascii_lowercase().contains(&query)
        || actor.class_name.to_ascii_lowercase().contains(&query);
    let level_match = level.is_empty() || actor.level.to_ascii_lowercase().contains(&level);
    query_match && level_match
}

fn actor_json(actor: &ListedActor) -> String {
    format!(
        r#"{{"name":"{}","path":"{}","fullName":"{} {}","class":"{}","map":"{}","level":"{}","memory":{{"numBytes":{},"maxBytes":{},"resourceKiB":{},"trueResourceKiB":{}}}}}"#,
        json_escape(&actor.name),
        json_escape(&actor.path),
        json_escape(&actor.class_name),
        json_escape(&actor.path),
        json_escape(&actor.class_name),
        json_escape(&actor.map),
        json_escape(&actor.level),
        actor.num_bytes,
        actor.max_bytes,
        actor.resource_kib,
        actor.true_resource_kib,
    )
}

pub(super) fn find_actors(
    class_name: &str,
    query: &str,
    level: &str,
    offset: usize,
    limit: usize,
) -> Result<String, String> {
    validate_find(class_name, query, level, offset, limit)?;
    let command = format!("OBJ LIST CLASS={class_name} ALPHASORT");
    let (handled, output) = run_static_exec(&command)?;
    if !handled {
        return Err(format!("UE3 did not handle '{command}'"));
    }

    let parsed: Vec<ListedActor> = output.lines().filter_map(parse_obj_list_line).collect();
    let matches: Vec<&ListedActor> = parsed
        .iter()
        .filter(|actor| matches_filters(actor, query, level))
        .collect();
    let total_matches = matches.len();
    let page = matches
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(actor_json)
        .collect::<Vec<_>>();
    let next_offset = offset
        .checked_add(page.len())
        .filter(|next| *next < total_matches)
        .map_or_else(|| "null".to_string(), |next| next.to_string());
    let output_complete = output
        .lines()
        .rev()
        .any(|line| line.trim().contains(" Objects ("));

    Ok(format!(
        r#"{{"source":"UE3 OBJ LIST","classFilter":"{}","query":"{}","levelFilter":"{}","offset":{offset},"limit":{limit},"parsedActorCount":{},"totalMatches":{total_matches},"returnedCount":{},"nextOffset":{next_offset},"truncated":{},"sourceOutputComplete":{output_complete},"actors":[{}]}}"#,
        json_escape(class_name),
        json_escape(query),
        json_escape(level),
        parsed.len(),
        page.len(),
        next_offset != "null",
        page.join(","),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> ListedActor {
        ListedActor {
            class_name: "StaticMeshActor".to_string(),
            path: "DM-Test.TheWorld:PersistentLevel.SM_Crate_2".to_string(),
            name: "SM_Crate_2".to_string(),
            level: "DM-Test.TheWorld:PersistentLevel".to_string(),
            map: "DM-Test".to_string(),
            num_bytes: 640,
            max_bytes: 768,
            resource_kib: 4,
            true_resource_kib: 5,
        }
    }

    #[test]
    fn parses_detailed_obj_list_rows_only() {
        let parsed = parse_obj_list_line(
            "StaticMeshActor DM-Test.TheWorld:PersistentLevel.SM_Crate_2 640 768 4 5",
        )
        .unwrap();
        assert_eq!(parsed, actor());
        assert!(parse_obj_list_line("StaticMeshActor 1 1K 1K 1K 1K").is_none());
        assert!(parse_obj_list_line("123 Objects (1.0M / 1.0M)").is_none());
    }

    #[test]
    fn filters_name_path_class_and_level_case_insensitively() {
        let value = actor();
        assert!(matches_filters(&value, "crate", ""));
        assert!(matches_filters(&value, "STATICMESH", ""));
        assert!(matches_filters(&value, "dm-test", "persistentlevel"));
        assert!(!matches_filters(&value, "playerstart", ""));
        assert!(!matches_filters(&value, "", "sublevel"));
    }

    #[test]
    fn search_limits_are_bounded() {
        assert!(validate_find("Actor", "", "", 0, DEFAULT_LIMIT).is_ok());
        assert!(validate_find("Actor", "", "", MAX_OFFSET + 1, 1).is_err());
        assert!(validate_find("Actor", "", "", 0, MAX_LIMIT + 1).is_err());
        assert!(validate_find("Actor;QUIT", "", "", 0, 1).is_err());
    }
}
