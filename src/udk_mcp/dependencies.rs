//! Bounded reference-graph traversal for one exact object path.
//!
//! The two directions are not symmetric, and the asymmetry is a property of the
//! engine rather than a shortcut taken here.
//!
//! Outbound edges come from UE3's `OBJ DUMP`, which exports one object's
//! reflected properties through the owning `UProperty`. That is a single-object
//! operation, so following it to depth costs one export per node.
//!
//! Inbound edges come from `UObject::OutputReferencers` via `OBJ REFS`, which
//! answers "who points at this" by serialising **every** loaded object through
//! `FArchiveFindCulprit`. One call is a whole-heap scan. Recursing it is
//! therefore budgeted explicitly rather than bounded only by depth, and the
//! budget is reported so a truncated inbound answer is never mistaken for a
//! complete one.

use std::collections::{HashMap, HashSet, VecDeque};

use super::{
    actor_identity, find_object_by_path, json_escape, object_path_from_full_name, run_static_exec,
    validate_identifier,
};

pub(super) const DEFAULT_MAX_DEPTH: usize = 2;
pub(super) const MAX_MAX_DEPTH: usize = 8;
pub(super) const DEFAULT_MAX_NODES: usize = 60;
pub(super) const MAX_MAX_NODES: usize = 400;
pub(super) const DEFAULT_INBOUND_SCANS: usize = 1;
pub(super) const MAX_INBOUND_SCANS: usize = 8;
const MAX_EDGES_PER_NODE: usize = 200;
/// A node budget bounds how many objects are expanded, not how many edges
/// they produce, so the edge list needs its own ceiling.
const MAX_TOTAL_EDGES: usize = 2000;
const MAX_CLASS_FILTER_LENGTH: usize = 64;
const MAX_PROPERTY_LENGTH: usize = 128;
const MAX_PATH_LENGTH: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Outbound,
    Inbound,
    Both,
}

impl Direction {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "outbound" => Ok(Direction::Outbound),
            "inbound" => Ok(Direction::Inbound),
            "both" => Ok(Direction::Both),
            _ => Err("direction must be 'outbound', 'inbound', or 'both'".to_string()),
        }
    }

    fn id(self) -> &'static str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
            Direction::Both => "both",
        }
    }

    fn wants_outbound(self) -> bool {
        matches!(self, Direction::Outbound | Direction::Both)
    }

    fn wants_inbound(self) -> bool {
        matches!(self, Direction::Inbound | Direction::Both)
    }
}

/// One reference, already reduced to the identity of both ends. Edges are keyed
/// on the pair plus the property so a struct that points at the same object
/// twice through different members stays two distinct facts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Edge {
    from: String,
    to: String,
    property: Option<String>,
    direction: &'static str,
    /// A genuine back edge: the far end is the near end, or an ancestor of it in
    /// the traversal tree. Reported, never followed.
    cycle: bool,
    /// The far end was already discovered by another branch. That is a diamond
    /// rather than a cycle, and conflating the two would describe most object
    /// graphs as almost entirely cyclic.
    revisit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    full_name: String,
    class_name: String,
    object_path: String,
    depth: usize,
    /// Set when the node was reached but not itself expanded, so a caller can
    /// tell a leaf from a frontier.
    expanded: bool,
}

fn identity_parts(full_name: &str) -> (String, String) {
    match full_name.split_once(' ') {
        Some((class_name, path)) => (class_name.to_string(), path.to_string()),
        None => (String::new(), full_name.to_string()),
    }
}

/// UE3 exports an object reference as `Class'Path.To.Object'`. Struct and array
/// values embed the same token, so one scanner covers every property shape
/// without needing to understand the value grammar around it.
fn extract_object_references(value: &str) -> Vec<String> {
    let mut found = Vec::new();
    let bytes = value.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(quote) = value[cursor..].find('\'').map(|index| cursor + index) else {
            break;
        };
        // Walk back over the class identifier that must precede the quote.
        let mut start = quote;
        while start > 0 {
            let previous = bytes[start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' {
                start -= 1;
            } else {
                break;
            }
        }
        let Some(end) = value[quote + 1..].find('\'').map(|index| quote + 1 + index) else {
            break;
        };
        let class_name = &value[start..quote];
        let path = &value[quote + 1..end];
        if !class_name.is_empty()
            && !path.is_empty()
            && path.len() <= MAX_PATH_LENGTH
            && path != "None"
            && !path.contains(char::is_whitespace)
        {
            found.push(format!("{class_name} {path}"));
        }
        cursor = end + 1;
    }
    found
}

/// `OBJ DUMP` output is `  Name=Value`, `  Name[i]=Value` for static arrays and
/// `  Name(i)=Value` for dynamic ones, under `=== Class properties ===`
/// headers. Only the property name is needed here; the value is scanned for
/// object tokens.
fn parse_dump_output(output: &str) -> (Vec<(String, String)>, bool) {
    let mut references = Vec::new();
    let mut truncated = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("===") || trimmed.starts_with("***") {
            continue;
        }
        // UE3 stops exporting a dynamic array at 100 elements and says so.
        if trimmed.starts_with("... ") && trimmed.ends_with(" more elements") {
            truncated = true;
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        let property = name
            .split(['[', '('])
            .next()
            .unwrap_or(name)
            .trim()
            .to_string();
        if property.is_empty() || property.len() > MAX_PROPERTY_LENGTH {
            continue;
        }
        for reference in extract_object_references(value) {
            references.push((property.clone(), reference));
        }
    }
    (references, truncated)
}

/// The referencer lines of `OBJ REFS`: `   <Class> <Path> (<count>)` followed by
/// indented `      <n>) <property full name>` detail lines.
fn parse_refs_output(output: &str) -> Vec<(String, Option<String>)> {
    let mut referencers: Vec<(String, Option<String>)> = Vec::new();
    let mut current: Option<String> = None;
    let mut current_properties = 0usize;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("External referencers of ")
            || trimmed.starts_with("Internal referencers of ")
        {
            current = None;
            continue;
        }
        if trimmed.starts_with("Shortest reachability from root to ") {
            break;
        }
        let leading_spaces = line.len().saturating_sub(line.trim_start().len());
        if leading_spaces >= 6 {
            let Some(referencer) = current.clone() else {
                continue;
            };
            let Some((_, detail)) = trimmed.split_once(") ") else {
                continue;
            };
            let property = if detail == "[[native reference]]" {
                None
            } else {
                // A property full name is `Class Outer:Property`; the caller
                // only wants the member, not the declaring class chain.
                Some(
                    detail
                        .rsplit([':', '.', ' '])
                        .next()
                        .unwrap_or(detail)
                        .to_string(),
                )
            };
            referencers.push((referencer, property));
            current_properties += 1;
            continue;
        }
        if leading_spaces >= 3 {
            if let Some(previous) = current.take() {
                // A referencer whose detail lines were all filtered out still
                // references the object; keep it as a property-less edge.
                if current_properties == 0 {
                    referencers.push((previous, None));
                }
            }
            current_properties = 0;
            let identity = trimmed
                .rsplit_once(" (")
                .map_or(trimmed, |(identity, _)| identity);
            if !identity.is_empty() {
                current = Some(identity.to_string());
            }
        }
    }
    if let Some(previous) = current {
        if current_properties == 0 {
            referencers.push((previous, None));
        }
    }
    referencers
}

pub(super) fn validate_query(
    direction: &str,
    class_filter: &str,
    max_depth: usize,
    max_nodes: usize,
    max_inbound_scans: usize,
) -> Result<(), String> {
    Direction::parse(direction)?;
    if !class_filter.is_empty() {
        if class_filter.len() > MAX_CLASS_FILTER_LENGTH {
            return Err(format!(
                "classFilter must be at most {MAX_CLASS_FILTER_LENGTH} characters"
            ));
        }
        if !class_filter
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Err("classFilter must be a bare UE3 class name".to_string());
        }
    }
    if !(1..=MAX_MAX_DEPTH).contains(&max_depth) {
        return Err(format!("maxDepth must be between 1 and {MAX_MAX_DEPTH}"));
    }
    if !(1..=MAX_MAX_NODES).contains(&max_nodes) {
        return Err(format!("maxNodes must be between 1 and {MAX_MAX_NODES}"));
    }
    if !(1..=MAX_INBOUND_SCANS).contains(&max_inbound_scans) {
        return Err(format!(
            "maxInboundScans must be between 1 and {MAX_INBOUND_SCANS}"
        ));
    }
    Ok(())
}

fn outbound_edges(full_name: &str) -> Result<(Vec<(String, String)>, bool), String> {
    let (class_name, path) = identity_parts(full_name);
    if class_name.is_empty() {
        return Err(format!("'{full_name}' has no class prefix"));
    }
    validate_identifier(&class_name, false)?;
    let (handled, output) = run_static_exec(&format!("OBJ DUMP CLASS={class_name} NAME={path}"))?;
    if !handled {
        return Err("UE3 did not handle the property dump".to_string());
    }
    Ok(parse_dump_output(&output))
}

fn inbound_edges(full_name: &str) -> Result<Vec<(String, Option<String>)>, String> {
    let (class_name, path) = identity_parts(full_name);
    if class_name.is_empty() {
        return Err(format!("'{full_name}' has no class prefix"));
    }
    validate_identifier(&class_name, false)?;
    let (handled, output) = run_static_exec(&format!("OBJ REFS CLASS={class_name} NAME={path}"))?;
    if !handled {
        return Err("UE3 did not handle the object-reference query".to_string());
    }
    Ok(parse_refs_output(&output))
}

struct Traversal {
    nodes: HashMap<String, Node>,
    /// Traversal-tree parent of each discovered node, so a back edge can be
    /// told apart from a diamond by walking up from the near end.
    parents: HashMap<String, String>,
    order: Vec<String>,
    edges: Vec<Edge>,
    seen_edges: HashSet<Edge>,
    failures: Vec<(String, String)>,
    node_limit_reached: bool,
    edge_limit_reached: bool,
    value_truncated: bool,
    inbound_scans_used: usize,
    inbound_scan_budget_reached: bool,
}

impl Traversal {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            parents: HashMap::new(),
            order: Vec::new(),
            edges: Vec::new(),
            seen_edges: HashSet::new(),
            failures: Vec::new(),
            node_limit_reached: false,
            edge_limit_reached: false,
            value_truncated: false,
            inbound_scans_used: 0,
            inbound_scan_budget_reached: false,
        }
    }

    fn insert_node(&mut self, full_name: &str, depth: usize, max_nodes: usize) -> bool {
        if self.nodes.contains_key(full_name) {
            return true;
        }
        if self.nodes.len() >= max_nodes {
            self.node_limit_reached = true;
            return false;
        }
        let (class_name, object_path) = identity_parts(full_name);
        self.nodes.insert(
            full_name.to_string(),
            Node {
                full_name: full_name.to_string(),
                class_name,
                object_path,
                depth,
                expanded: false,
            },
        );
        self.order.push(full_name.to_string());
        true
    }

    fn record_parent(&mut self, child: &str, parent: &str) {
        if child != parent {
            self.parents
                .entry(child.to_string())
                .or_insert_with(|| parent.to_string());
        }
    }

    fn is_ancestor(&self, candidate: &str, of: &str) -> bool {
        if candidate == of {
            return true;
        }
        let mut cursor = of;
        // The walk is bounded by the node budget, so a malformed parent chain
        // cannot spin here.
        for _ in 0..self.nodes.len() + 1 {
            match self.parents.get(cursor) {
                Some(parent) => {
                    if parent == candidate {
                        return true;
                    }
                    cursor = parent;
                }
                None => return false,
            }
        }
        false
    }

    fn push_edge(&mut self, edge: Edge) {
        if self.edges.len() >= MAX_TOTAL_EDGES {
            self.edge_limit_reached = true;
            return;
        }
        if self.seen_edges.insert(edge.clone()) {
            self.edges.push(edge);
        }
    }
}

fn class_allowed(class_filter: &str, class_name: &str) -> bool {
    class_filter.is_empty() || class_filter.eq_ignore_ascii_case(class_name)
}

pub(super) fn graph(
    object_path: &str,
    direction: &str,
    class_filter: &str,
    max_depth: usize,
    max_nodes: usize,
    max_inbound_scans: usize,
) -> Result<String, String> {
    validate_query(
        direction,
        class_filter,
        max_depth,
        max_nodes,
        max_inbound_scans,
    )?;
    let direction = Direction::parse(direction)?;
    let object = find_object_by_path(object_path)?;
    let (_, root_full_name, _) = actor_identity(object)?;
    let resolved_path = object_path_from_full_name(&root_full_name).to_string();

    let mut traversal = Traversal::new();
    traversal.insert_node(&root_full_name, 0, max_nodes);
    let mut queue = VecDeque::new();
    queue.push_back((root_full_name.clone(), 0usize));
    let mut visited = HashSet::new();
    visited.insert(root_full_name.clone());

    while let Some((full_name, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        let mut expanded = false;

        if direction.wants_outbound() {
            match outbound_edges(&full_name) {
                Ok((references, truncated)) => {
                    expanded = true;
                    traversal.value_truncated |= truncated;
                    for (property, target) in references.into_iter().take(MAX_EDGES_PER_NODE) {
                        let (target_class, _) = identity_parts(&target);
                        if !class_allowed(class_filter, &target_class) {
                            continue;
                        }
                        let cycle = traversal.is_ancestor(&target, &full_name);
                        let revisit = !cycle && visited.contains(&target);
                        let admitted = traversal.insert_node(&target, depth + 1, max_nodes);
                        if admitted {
                            traversal.record_parent(&target, &full_name);
                        }
                        traversal.push_edge(Edge {
                            from: full_name.clone(),
                            to: target.clone(),
                            property: Some(property),
                            direction: "outbound",
                            cycle,
                            revisit,
                        });
                        if admitted && !cycle && visited.insert(target.clone()) {
                            queue.push_back((target, depth + 1));
                        }
                    }
                }
                Err(reason) => traversal.failures.push((full_name.clone(), reason)),
            }
        }

        if direction.wants_inbound() {
            if traversal.inbound_scans_used >= max_inbound_scans {
                traversal.inbound_scan_budget_reached = true;
            } else {
                traversal.inbound_scans_used += 1;
                match inbound_edges(&full_name) {
                    Ok(referencers) => {
                        expanded = true;
                        for (source, property) in referencers.into_iter().take(MAX_EDGES_PER_NODE) {
                            let (source_class, _) = identity_parts(&source);
                            if !class_allowed(class_filter, &source_class) {
                                continue;
                            }
                            let cycle = traversal.is_ancestor(&source, &full_name);
                            let revisit = !cycle && visited.contains(&source);
                            let admitted = traversal.insert_node(&source, depth + 1, max_nodes);
                            if admitted {
                                traversal.record_parent(&source, &full_name);
                            }
                            traversal.push_edge(Edge {
                                from: source.clone(),
                                to: full_name.clone(),
                                property,
                                direction: "inbound",
                                cycle,
                                revisit,
                            });
                            if admitted && !cycle && visited.insert(source.clone()) {
                                queue.push_back((source, depth + 1));
                            }
                        }
                    }
                    Err(reason) => traversal.failures.push((full_name.clone(), reason)),
                }
            }
        }

        if expanded {
            if let Some(node) = traversal.nodes.get_mut(&full_name) {
                node.expanded = true;
            }
        }
    }

    let nodes = traversal
        .order
        .iter()
        .filter_map(|key| traversal.nodes.get(key))
        .map(|node| {
            format!(
                r#"{{"fullName":"{}","class":"{}","objectPath":"{}","depth":{},"expanded":{}}}"#,
                json_escape(&node.full_name),
                json_escape(&node.class_name),
                json_escape(&node.object_path),
                node.depth,
                node.expanded,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let edges = traversal
        .edges
        .iter()
        .map(|edge| {
            format!(
                r#"{{"direction":"{}","from":"{}","to":"{}","property":{},"cycle":{},"revisit":{}}}"#,
                edge.direction,
                json_escape(&edge.from),
                json_escape(&edge.to),
                edge.property.as_ref().map_or_else(
                    || "null".to_string(),
                    |property| format!("\"{}\"", json_escape(property))
                ),
                edge.cycle,
                edge.revisit,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let failures = traversal
        .failures
        .iter()
        .map(|(full_name, reason)| {
            format!(
                r#"{{"fullName":"{}","reason":"{}"}}"#,
                json_escape(full_name),
                json_escape(reason)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let cycle_count = traversal.edges.iter().filter(|edge| edge.cycle).count();
    let revisit_count = traversal.edges.iter().filter(|edge| edge.revisit).count();
    let truncated = traversal.node_limit_reached
        || traversal.edge_limit_reached
        || traversal.value_truncated
        || traversal.inbound_scan_budget_reached;

    Ok(format!(
        r#"{{"objectPath":"{}","fullName":"{}","direction":"{}","classFilter":{},"maxDepth":{max_depth},"maxNodes":{max_nodes},"maxInboundScans":{max_inbound_scans},"inboundScansUsed":{},"nodeCount":{},"edgeCount":{},"cycleEdgeCount":{cycle_count},"revisitEdgeCount":{revisit_count},"truncated":{truncated},"limits":{{"nodeLimitReached":{},"edgeLimitReached":{},"arrayValueTruncated":{},"inboundScanBudgetReached":{}}},"sources":{{"outbound":"UE3 OBJ DUMP reflected property export","inbound":"UE3 UObject::OutputReferencers via OBJ REFS"}},"coverage":"Outbound edges are reflected properties only; references held by native C++ members are invisible to property export. Inbound edges include native references but each one costs a full loaded-object scan, which is why they are budgeted separately from depth.","nodes":[{nodes}],"edges":[{edges}],"failures":[{failures}]}}"#,
        json_escape(&resolved_path),
        json_escape(&root_full_name),
        direction.id(),
        if class_filter.is_empty() {
            "null".to_string()
        } else {
            format!("\"{}\"", json_escape(class_filter))
        },
        traversal.inbound_scans_used,
        traversal.nodes.len(),
        traversal.edges.len(),
        traversal.node_limit_reached,
        traversal.edge_limit_reached,
        traversal.value_truncated,
        traversal.inbound_scan_budget_reached,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_object_tokens_from_property_values() {
        assert_eq!(
            extract_object_references("StaticMesh'Pkg.Group.Mesh'"),
            vec!["StaticMesh Pkg.Group.Mesh"]
        );
        assert_eq!(
            extract_object_references(
                "(Material=MaterialInstanceConstant'Pkg.MI',Scale=Texture2D'Pkg.Tex')"
            ),
            vec![
                "MaterialInstanceConstant Pkg.MI",
                "Texture2D Pkg.Tex"
            ]
        );
        assert!(extract_object_references("None").is_empty());
        assert!(extract_object_references("12.5").is_empty());
    }

    #[test]
    fn parses_obj_dump_property_lines() {
        let output = "\
*** Property dump for object 'StaticMeshActor Map.TheWorld:PersistentLevel.StaticMeshActor_0' ***
=== StaticMeshActor properties ===
  StaticMeshComponent=StaticMeshComponent'Map.TheWorld:PersistentLevel.StaticMeshActor_0.StaticMeshComponent_0'
=== Actor properties ===
  Components(0)=StaticMeshComponent'Map.TheWorld:PersistentLevel.StaticMeshActor_0.StaticMeshComponent_0'
  Components(1)=None
  Tag=StaticMeshActor
  ... 4 more elements
";
        let (references, truncated) = parse_dump_output(output);
        assert!(truncated);
        assert_eq!(references.len(), 2);
        assert_eq!(references[0].0, "StaticMeshComponent");
        assert_eq!(references[1].0, "Components");
        assert!(references[1]
            .1
            .ends_with("StaticMeshActor_0.StaticMeshComponent_0"));
    }

    #[test]
    fn parses_obj_refs_referencers_and_native_edges() {
        let output = "\
External referencers of StaticMesh Pkg.Mesh:
   StaticMeshComponent Map.TheWorld:PersistentLevel.Actor_0.Comp_0 (2)
      0) ObjectProperty Engine.StaticMeshComponent:StaticMesh
      1) [[native reference]]
   Level Map.TheWorld:PersistentLevel (1)
      0) [[native reference]]

Shortest reachability from root to StaticMesh Pkg.Mesh:
   ignored
";
        let referencers = parse_refs_output(output);
        assert_eq!(referencers.len(), 3);
        assert_eq!(
            referencers[0],
            (
                "StaticMeshComponent Map.TheWorld:PersistentLevel.Actor_0.Comp_0".to_string(),
                Some("StaticMesh".to_string())
            )
        );
        assert_eq!(referencers[1].1, None);
        assert_eq!(
            referencers[2],
            (
                "Level Map.TheWorld:PersistentLevel".to_string(),
                None
            )
        );
    }

    #[test]
    fn splits_class_and_path_from_full_names() {
        assert_eq!(
            identity_parts("StaticMesh Pkg.Group.Mesh"),
            ("StaticMesh".to_string(), "Pkg.Group.Mesh".to_string())
        );
        assert_eq!(
            identity_parts("Bare"),
            (String::new(), "Bare".to_string())
        );
    }

    #[test]
    fn query_bounds_are_enforced() {
        assert!(validate_query("outbound", "", DEFAULT_MAX_DEPTH, DEFAULT_MAX_NODES, 1).is_ok());
        assert!(validate_query("both", "StaticMesh", 1, 1, 1).is_ok());
        assert!(validate_query("sideways", "", 1, 1, 1).is_err());
        assert!(validate_query("outbound", "", 0, 1, 1).is_err());
        assert!(validate_query("outbound", "", MAX_MAX_DEPTH + 1, 1, 1).is_err());
        assert!(validate_query("outbound", "", 1, MAX_MAX_NODES + 1, 1).is_err());
        assert!(validate_query("outbound", "", 1, 1, MAX_INBOUND_SCANS + 1).is_err());
        assert!(validate_query("outbound", "Static Mesh", 1, 1, 1).is_err());
    }

    #[test]
    fn class_filter_matches_case_insensitively_and_passes_when_empty() {
        assert!(class_allowed("", "StaticMesh"));
        assert!(class_allowed("staticmesh", "StaticMesh"));
        assert!(!class_allowed("Texture2D", "StaticMesh"));
    }

    #[test]
    fn node_insertion_respects_the_node_limit() {
        let mut traversal = Traversal::new();
        assert!(traversal.insert_node("A Pkg.A", 0, 2));
        assert!(traversal.insert_node("B Pkg.B", 1, 2));
        assert!(!traversal.insert_node("C Pkg.C", 1, 2));
        assert!(traversal.node_limit_reached);
        // An already-known node is still reachable after the limit is hit.
        assert!(traversal.insert_node("A Pkg.A", 0, 2));
        assert_eq!(traversal.order.len(), 2);
    }

    #[test]
    fn duplicate_edges_collapse_but_distinct_properties_do_not() {
        let mut traversal = Traversal::new();
        let base = Edge {
            from: "A Pkg.A".to_string(),
            to: "B Pkg.B".to_string(),
            property: Some("Mesh".to_string()),
            direction: "outbound",
            cycle: false,
            revisit: false,
        };
        traversal.push_edge(base.clone());
        traversal.push_edge(base.clone());
        traversal.push_edge(Edge {
            property: Some("Other".to_string()),
            ..base
        });
        assert_eq!(traversal.edges.len(), 2);
    }
}
