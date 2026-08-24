#!/usr/bin/env bash
#
# MITRE ATT&CK APT Group TTP & IOC Scraper  (Bash port of MITRE-Scraper.ps1)
# ------------------------------------------------------------------------------
# Lists the MITRE ATT&CK threat groups and generates a compact Markdown (.md) +
# HTML cheat sheet per selected group:
#   * TTPs grouped by tactic - one row per technique:
#       TTP ID + full name | one-line topic descriptor | auto-generated "General Query"
#   * Software used (S-codes), attributed Campaigns, and heuristic IOCs at the bottom
#
# The General Query (KQL) is auto-generated from the technique's Detection
# Strategies / Analytics (the modern 'what to look for'), ECS fields, heuristic.
#
# Markdown files go to a 'markdown' folder, HTML files to an 'html' folder
# next to the script (or under --output).
#
# DATA SOURCE: the official MITRE CTI STIX 2.1 bundle that attack.mitre.org is
# generated from:
#   https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
# Downloaded once (~48 MB) and cached; a slim subset is cached to make later runs fast.
#
# REQUIREMENTS: jq, curl, GNU grep (grep -P), awk, sed.
#   Debian/Ubuntu:  sudo apt-get install -y jq curl grep
#
# USAGE:
#   ./MITRE-Scraper.sh                    # interactive: pick group(s) from a menu
#   ./MITRE-Scraper.sh -g G0007,G0006     # generate APT28 + APT1 non-interactively
#   ./MITRE-Scraper.sh -a                 # generate reports for every group
#   ./MITRE-Scraper.sh -a -m              # every group, HTML only
#   ./MITRE-Scraper.sh -g G0007 -r        # force re-download, then generate APT28
#
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
STIX_URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
GROUP_BASE_URL="https://attack.mitre.org/groups/"
TECH_BASE_URL="https://attack.mitre.org/techniques/"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR=""
OUT_DIR=""
REFRESH=0
ALL=0
NO_MD=0
NO_HTML=0
declare -a GROUP_ARGS=()

usage() {
  cat <<'EOF'
MITRE ATT&CK APT Group TTP & IOC Scraper (bash)

Usage: ./MITRE-Scraper.sh [options]

  -g, --group LIST   One or more group IDs or names, comma separated (e.g. G0007,G0006 or APT28)
  -a, --all          Generate reports for every group
  -o, --output DIR   Output directory (default: script folder)
  -c, --cache DIR    Cache directory (default: <script>/.cache)
  -r, --refresh      Force re-download of the STIX bundle
  -m, --no-markdown  Skip Markdown generation
  -H, --no-html      Skip HTML generation
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--group|--groups) shift; GROUP_ARGS+=("$1"); shift ;;
    -a|--all)            ALL=1; shift ;;
    -o|--output)         shift; OUT_DIR="$1"; shift ;;
    -c|--cache)          shift; CACHE_DIR="$1"; shift ;;
    -r|--refresh)        REFRESH=1; shift ;;
    -m|--no-markdown)    NO_MD=1; shift ;;
    -H|--no-html)        NO_HTML=1; shift ;;
    -h|--help)           usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

CACHE_DIR="${CACHE_DIR:-$SCRIPT_DIR/.cache}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR}"
BUNDLE_PATH="$CACHE_DIR/enterprise-attack.json"
SLIM_PATH="$CACHE_DIR/enterprise-attack.slim.json"
INDEX_DIR="$CACHE_DIR/_index"
MD_DIR="$OUT_DIR/markdown"
HTML_DIR="$OUT_DIR/html"

# -----------------------------------------------------------------------------
# Dependencies
# -----------------------------------------------------------------------------
for cmd in jq curl grep awk sed; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: '$cmd' is required (install with: apt-get install $cmd)." >&2; exit 1; }
done
if ! echo test | grep -qP 'test' 2>/dev/null; then
  echo "ERROR: GNU grep with -P (PCRE) support is required." >&2; exit 1
fi

# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------
say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

# jget <jq-filter> [<json>]  ->  raw value (json via arg $2, or via stdin heredoc)
jget()  { if [[ $# -ge 2 ]]; then jq -r "$1" <<<"$2"; else jq -r "$1"; fi; }
# jgetc <jq-filter> [<json>] ->  compact json
jgetc() { if [[ $# -ge 2 ]]; then jq -c "$1" <<<"$2"; else jq -c "$1"; fi; }

# ATT&CK code for an object (G/T/S/C code from external_references, or a prebuilt .code field)
code_of() { jget '([.external_references[]? | select(.source_name=="mitre-attack") | .external_id][0] // .code // "")' "$1"; }

# Clean MITRE rich text: <code> -> backticks, strip other HTML tags and the
# (Citation: ...) markers, collapse whitespace.
clean_text() {
  printf '%s' "$1" \
    | sed -E 's#<code>(.*)</code>#`\1`#g; s#<[^>]+>##g; s#\(Citation:[^)]*\)##g; s/[[:space:]]+/ /g; s/^ +//; s/ +$//'
}

# HTMLTXT: jq def mirroring the PS ConvertTo-HtmlText:
#   clean (<code>->backtick, strip tags, strip citations, collapse spaces)
#   -> HTML-escape -> backticks to <code> -> markdown [t](u) to <a> -> newlines to <br/>
# Backticks are written as \u0060 so the string stays free of literal backticks.
HTMLTXT='def html_text:
  (gsub("<code>(?<x>[^<]*)</code>"; "\u0060\(.x)\u0060")
   | gsub("<[^>]*>"; "")
   | gsub("\\(Citation:[^)]*\\)"; "")
   | gsub(" +"; " ")
   | gsub("&";"&amp;") | gsub("<";"&lt;") | gsub(">";"&gt;") | gsub("\"";"&quot;")
   | gsub("\u0060(?<c>[^\u0060\r\n]+)\u0060"; "<code>\(.c)</code>")
   | gsub("\\[(?<t>[^\\]]+)\\]\\((?<u>[^)\\s]+)\\)"; "<a href=\"\(.u)\">\(.t)</a>")
   | gsub("\\r?\\n"; "<br/>")
   | gsub(" +"; " "));'

# Convert text to safe HTML (group summary + hero subtitle)
html_text() {
  jq -nr --arg s "$1" "$HTMLTXT"' $s | html_text'
}

# "defense-impairment" -> "Defense Impairment"
title_case() {
  printf '%s' "$1" | sed -E 's/-/ /g' \
    | awk '{ for (i=1;i<=NF;i++) { if (length($i)) $i = toupper(substr($i,1,1)) substr($i,2) } print }'
}

# File-safe name for output files
file_safe() {
  printf '%s' "$1" | sed -E 's/[^A-Za-z0-9_-]/-/g; s/-+/-/g; s/^-//; s/-$//'
}

# One-line topic descriptor (first sentence, capped at 110)
short_desc() {
  local s="$1" sep
  # first sentence, fall back to second if tiny
  s="$(printf '%s' "$s" | awk -v RS='[.!?][[:space:]]+' 'NR==1{print; if (length($0)>=30) exit}')"
  s="$(printf '%s' "$s" | tr -s ' ')"
  if [[ ${#s} -gt 110 ]]; then s="${s:0:110}"; fi
  printf '%s' "$s"
}

# Build the canonical attack.mitre.org URL (fallback for techniques)
fallback_url() {
  local code="$1"
  if [[ "$code" =~ ^(T[0-9]+)(\.[0-9]+)?$ ]]; then
    if [[ -n "${BASH_REMATCH[2]:-}" ]]; then
      printf '%s%s%s/' "$TECH_BASE_URL" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    else
      printf '%s%s/' "$TECH_BASE_URL" "${BASH_REMATCH[1]}"
    fi
  else
    printf ''
  fi
}

# Full name for a sub-technique: "Parent: Sub" (sub.name is only "Sub")
full_technique_name() {
  local p="$1" code sub parent_code parent
  code="$(jget '.code' "$p")"
  sub="$(jget '.name' "$p")"
  if [[ "$(jget '.is_sub' "$p")" == "true" && "$code" =~ ^(T[0-9]+)\.[0-9]+$ ]]; then
    parent_code="${BASH_REMATCH[1]}"
    parent="$(jq -r --arg c "$parent_code" '.[$c] // empty' "$INDEX_DIR/pattern_by_code.json")"
    if [[ -n "$parent" ]]; then
      printf '%s: %s' "$(jget '.name' "$parent")" "$sub"
      return
    fi
  fi
  printf '%s' "$sub"
}

# Resolve data source names from a pattern's data components
data_sources() {
  local p="$1"
  jq -c --slurpfile comps "$INDEX_DIR/components_by_id.json" \
    '[.components[]? as $cid | $comps[0][$cid].name // empty] | join(", ")' <<<"$p"
}

# -----------------------------------------------------------------------------
# Data layer: download + slim cache + precomputed indexes (jq)
# -----------------------------------------------------------------------------
KEEP_TYPES='"intrusion-set","attack-pattern","malware","tool","campaign","relationship","x-mitre-detection-strategy","x-mitre-analytic","x-mitre-data-component","x-mitre-data-source"'

build_indexes() {
  say "Building indexes..."
  mkdir -p "$INDEX_DIR"

  # groups (name-sorted)
  jq -c '[.objects[] | select(.type=="intrusion-set")
          | {id, code:([.external_references[]?|select(.source_name=="mitre-attack")|.external_id][0]//""),
             name, aliases:(.aliases // .x_mitre_aliases // []),
             description, version:(.x_mitre_version // "")}]
          | sort_by(.name)' "$SLIM_PATH" > "$INDEX_DIR/groups.json"

  # attack-patterns (techniques / sub-techniques)
  jq -c '[.objects[] | select(.type=="attack-pattern")
          | {id, code:([.external_references[]?|select(.source_name=="mitre-attack")|.external_id][0]//""),
             name, is_sub:(.x_mitre_is_subtechnique // false), description,
             platforms:(.x_mitre_platforms // []),
             components:(.x_mitre_data_components // []),
             tactics:[.kill_chain_phases[]?.phase_name],
             url:([.external_references[]?|select(.source_name=="mitre-attack")|.url][0]//"")}]' \
    "$SLIM_PATH" > "$INDEX_DIR/patterns.json"

  # software (malware + tool)
  jq -c '[.objects[] | select(.type=="malware" or .type=="tool")
          | {id, code:([.external_references[]?|select(.source_name=="mitre-attack")|.external_id][0]//""),
             name, type, description}]' \
    "$SLIM_PATH" > "$INDEX_DIR/software.json"

  # campaigns
  jq -c '[.objects[] | select(.type=="campaign")
          | {id, code:([.external_references[]?|select(.source_name=="mitre-attack")|.external_id][0]//""),
             name, description}]' \
    "$SLIM_PATH" > "$INDEX_DIR/campaigns.json"

  # data components (id -> name) and analytics (id -> an_code/description)
  jq -c '[.objects[] | select(.type=="x-mitre-data-component") | {id, name}]' \
    "$SLIM_PATH" > "$INDEX_DIR/components.json"
  jq -c '[.objects[] | select(.type=="x-mitre-analytic")
          | {id, an_code:([.external_references[]?|select(.source_name=="mitre-attack")|.external_id][0]//""),
             description}]' \
    "$SLIM_PATH" > "$INDEX_DIR/analytics.json"

  # detection strategies with their analytics (DET codes + AN descriptions)
  jq -c --slurpfile an "$INDEX_DIR/analytics.json" '
    [.objects[] | select(.type=="x-mitre-detection-strategy")
     | {id,
        det_code:([.external_references[]?|select(.source_name=="mitre-attack")|.external_id][0]//""),
        det_name:.name,
        analytics:[.x_mitre_analytic_refs[]? as $rid
                   | ($an[0][] | select(.id==$rid) | {an_code, description})]}]' \
    "$SLIM_PATH" > "$INDEX_DIR/det_strats.json"

  # relationships (compact join table)
  jq -c '[.objects[] | select(.type=="relationship")
          | {s:.source_ref, t:.target_ref, ty:.relationship_type, desc:(.description // "")}]' \
    "$SLIM_PATH" > "$INDEX_DIR/rels.json"

  # indexes keyed by source / target
  jq -c 'group_by(.s) | map({s: .[0].s, rels: [.[] | {t, ty, desc}]})' \
    "$INDEX_DIR/rels.json" > "$INDEX_DIR/rels_by_source.json"
  jq -c 'group_by(.t) | map({t: .[0].t, rels: [.[] | {s, ty, desc}]})' \
    "$INDEX_DIR/rels.json" > "$INDEX_DIR/rels_by_target.json"

  # detection strategies per technique (target_id -> [{det_code,det_name,analytics}])
  jq -c --slurpfile ds "$INDEX_DIR/det_strats.json" '
    reduce (.objects[] | select(.type=="relationship" and .relationship_type=="detects")) as $r ({};
      .[$r.target_ref] += [ ($ds[0][] | select(.id == $r.source_ref) | {det_code, det_name, analytics}) ]
    )' "$SLIM_PATH" > "$INDEX_DIR/detects_by_target.json"

  # procedure examples per technique (target_id -> [{name,code,description,usage_desc}])
  jq -c --slurpfile sw "$INDEX_DIR/software.json" '
    reduce (.objects[] | select(.type=="relationship" and .relationship_type=="uses")) as $r ({};
      .[$r.target_ref] += [ ($sw[0][] | select(.id == $r.source_ref)
                             | {name, code, description} + {usage_desc: ($r.description // "")}) ]
    )' "$SLIM_PATH" > "$INDEX_DIR/uses_by_target.json"

  # by-id maps for fast resolution
  jq -c 'map({key:.id, value:.}) | from_entries' "$INDEX_DIR/patterns.json"  > "$INDEX_DIR/pattern_by_id.json"
  jq -c 'map({key:.id, value:.}) | from_entries' "$INDEX_DIR/software.json"  > "$INDEX_DIR/software_by_id.json"
  jq -c 'map({key:.id, value:.}) | from_entries' "$INDEX_DIR/campaigns.json" > "$INDEX_DIR/campaign_by_id.json"
  jq -c 'map({key:.id, value:.}) | from_entries' "$INDEX_DIR/components.json" > "$INDEX_DIR/components_by_id.json"
  jq -c 'map({key:.code, value:.}) | from_entries' "$INDEX_DIR/patterns.json" > "$INDEX_DIR/pattern_by_code.json"
}

get_attack_data() {
  mkdir -p "$CACHE_DIR"
  local need_full=0 need_parse=0

  if [[ "$REFRESH" == 1 || ! -f "$BUNDLE_PATH" ]]; then
    say "Downloading MITRE ATT&CK STIX bundle (~48 MB, one time)..."
    curl -fSL --retry 2 -o "$BUNDLE_PATH" "$STIX_URL"
    need_full=1
  fi

  if [[ "$need_full" == 1 || ! -f "$SLIM_PATH" ]]; then
    need_parse=1
    say "Building slim dataset..."
    jq -c '{type:"bundle", objects:[.objects[] | select(.type==('"$KEEP_TYPES"'))]}' \
      "$BUNDLE_PATH" > "$SLIM_PATH"
  fi

  if [[ "$need_parse" == 1 || ! -d "$INDEX_DIR" ]]; then
    build_indexes
  else
    say "Using cached ATT&CK data + indexes."
  fi
}

# -----------------------------------------------------------------------------
# Group profile: techniques / software / campaigns for one group
# -----------------------------------------------------------------------------
build_profile() {
  local gid="$1"
  jq -nc \
    --arg g "$gid" \
    --slurpfile pat "$INDEX_DIR/pattern_by_id.json" \
    --slurpfile sw  "$INDEX_DIR/software_by_id.json" \
    --slurpfile cam "$INDEX_DIR/campaign_by_id.json" \
    --slurpfile rs  "$INDEX_DIR/rels_by_source.json" \
    --slurpfile rt  "$INDEX_DIR/rels_by_target.json" '
    def resolve($other; $desc):
      if   $pat[0][$other] then {type:"technique", id:$other, code:$pat[0][$other].code, name:$pat[0][$other].name, usage:($desc // "")}
      elif $sw[0][$other]  then {type:"software",  id:$other, code:$sw[0][$other].code,  name:$sw[0][$other].name,  kind:$sw[0][$other].type, desc:($desc // "")}
      elif $cam[0][$other] then {type:"campaign",  id:$other, code:$cam[0][$other].code,  name:$cam[0][$other].name,  desc:$cam[0][$other].description}
      else null end;
    [ (($rs[0] | map(select(.s==$g))[0].rels // []) | map({other:.t, desc:.desc})),
      (($rt[0] | map(select(.t==$g))[0].rels // []) | map({other:.s, desc:.desc})) ]
    | add
    | map(. as $r | resolve($r.other; $r.desc))
    | map(select(. != null))
    | { techniques: (map(select(.type=="technique")) | unique_by(.code)),
        software:   (map(select(.type=="software"))  | unique_by(.code)),
        campaigns:  (map(select(.type=="campaign"))  | unique_by(.code)) }
  '
}

# -----------------------------------------------------------------------------
# KQL / General Query generation (heuristic, ECS fields)
# -----------------------------------------------------------------------------
PAT_TERMS=('-enc' '-e ' '-exec bypass' '-windowstyle hidden' '-w hidden' '-nop' '-noprofile'
           'IEX' 'DownloadString' 'FromBase64String' 'EncodedCommand' 'Invoke-Expression'
           'Reflection.Assembly' 'Add-Type')
TLDS='com net org io co ru cn biz info gov mil edu xyz top online site store tech me tv cc us uk de fr jp kr au ca nl se no fi dk pl cz it es pt ch at be gr tr in br mx ar za nz hk sg tw th my id ph vn ae sa il eg ma ng ke gh ua by kz uz ir pk bd lk np ro hu bg hr si sk lt lv ee is ie lu'
BENIGN='.mitre.org .github.com .wikipedia.org .google.com .microsoft.com .example.com .youtube.com .twitter.com .x.com .facebook.com .linkedin.com .medium.com .bit.ly .ow.ly .tinyurl.com .goo.gl .reddit.com .arstechnica.com .securelist.com .blogspot.com .virustotal.com .scholar.google.com'

# Returns a newline-separated list of process names (max 4)
signals_procs() {
  printf '%s' "$1" \
    | grep -oP '(?<![A-Za-z0-9_\\\.])\b[A-Za-z0-9_][A-Za-z0-9_.\-]*\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr|msi|cpl|hta)\b' \
    | tr 'A-Z' 'a-z' | sort -u | head -n 4 || true
}
signals_ports() {
  printf '%s' "$1" \
    | grep -oiP '\bport\s+(?:number\s+)?\d{1,5}\b|\b\d{1,5}\s*/\s*(?:tcp|udp)\b' \
    | grep -oP '\d{1,5}' | sort -n -u | head -n 3 || true
}
signals_eventids() {
  printf '%s' "$1" | grep -oiP '\bevent\s+id\s+\d+\b' | grep -oP '\d+' | sort -n -u | head -n 3 || true
}
signals_registry() {
  printf '%s' "$1" \
    | grep -oP '(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[A-Za-z0-9_\\\.\-]{2,}' \
    | sort -u | head -n 2 || true
}
signals_domains() {
  local text="$1"
  printf '%s' "$text" \
    | grep -oP '(?i)(?<![\w.@/])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?![\w.])' \
    | tr 'A-Z' 'a-z' | sed 's/^www\.//' | sort -u | while IFS= read -r d; do
        local tld="${d##*.}" first="${d%%.*}"
        [[ ${#first} -lt 3 ]] && continue
        [[ "$d" == "asp.net" || "$d" == "vb.net" || "$d" == "msdn.net" ]] && continue
        case " $TLDS " in *" $tld "*) ;; *) continue ;; esac
        for b in $BENIGN; do [[ "$d" == *"$b" ]] && continue 2; done
        printf '%s\n' "$d"
        [[ $(wc -l <<<"$(printf '%s\n' "${d}")" 2>/dev/null) -gt 2 ]] && break 2>/dev/null
      done | head -n 3 || true
}
signals_patterns() {
  local text="$1" p
  for p in "${PAT_TERMS[@]}"; do
    if printf '%s' "$text" | grep -qF -- "$p"; then printf '%s\n' "$p"; fi
  done | head -n 4
}

# build_kql <text> -> KQL string (may be empty)
build_kql() {
  local text="$1" procs patterns ports domains reg events
  procs="$(signals_procs "$text")"
  patterns="$(signals_patterns "$text")"
  ports="$(signals_ports "$text")"
  domains="$(signals_domains "$text")"
  reg="$(signals_registry "$text")"
  events="$(signals_eventids "$text")"

  local -a clauses=()
  if [[ -n "$procs" ]]; then
    local v=''
    while IFS= read -r p; do v="$v\"$p\" or "; done <<<"$procs"
    v="${v% or }"
    clauses+=("process.name : ($v)")
  fi
  if [[ -n "$patterns" ]]; then
    local v=''
    while IFS= read -r p; do v="$v\"*$p*\" or "; done <<<"$patterns"
    v="${v% or }"
    clauses+=("process.command_line : ($v)")
  fi
  if [[ -n "$ports" ]]; then
    local v=''
    while IFS= read -r p; do v="$v$p or "; done <<<"$ports"
    v="${v% or }"
    clauses+=("destination.port : ($v)")
  fi
  if [[ -n "$domains" ]]; then
    local v=''
    while IFS= read -r p; do v="$v\"$p\" or "; done <<<"$domains"
    v="${v% or }"
    clauses+=("dns.question.name : ($v)")
  fi
  if [[ -n "$reg" ]]; then
    local r
    r="$(printf '%s' "$reg" | head -n1 | sed 's/\\/\\\\/g')"
    clauses+=("registry.path : \"$r\"")
  fi
  if [[ -n "$events" ]]; then
    local v=''
    while IFS= read -r p; do v="$v$p or "; done <<<"$events"
    v="${v% or }"
    clauses+=("winlog.event_id : ($v)")
  fi

  local q
  q="$(printf '%s' "${clauses[*]}" | sed 's/ / or /g')"   # no: build properly below
  # Join clauses with " or ":
  q=""
  local i
  for i in "${!clauses[@]}"; do
    if [[ -n "$q" ]]; then q+=" or "; fi
    q+="${clauses[$i]}"
  done
  printf '%s' "$q"
}

# Primary ECS field fallback based on tactic
primary_field() {
  local tactic="$1"
  case "$tactic" in
    *"Command and Control"*|*"Exfiltration"*) echo "network.transport" ;;
    *"Persistence"*|*"Defense Impairment"*)  echo "registry.path" ;;
    *"Stealth"*)                             echo "file.name" ;;
    *)                                       echo "process.name" ;;
  esac
}

# -----------------------------------------------------------------------------
# Per-technique detail (JSON object)
# -----------------------------------------------------------------------------
tech_detail() {
  local p="$1" usage="$2" code full tac short kql url det_text dets n_det
  code="$(jget '.code' "$p")"
  full="$(full_technique_name "$p")"
  tac="$(title_case "$(jget '.tactics[0] // ""' "$p")")"
  short="$(short_desc "$(clean_text "$(jget '.description' "$p")")")"
  url="$(jget '.url // ""' "$p")"; [[ -z "$url" ]] && url="$(fallback_url "$code")"

  dets="$(jq -c --arg c "$(jget '.id' "$p")" '.[$c] // []' "$INDEX_DIR/detects_by_target.json")"
  n_det="$(jget 'length' "$dets")"
  det_text="$(jq -r '[.[] | .analytics[]?.description // empty] | join("\n")' <<<"$dets")"

  local sigtext
  sigtext="$(printf '%s\n%s\n%s' "$det_text" "$(clean_text "$(jget '.description' "$p")")" "$(clean_text "$usage")")"

  kql="$(build_kql "$sigtext")"
  if [[ -z "$kql" ]]; then
    if [[ "$n_det" -gt 0 ]]; then
      kql="$(primary_field "$tac") : *"
    else
      kql="—"
    fi
  fi

  jq -cn --arg id "$code" --arg name "$full" --arg tac "$tac" --arg short "$short" \
     --arg kql "$kql" --arg url "$url" \
     --arg plat "$(jget '.platforms | join(", ")' "$p")" \
     --arg ds "$(data_sources "$p")" \
     '{id:$id, name:$name, tactic:$tac, short:$short, kql:$kql, url:$url, platforms:$plat, data_sources:$ds}'
}

# -----------------------------------------------------------------------------
# IOC extraction (heuristic, mirrors the PowerShell Get-Indicators)
# -----------------------------------------------------------------------------
CMD_VERBS='reg|rundll32|powershell|pwsh|cmd|net|netsh|certutil|vssadmin|cipher|wevtutil|sc|schtasks|wmic|whoami|ipconfig|nltest|tasklist|taskkill|mshta|wscript|cscript|bitsadmin|curl|wget|regsvr32|forfiles|psexec|procdump|mimikatz|winexe'
STOPWORDS='to and with for that via using use of the an a in on from which can may also have has had be is are was were not its their it as by such like'

extract_commands() {
  local text="$1" v
  printf '%s' "$text" \
    | grep -oiP "\b(?:$CMD_VERBS)(?:\.exe)?\b(?:(?:\s+\S+){1,5})?" \
    | sed -E 's/[[:space:]]+/ /g; s/^ +//; s/ +$//; s/[.,;:>"]+$//' \
    | sed -E 's/[[:space:]]+(to|and|with|for|that|via|using|use|of|the|an|a|in|on|from|which|can|may|also|have|has|had|be|is|are|was|were|not|its|their|it|as|by|such|like)\b.*$//' \
    | while IFS= read -r v; do
        [[ ${#v} -lt 3 || ${#v} -gt 120 ]] && continue
        if [[ "$v" =~ (^|\s)-{1,2}\S || "$v" =~ (^|\s)/\S || "$v" == *\\* || "$v" == *=* || "$v" == *\<* || "$v" == *\>* || "$v" =~ %[A-Za-z0-9]+% || "$v" =~ \.[a-z]{2,4}\b || ! "$v" =~ \  ]]; then
          printf '%s\n' "$v"
        fi
      done | sort -u || true
}

extract_indicators() {
  local text="$1" clean
  clean="$(clean_text "$text")"
  local procs cmds regs files domains ports
  procs="$(printf '%s' "$clean" | grep -oP '(?<![A-Za-z0-9_\\\.])\b[A-Za-z0-9_][A-Za-z0-9_.\-]*\.(?:exe|dll|ps1|bat|cmd|vbs|js|scr|msi|cpl|hta)\b' | tr 'A-Z' 'a-z' | sort -u || true)"
  cmds="$(extract_commands "$clean")"
  regs="$(printf '%s' "$clean" | grep -oP '(?i)\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[A-Za-z0-9_\\\.\-]{2,}' | sort -u || true)"
  files="$( { printf '%s' "$clean" | grep -oP '(?i)\b[A-Za-z]:\\[^\s"<>|`;]{1,120}\b'; printf '%s' "$clean" | grep -oP '(?i)%\w+%\\[^\s"<>|`;]{1,120}\b'; } | sort -u || true)"
  domains="$(signals_domains "$clean")"
  ports="$(signals_ports "$clean")"

  # assemble JSON
  jq -cn \
    --arg procs  "$(printf '%s' "$procs" | jq -R . | jq -s 'map(select(.!=""))' 2>/dev/null || echo '[]')" \
    --arg cmds   "$(printf '%s' "$cmds" | jq -R . | jq -s 'map(select(.!=""))' 2>/dev/null || echo '[]')" \
    --arg regs   "$(printf '%s' "$regs" | jq -R . | jq -s 'map(select(.!=""))' 2>/dev/null || echo '[]')" \
    --arg files  "$(printf '%s' "$files" | jq -R . | jq -s 'map(select(.!=""))' 2>/dev/null || echo '[]')" \
    --arg domains "$(printf '%s' "$domains" | jq -R . | jq -s 'map(select(.!=""))' 2>/dev/null || echo '[]')" \
    --arg ports  "$(printf '%s' "$ports" | jq -R . | jq -s 'map(select(.!=""))' 2>/dev/null || echo '[]')" \
    '{Processes:($procs|fromjson), Commands:($cmds|fromjson), Registry:($regs|fromjson),
      FilePaths:($files|fromjson), Domains:($domains|fromjson), Ports:($ports|fromjson)}'
}

# -----------------------------------------------------------------------------
# Reports
# -----------------------------------------------------------------------------
IOC_CATS=('Processes' 'Commands' 'Registry' 'FilePaths' 'Domains' 'Ports')
TACTIC_ORDER=('Reconnaissance' 'Resource Development' 'Initial Access' 'Execution' 'Persistence'
  'Privilege Escalation' 'Defense Impairment' 'Stealth' 'Credential Access' 'Discovery'
  'Lateral Movement' 'Collection' 'Command and Control' 'Exfiltration' 'Impact')

# Full markdown writer (uses profile object)
write_markdown() {
  local g="$1" profile="$2" details="$3" iocs="$4"
  local gcode gname version aliases gdesc n_sw n_cam
  gcode="$(code_of "$g")"; gname="$(jget '.name' "$g")"
  version="$(jget '.version // ""' "$g")"
  aliases="$(jget '.aliases | join(", ")' "$g")"
  gdesc="$(clean_text "$(jget '.description' "$g")")"
  n_sw="$(jget '.software | length' "$profile")"
  n_cam="$(jget '.campaigns | length' "$profile")"

  local f
  f="$MD_DIR/MITRE-$(file_safe "$gname").md"
  {
    printf '# %s (%s) — MITRE ATT&CK Cheat Sheet\n\n' "$gname" "$gcode"
    printf '> **Group:** %s | **ID:** %s | **Aliases:** %s | **Version:** %s\n' "$gname" "$gcode" "$aliases" "$version"
    printf '> **Source:** %s%s  •  Generated %s\n' "$GROUP_BASE_URL" "$gcode" "$(date '+%Y-%m-%d %H:%M')"
    printf "> 💡 General queries are auto-generated from MITRE detection strategies (heuristic, ECS fields). '—' = no in-network detection signal.\n\n"
    if [[ -n "$gdesc" ]]; then
      local gs="$gdesc"; [[ ${#gs} -gt 240 ]] && gs="${gs:0:240}…"
      printf '%s\n\n' "$gs"
    fi

    local tac order_list
    order_list="${TACTIC_ORDER[*]}"
    for tac in "${TACTIC_ORDER[@]}"; do
      local rows
      rows="$(jq -c --arg t "$tac" '[.[] | select(.tactic==$t)] | sort_by(.id)' <<<"$details")"
      [[ "$(jget 'length' "$rows")" == "0" ]] && continue
      printf '## %s (%s)\n\n' "$tac" "$(jget 'length' "$rows")"
      printf '| TTP | Topic | General Query |\n|---|---|---|\n'
      jq -r '.[] | "| [" + .id + "](" + .url + ") " + .name + " | " + (.short|gsub("\\|";"\\|")) + " | `" + (.kql|gsub("\\|";"\\|")) + "` |"' <<<"$rows"
      printf '\n'
    done
    local other
    other="$(jq -c --arg order " $order_list " '[.[] | select(.tactic as $t | ($order | contains(" \($t) ")) | not)] | sort_by(.id)' <<<"$details")"
    if [[ "$(jget 'length' "$other")" != "0" ]]; then
      printf '## Other (%s)\n\n' "$(jget 'length' "$other")"
      printf '| TTP | Topic | General Query |\n|---|---|---|\n'
      jq -r '.[] | "| [" + .id + "](" + .url + ") " + .name + " | " + (.short|gsub("\\|";"\\|")) + " | `" + (.kql|gsub("\\|";"\\|")) + "` |"' <<<"$other"
      printf '\n'
    fi

    printf '## Software Used (%s)\n\n' "$n_sw"
    printf '| ID | Name | Type | Notes |\n|---|---|---|---|\n'
    jq -r '.software | sort_by(.name) | .[] | "| [" + .code + "](https://attack.mitre.org/software/" + .code + ") | " + .name + " | " + .kind + " | " + ((.desc // "")) + " |"' <<<"$profile"
    printf '\n'

    if [[ "$n_cam" != "0" ]]; then
      printf '## Campaigns (%s)\n\n' "$n_cam"
      printf '| ID | Name | Description |\n|---|---|---|\n'
      jq -r '.campaigns | sort_by(.code) | .[] | "| [" + .code + "](https://attack.mitre.org/campaigns/" + .code + ") | " + .name + " | " + (.desc // "") + " |"' <<<"$profile"
      printf '\n'
    fi

    printf '## IOCs (auto-extracted — heuristic)\n\n'
    printf '> ⚠ These were pulled from MITRE detection/procedure text by regex. MITRE publishes\n'
    printf '> *behavioral* IOCs only (no hashes/IPs). Review and enrich before operational use.\n\n'
    local cat
    for cat in "${IOC_CATS[@]}"; do
      local n
      n="$(jget ".$cat | length" "$iocs")"
      printf '### %s (%s)\n\n' "$cat" "$n"
      if [[ "$n" != "0" ]]; then
        jq -r --arg c "$cat" '.[$c][] | "- `" + . + "`"' <<<"$iocs"
        printf '\n'
      else
        printf '_none extracted_\n\n'
      fi
    done
  } > "$f"
  say "  Markdown -> $f"
}

write_html() {
  local g="$1" profile="$2" details="$3" iocs="$4"
  local gcode gname version aliases gdesc short n_sw n_cam
  gcode="$(code_of "$g")"; gname="$(jget '.name' "$g")"
  version="$(jget '.version // ""' "$g")"
  aliases="$(jget '.aliases | join(", ")' "$g")"
  gdesc="$(jget '.description' "$g")"
  gdesc_clean="$(clean_text "$gdesc")"
  short="$gdesc_clean"; [[ ${#short} -gt 320 ]] && short="${short:0:320}…"
  n_sw="$(jget '.software | length' "$profile")"
  n_cam="$(jget '.campaigns | length' "$profile")"
  n_tech="$(jget 'length' "$details")"

  local f theme themes
  f="$HTML_DIR/MITRE-$(file_safe "$gname").html"
  themes=('blue' 'green' 'amber' 'rose' 'violet' 'cyan' 'red')

  {
    cat <<'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
EOF
    printf '    <title>MITRE ATT&amp;CK: %s (%s) — TTP &amp; IOC Cheat Sheet</title>\n' "$gname" "$gcode"
    printf '    <link rel="stylesheet" href="styles.css" />\n'
    printf '%s\n' '  </head>'
    printf '%s\n' '  <body class="mitre">'
    printf '%s\n' '    <div class="shell">'

    # hero
    cat <<EOF
      <header class="hero">
        <div class="hero-inner">
          <span class="eyebrow">Kevin C. Jones - 4n6post.com</span>
          <h1>MITRE ATT&amp;CK: $gname ($gcode)</h1>
          <p class="subtitle">$(html_text "$short")</p>
          <div class="badges">
            <span class="badge">Aliases: $aliases</span>
            <span class="badge">$n_tech techniques</span>
            <span class="badge">$n_sw software</span>
            <span class="badge">$n_cam campaigns</span>
            <span class="badge">ATT&amp;CK v$version</span>
            <span class="badge">$(date '+%Y-%m-%d %H:%M')</span>
          </div>
        </div>
      </header>
      <main class="grid">
EOF

    # group summary
    cat <<EOF
        <section class="topic span-full" data-theme="slate">
          <div class="topic-header"><h2>Group Summary</h2><span class="topic-tag">1</span></div>
          <p class="mini">$(html_text "$gdesc")</p>
          <p class="mini">💡 General queries are auto-generated from MITRE detection strategies (heuristic, ECS fields). '—' = no in-network detection signal.</p>
          <div class="table-wrap"><table><tbody>
            <tr><td>ID</td><td>$gcode</td></tr>
            <tr><td>Aliases</td><td>$aliases</td></tr>
            <tr><td>Version</td><td>$version</td></tr>
            <tr><td>Source</td><td><a href="$GROUP_BASE_URL$gcode">$GROUP_BASE_URL$gcode</a></td></tr>
          </tbody></table></div>
        </section>
EOF

    # tactic sections
    local topic_num=2 ti=0 tac
    for tac in "${TACTIC_ORDER[@]}"; do
      local rows
      rows="$(jq -c --arg t "$tac" '[.[] | select(.tactic==$t)] | sort_by(.id)' <<<"$details")"
      [[ "$(jget 'length' "$rows")" == "0" ]] && continue
      theme="${themes[$((ti % ${#themes[@]}))]}"
      printf '        <section class="topic span-full" data-theme="%s">\n' "$theme"
      printf '          <div class="topic-header"><h2>%s (%s)</h2><span class="topic-tag">%s</span></div>\n' "$tac" "$(jget 'length' "$rows")" "$topic_num"
      printf '          <div class="table-wrap"><table class="ttp-table"><thead><tr><th>TTP</th><th>Topic</th><th>General Query</th></tr></thead><tbody>\n'
      jq -r "$HTMLTXT"' .[] | "            <tr><td><a href=\"" + .url + "\">" + .id + "</a><br/><span class=\"mini\">" + (.name|html_text) + "</span></td><td>" + (.short|html_text) + "</td><td><code class=\"kql\">" + (.kql|@html) + "</code></td></tr>"' <<<"$rows"
      printf '          </tbody></table></div>\n        </section>\n'
      topic_num=$((topic_num+1)); ti=$((ti+1))
    done

    # software
    printf '        <section class="topic span-full" data-theme="green">\n'
    printf '          <div class="topic-header"><h2>Software Used (%s)</h2><span class="topic-tag">%s</span></div>\n' "$n_sw" "$topic_num"; topic_num=$((topic_num+1))
    printf '          <div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Notes</th></tr></thead><tbody>\n'
    jq -r "$HTMLTXT"' .software | sort_by(.name) | .[] | "            <tr><td><a href=\"https://attack.mitre.org/software/" + .code + "\">" + .code + "</a></td><td>" + (.name|html_text) + "</td><td>" + .kind + "</td><td>" + ((.desc // "")|html_text) + "</td></tr>"' <<<"$profile"
    printf '          </tbody></table></div>\n        </section>\n'

    # campaigns
    if [[ "$n_cam" != "0" ]]; then
      printf '        <section class="topic span-full" data-theme="amber">\n'
      printf '          <div class="topic-header"><h2>Campaigns (%s)</h2><span class="topic-tag">%s</span></div>\n' "$n_cam" "$topic_num"; topic_num=$((topic_num+1))
      printf '          <div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Description</th></tr></thead><tbody>\n'
      jq -r "$HTMLTXT"' .campaigns | sort_by(.code) | .[] | "            <tr><td><a href=\"https://attack.mitre.org/campaigns/" + .code + "\">" + .code + "</a></td><td>" + (.name|html_text) + "</td><td>" + ((.desc // "")|html_text) + "</td></tr>"' <<<"$profile"
      printf '          </tbody></table></div>\n        </section>\n'
    fi

    # iocs
    printf '        <section class="topic span-full" data-theme="violet">\n'
    printf '          <div class="topic-header"><h2>IOCs (auto-extracted)</h2><span class="topic-tag">%s</span></div>\n' "$topic_num"
    printf '          <p class="mini">⚠ Auto-extracted from MITRE detection/procedure text via regex. MITRE publishes behavioral IOCs only (no hashes/IPs) — review and enrich before operational use.</p>\n'
    printf '          <div class="table-wrap"><table><thead><tr><th>Category</th><th>Indicators</th></tr></thead><tbody>\n'
    local cat
    for cat in "${IOC_CATS[@]}"; do
      printf '            <tr><td>%s</td><td>' "$cat"
      if [[ "$(jget ".$cat | length" "$iocs")" == "0" ]]; then
        printf '<span class="mini">none extracted</span>'
      else
        jq -r --arg c "$cat" '.[$c] | map("<code>" + @html + "</code>") | join("<br/>")' <<<"$iocs"
      fi
      printf '</td></tr>\n'
    done
    printf '          </tbody></table></div>\n        </section>\n'

    printf '%s\n' '      </main>'
    printf '%s\n' '    </div>'
    printf '%s\n' '  </body>'
    printf '%s\n' '</html>'
  } > "$f"
  say "  HTML     -> $f"
}

# Write the combined stylesheet into html/ (self-contained on Linux)
ensure_stylesheet() {
  mkdir -p "$HTML_DIR"
  if [[ ! -f "$HTML_DIR/styles.css" ]]; then
    cat > "$HTML_DIR/styles.css" <<'CSS'
:root{--bg-1:#081120;--bg-2:#101b2d;--bg-3:#0f1d2d;--text:#edf6ff;--muted:#9bb3c8;--card:rgba(15,23,42,.82);--shadow:rgba(0,0,0,.35);--border:rgba(148,163,184,.18)}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:"Segoe UI",Tahoma,Geneva,Verdana,sans-serif;background:radial-gradient(circle at top left,rgba(18,116,255,.17),transparent 30%),radial-gradient(circle at top right,rgba(31,211,168,.14),transparent 35%),linear-gradient(160deg,var(--bg-1),var(--bg-2) 38%,var(--bg-3));color:var(--text);min-height:100vh}
.shell{max-width:1380px;margin:0 auto;padding:15px 10px 30px}
.hero{position:relative;overflow:hidden;padding:34px 40px;backdrop-filter:blur(12px)}
.hero::before{content:"";position:absolute;inset:0;pointer-events:none}
.hero-inner{position:relative;z-index:1}
.eyebrow{display:inline-block;padding:7px 12px;border-radius:999px;background:rgba(59,130,246,.14);border:1px solid rgba(96,165,250,.24);color:#cfe5ff;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
h1{margin:16px 0 10px;font-size:clamp(2.2rem,5vw,4.2rem);line-height:1.05;letter-spacing:-.05em}
.subtitle{margin:0;max-width:760px;color:var(--muted);font-size:1.08rem;line-height:1.6}
.badges{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
.badge{padding:8px 12px;border-radius:999px;background:rgba(15,118,110,.12);border:1px solid rgba(45,212,191,.2);color:#c8fff8;font-size:.8rem;font-weight:600}
.grid{margin-top:30px;display:grid;gap:20px}
.grid .topic.span-full{grid-column:1/-1}
.topic{padding:10px 13px 8px;position:relative;overflow:hidden}
.topic::before{content:"";position:absolute;inset:0 0 auto 0;height:4px;background:var(--accent)}
.topic-header{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
.topic h2{margin:0;font-size:1.12rem;letter-spacing:-.02em}
.topic-tag{display:inline-flex;align-items:center;justify-content:center;min-width:36px;height:36px;border-radius:12px;background:var(--accent-soft);color:var(--accent-text);font-weight:800;font-size:.92rem;border:1px solid rgba(255,255,255,.06)}
table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:14px;font-size:.93rem;background:rgba(8,15,27,.35)}
thead th{background:var(--thead);color:var(--head-text);text-align:left;padding:3px 10px;font-size:.76rem;letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid rgba(255,255,255,.04)}
tbody td{padding:1px 10px;border-bottom:1px solid rgba(148,163,184,.12);color:var(--text);vertical-align:top}
tbody tr:nth-child(even){background:rgba(255,255,255,.07)}
code{font-family:"Consolas","SFMono-Regular",monospace;background:rgba(15,23,42,.7);border:2px solid rgba(148,163,184,.14);border-radius:7px;font-size:.85em;color:#f2f5ff}
tbody td code{overflow-wrap:anywhere;word-break:break-word}
th:first-child,td:first-child{width:100px;min-width:100px;max-width:300px;white-space:nowrap}
section.topic.span-full tbody td:first-child{font-weight:500}
.topic[data-theme="blue"]{--accent-soft:rgba(96,165,250,.14);--accent-text:#dfeeff;--thead:linear-gradient(135deg,#1d4ed8,#2563eb);--head-text:#eaf3ff}
.topic[data-theme="green"]{--accent-soft:rgba(45,212,191,.15);--accent-text:#dffef8;--thead:linear-gradient(135deg,#047857,#0f766e);--head-text:#ecfffb}
.topic[data-theme="amber"]{--accent-soft:rgba(245,158,11,.14);--accent-text:#fff5d9;--thead:linear-gradient(135deg,#b45309,#c2410c);--head-text:#fff7e8}
.topic[data-theme="rose"]{--accent-soft:rgba(244,63,94,.14);--accent-text:#ffeaf0;--thead:linear-gradient(135deg,#be123c,#e11d48);--head-text:#fff1f3}
.topic[data-theme="violet"]{--accent-soft:rgba(139,92,246,.14);--accent-text:#f2ebff;--thead:linear-gradient(135deg,#6d28d9,#7c3aed);--head-text:#f4edff}
.topic[data-theme="cyan"]{--accent-soft:rgba(56,189,248,.14);--accent-text:#e8fbff;--thead:linear-gradient(135deg,#0f766e,#0284c7);--head-text:#effcff}
.topic[data-theme="red"]{--accent-soft:rgba(239,68,68,.14);--accent-text:#fff0f0;--thead:linear-gradient(135deg,#b91c1c,#dc2626);--head-text:#fff2f2}
.topic[data-theme="slate"]{--accent-soft:rgba(148,163,184,.12);--accent-text:#f4f7fb;--thead:linear-gradient(135deg,#475569,#334155);--head-text:#f8fafc}
.mini{font-size:.82rem;color:var(--muted);line-height:1.5;margin:8px 2px 2px}
.topic a{color:#60a5fa;text-decoration:none;border-bottom:1px dashed rgba(96,165,250,.5)}
.topic a:hover{color:#93c5fd;border-bottom-style:solid}
@media (max-width:720px){.shell{padding:22px 12px 40px}.hero{padding:22px 18px;border-radius:18px}.grid{grid-template-columns:1fr}thead th{font-size:.68rem}tbody td{font-size:.88rem}}
body.mitre .grid{grid-template-columns:1fr}
body.mitre .topic{padding:14px 16px 10px}
body.mitre .mini{margin:2px 0 6px}
body.mitre .table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:14px}
body.mitre .ttp-table{width:100%;min-width:560px;table-layout:auto}
body.mitre .ttp-table th:first-child,body.mitre .ttp-table td:first-child{width:auto;min-width:120px;max-width:none;white-space:normal}
body.mitre .ttp-table td:first-child>a{font-weight:700}
body.mitre .ttp-table td:first-child .mini{display:block;font-weight:400;margin-top:1px}
body.mitre table th,body.mitre table td{vertical-align:top}
body.mitre .kql{white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;font-size:.8rem}
body.mitre table tbody tr:hover{background:rgba(255,255,255,.1)}
CSS
  fi
}

# -----------------------------------------------------------------------------
# Interactive menu + selection
# -----------------------------------------------------------------------------
resolve_selection() {
  # input: comma/range text; output: indices (1-based) on stdout
  local input="$1" count="$2" token lo hi i
  local -A picked=()
  IFS=',' read -ra tokens <<<"$input"
  for token in "${tokens[@]}"; do
    token="${token// /}"
    [[ -z "$token" ]] && continue
    if [[ "$token" == "all" || "$token" == "0" ]]; then
      for ((i=1; i<=count; i++)); do picked[$i]=1; done
    elif [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[2]}"
      (( lo > hi )) && { tmp=$lo; lo=$hi; hi=$tmp; }
      for ((i=lo; i<=hi && i<=count; i++)); do (( i >= 1 )) && picked[$i]=1; done
    elif [[ "$token" =~ ^[0-9]+$ ]]; then
      (( token >= 1 && token <= count )) && picked[$token]=1
    else
      warn "Ignoring invalid selection token: $token"
    fi
  done
  printf '%s\n' "${!picked[@]}" | sort -n
}

show_menu() {
  local -a groups=("$@") i idx
  # All display goes to stderr; only the selected group JSON objects go to stdout.
  say "" >&2
  say "MITRE ATT&CK Threat Groups  (${#groups[@]} total)" >&2
  printf '%s\n' "----------------------------------------------------------------------" >&2
  for i in "${!groups[@]}"; do
    local g="${groups[$i]}"
    local code name alias_text
    code="$(code_of "$g")"
    name="$(jget '.name' "$g")"
    alias_text="$(jget '.aliases[0:3] | join(", ")' "$g")"
    printf '%3d. %-6s %s  [%s]\n' $((i+1)) "$code" "$name" "${alias_text:0:40}" >&2
  done
  while :; do
    printf 'Select group(s) [e.g. 1,3,7  or  1-5;  "all" or 0 = every group;  Enter to quit]: ' >&2
    local ans
    IFS= read -r ans || return 1
    [[ -z "$ans" ]] && return 1
    [[ "$ans" =~ ^[Qq]([Uu][Ii][Tt])?$ ]] && return 1
    local -a idx
    mapfile -t idx < <(resolve_selection "$ans" "${#groups[@]}")
    if [[ ${#idx[@]} -eq 0 ]]; then
      say 'No valid selection. Try again.' >&2
      continue
    fi
    for i in "${idx[@]}"; do printf '%s\n' "${groups[$((i-1))]}"; done
    return 0
  done
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
get_attack_data

mapfile -t ALL_GROUPS < <(jq -c '.[]' "$INDEX_DIR/groups.json")
if [[ ${#ALL_GROUPS[@]} -eq 0 ]]; then
  say 'No groups found in the ATT&CK data.'
  exit 1
fi

declare -a SELECTED=()
if [[ "$ALL" == 1 ]]; then
  SELECTED=("${ALL_GROUPS[@]}")
  say "Parsing ALL ${#SELECTED[@]} groups..."
  say 'This writes a Markdown + HTML report per group and may take a few minutes.'
elif [[ ${#GROUP_ARGS[@]} -gt 0 ]]; then
  part=
g=
m=
  for g in "${GROUP_ARGS[@]}"; do
    IFS=',' read -ra parts <<<"$g"
    for part in "${parts[@]}"; do
      part="${part// /}"
      [[ -z "$part" ]] && continue
      m="$(jq -c --arg n "$part" --arg c "$part" '.[] | select(.name==$n or .code==$c)' "$INDEX_DIR/groups.json")"
      if [[ -n "$m" ]]; then SELECTED+=("$m"); else warn "Group '$part' not found."; fi
    done
  done
  if [[ ${#SELECTED[@]} -eq 0 ]]; then say 'No matching groups selected.'; exit 1; fi
else
  mapfile -t SELECTED < <(show_menu "${ALL_GROUPS[@]}")
  if [[ ${#SELECTED[@]} -eq 0 ]]; then say 'No selection made. Exiting.'; exit 0; fi
fi

mkdir -p "$MD_DIR" "$HTML_DIR"
ensure_stylesheet

for g in "${SELECTED[@]}"; do
  gid="$(jget '.id' "$g")"
  gname="$(jget '.name' "$g")"
  gcode="$(code_of "$g")"
  say "Building profile: $gname ($gcode)..."

  profile="$(build_profile "$gid")"

  # per-technique details
  DETAILS=()
  tech=
  usage=
  while IFS= read -r tech; do
    usage="$(jget '.usage // ""' <<<"$tech")"
    DETAILS+=("$(tech_detail "$(jq -c --arg id "$(jget '.id' <<<"$tech")" '.[$id] // empty' "$INDEX_DIR/pattern_by_id.json")" "$usage")")
  done < <(jq -c '.techniques[]' <<<"$profile")
  # join details into a JSON array
  details_json="$(printf '%s\n' "${DETAILS[@]}" | jq -s '.')"

  # IOC text: group description + detection strategy descriptions + procedure example descriptions + software descriptions
  ioc_text="$( { jget '.description' "$g";
                  jq -r '.techniques[] | select(.usage != "") | .usage' <<<"$profile";
                  while IFS= read -r tech; do
                    pat="$(jq -c --arg id "$(jget '.id' <<<"$tech")" '.[$id] // empty' "$INDEX_DIR/pattern_by_id.json")"
                    jq -c --arg c "$(jget '.id' <<<"$pat")" '.[$c] // []' "$INDEX_DIR/detects_by_target.json" \
                      | jq -r '.[] | .analytics[]?.description // empty'
                    jq -c --arg c "$(jget '.id' <<<"$pat")" '.[$c] // []' "$INDEX_DIR/uses_by_target.json" \
                      | jq -r '.[] | .usage_desc // empty'
                  done < <(jq -c '.techniques[]' <<<"$profile");
                  jq -r '.software[] | .desc // ""' <<<"$profile";
                } | sed '/^$/d' )"

  iocs="$(extract_indicators "$ioc_text")"

  if [[ "$NO_MD" == 0 ]]; then write_markdown "$g" "$profile" "$details_json" "$iocs"; fi
  if [[ "$NO_HTML" == 0 ]]; then write_html "$g" "$profile" "$details_json" "$iocs"; fi

  say "  Done: $(jget '.techniques | length' "$profile") techniques, $(jget '.software | length' "$profile") software, $(jget '.campaigns | length' "$profile") campaigns."
done

say 'All reports generated.'
