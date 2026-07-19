# tests/diagnostics/defense_groups.py
#
# Splits DEFENSE_CONFIGS into the groups the paper/poster need:
#   "individual" -- the baseline single/combined-mechanism defenses (paper)
#   "risk"       -- the risk-scoring proposal (paper, kept separate for a
#                   cleaner narrative: "here's what exists" vs "here's what
#                   we propose")
#   "all"        -- every config together (poster: space is limited, so
#                   everything goes in one figure)
#
# When step 4 (a new extractor-driven config) or step 5 (two_agent) register
# a new entry in DEFENSE_CONFIGS, add its name to the appropriate list below
# -- "all" is derived automatically, and both make_stacked_chart.py and
# make_stacked_table.py pick it up with no other changes.

GROUPS = {
    "individual": ["none", "regex", "trust_fileaccess", "pydantic", "full"],
    "risk": ["risk", "risk_llm"],
    # "two_agent" (step 5) belongs here once registered -- it's an
    # architectural proposal like risk_llm, not a single-mechanism baseline.
}
GROUPS["all"] = GROUPS["individual"] + GROUPS["risk"]

DISPLAY_NAME = {
    "none": "No defense", "regex": "Regex", "trust_fileaccess": "Trust +\nfile-access",
    "pydantic": "Pydantic\nschema", "full": "Full\n(combined)", "risk": "Risk\nscore",
    "risk_llm": "Risk +\nLLM judge",
}
