#!/usr/bin/env bash
# Stop-hook: nudge to update memory when session is learning-heavy

CONTEXT=$(cat)

STRONG_PATTERNS="fixed|workaround|gotcha|that's wrong|check again|we already|should have|discovered|realized|turns out"
WEAK_PATTERNS="error|bug|issue|fail"

if echo "$CONTEXT" | grep -qiE "$STRONG_PATTERNS"; then
  cat << 'EOF'
{
  "decision": "approve",
  "systemMessage": "This session involved fixes or discoveries. Consider updating .agents/rules/memory-decisions.md and memory-sessions.md with what you learned. Use ISO dates (YYYY-MM-DD)."
}
EOF
elif echo "$CONTEXT" | grep -qiE "$WEAK_PATTERNS"; then
  echo '{"decision":"approve","systemMessage":"If you learned something non-obvious, add a short note to memory-decisions.md or memory-sessions.md."}'
else
  echo '{"decision": "approve"}'
fi
