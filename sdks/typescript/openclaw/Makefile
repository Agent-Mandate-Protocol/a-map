SKILLS_DIR := skills
SKILL_VERSION ?= 1.0.0

.PHONY: build test typecheck lint clean \
        skill-inspect skill-publish skill-search

# ── Dev ──────────────────────────────────────────────────────────────────────

build:
	pnpm build

test:
	pnpm test

typecheck:
	pnpm typecheck

lint:
	pnpm lint

clean:
	pnpm clean

# ── ClawHub skill ─────────────────────────────────────────────────────────────

## Inspect the skill (shows what the server will parse — run before publish)
skill-inspect:
	clawhub inspect $(SKILLS_DIR)/agent-mandate-protocol

## Publish the skill to ClawHub
skill-publish:
	clawhub publish $(SKILLS_DIR)/agent-mandate-protocol --slug agent-mandate-protocol --name "Agent Mandate Protocol" --version $(SKILL_VERSION)

## Search ClawHub to confirm the skill is indexed after publishing
skill-search:
	clawhub search 'verify agent identity'
	clawhub search 'sign agent request'
	clawhub search 'delegate permissions to sub-agent'
	clawhub search 'agent authorization A-MAP'
